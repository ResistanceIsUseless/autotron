package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type config struct {
	provider      string
	ip            string
	jsonOutput    bool
	timeout       time.Duration
	maxServices   int
	shodanKey     string
	shodanBaseURL string
	fofaEmail     string
	fofaKey       string
	fofaBaseURL   string
}

type outputRecord struct {
	Provider string   `json:"provider"`
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Service  string   `json:"service"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Banner   string   `json:"banner"`
	CVE      []string `json:"cve,omitempty"`
	Risk     string   `json:"risk"`
}

type shodanHostResponse struct {
	IPStr string                     `json:"ip_str"`
	Data  []shodanBanner             `json:"data"`
	Vulns map[string]json.RawMessage `json:"vulns"`
}

type shodanBanner struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Data      string `json:"data"`
	Shodan    struct {
		Module string `json:"module"`
	} `json:"_shodan"`
}

type fofaSearchResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Results [][]any  `json:"results"`
	Mode    string   `json:"mode"`
	Query   string   `json:"query"`
	Page    int      `json:"page"`
	Size    int      `json:"size"`
	Total   int64    `json:"total"`
	Fields  []string `json:"fields"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "exposure-intel error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.provider, "provider", "shodan", "provider to query (shodan|fofa)")
	flag.StringVar(&cfg.ip, "ip", "", "target IP address")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL records")
	flag.DurationVar(&cfg.timeout, "timeout", 20*time.Second, "HTTP timeout per request")
	flag.IntVar(&cfg.maxServices, "max-services", 100, "maximum number of service records to emit")
	flag.StringVar(&cfg.shodanKey, "shodan-key", "", "Shodan API key (or SHODAN_API_KEY)")
	flag.StringVar(&cfg.shodanBaseURL, "shodan-base-url", "https://api.shodan.io", "Shodan API base URL")
	flag.StringVar(&cfg.fofaEmail, "fofa-email", "", "FOFA account email (or FOFA_EMAIL)")
	flag.StringVar(&cfg.fofaKey, "fofa-key", "", "FOFA API key (or FOFA_KEY)")
	flag.StringVar(&cfg.fofaBaseURL, "fofa-base-url", "https://fofa.info", "FOFA API base URL")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	if strings.TrimSpace(cfg.ip) == "" {
		return errors.New("--ip is required")
	}
	if net.ParseIP(strings.TrimSpace(cfg.ip)) == nil {
		return fmt.Errorf("invalid --ip value %q", cfg.ip)
	}
	if cfg.maxServices <= 0 {
		return errors.New("--max-services must be > 0")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.provider))
	if provider != "shodan" && provider != "fofa" {
		return fmt.Errorf("unsupported --provider %q (supported: shodan|fofa)", cfg.provider)
	}

	shodanKey := strings.TrimSpace(cfg.shodanKey)
	if shodanKey == "" {
		shodanKey = strings.TrimSpace(os.Getenv("SHODAN_API_KEY"))
	}
	fofaEmail := strings.TrimSpace(cfg.fofaEmail)
	if fofaEmail == "" {
		fofaEmail = strings.TrimSpace(os.Getenv("FOFA_EMAIL"))
	}
	fofaKey := strings.TrimSpace(cfg.fofaKey)
	if fofaKey == "" {
		fofaKey = strings.TrimSpace(os.Getenv("FOFA_KEY"))
	}

	if provider == "shodan" && shodanKey == "" {
		return errors.New("missing Shodan API key (set SHODAN_API_KEY)")
	}
	if provider == "fofa" && (fofaEmail == "" || fofaKey == "") {
		return errors.New("missing FOFA credentials (set FOFA_EMAIL and FOFA_KEY)")
	}

	client := &http.Client{Timeout: cfg.timeout}
	ctx := context.Background()

	var (
		records []outputRecord
		err     error
	)
	switch provider {
	case "shodan":
		records, err = shodanLookup(ctx, client, cfg.shodanBaseURL, shodanKey, cfg.ip, cfg.maxServices)
	case "fofa":
		records, err = fofaLookup(ctx, client, cfg.fofaBaseURL, fofaEmail, fofaKey, cfg.ip, cfg.maxServices)
	}
	if err != nil {
		return err
	}

	for _, rec := range records {
		if cfg.jsonOutput {
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s:%d\n", rec.IP, rec.Port)
		}
	}

	return nil
}

func shodanLookup(ctx context.Context, client *http.Client, baseURL, key, ip string, maxServices int) ([]outputRecord, error) {
	baseURL = strings.TrimSpace(strings.TrimSuffix(baseURL, "/"))
	if baseURL == "" {
		baseURL = "https://api.shodan.io"
	}

	u, err := url.Parse(baseURL + "/shodan/host/" + url.PathEscape(ip))
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Set("key", key)
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var parsed shodanHostResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode shodan response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("shodan api status: %s", resp.Status)
	}

	targetIP := strings.TrimSpace(parsed.IPStr)
	if targetIP == "" {
		targetIP = ip
	}

	cveKeys := mapKeys(parsed.Vulns)
	out := make([]outputRecord, 0, len(parsed.Data))
	for _, b := range parsed.Data {
		if b.Port <= 0 || b.Port > 65535 {
			continue
		}
		service := classifyService(b)
		protocol := strings.ToLower(strings.TrimSpace(b.Transport))
		if protocol == "" {
			protocol = "tcp"
		}

		rec := outputRecord{
			Provider: "shodan",
			IP:       targetIP,
			Port:     b.Port,
			Protocol: protocol,
			Service:  service,
			Product:  strings.TrimSpace(b.Product),
			Version:  strings.TrimSpace(b.Version),
			Banner:   strings.TrimSpace(b.Data),
			CVE:      cveKeys,
			Risk:     classifyRisk(cveKeys, b.Port, service),
		}
		out = append(out, rec)
		if len(out) >= maxServices {
			break
		}
	}

	return out, nil
}

func fofaLookup(ctx context.Context, client *http.Client, baseURL, email, key, ip string, maxServices int) ([]outputRecord, error) {
	baseURL = strings.TrimSpace(strings.TrimSuffix(baseURL, "/"))
	if baseURL == "" {
		baseURL = "https://fofa.info"
	}

	u, err := url.Parse(baseURL + "/api/v1/search/all")
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`ip="%s"`, ip)
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))
	v := u.Query()
	v.Set("email", email)
	v.Set("key", key)
	v.Set("qbase64", qbase64)
	v.Set("fields", "host,ip,port,protocol,title,server")
	v.Set("size", fmt.Sprintf("%d", min(maxServices, 10000)))
	v.Set("page", "1")
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fofa api: %s", resp.Status)
	}

	var parsed fofaSearchResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode fofa response: %w", err)
	}
	if parsed.Error {
		msg := strings.TrimSpace(parsed.ErrMsg)
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("fofa api: %s", msg)
	}

	out := make([]outputRecord, 0, len(parsed.Results))
	for _, row := range parsed.Results {
		host := toStringAt(row, 0)
		rowIP := toStringAt(row, 1)
		port := toIntAt(row, 2)
		protocol := strings.ToLower(toStringAt(row, 3))
		title := toStringAt(row, 4)
		server := toStringAt(row, 5)

		if rowIP == "" {
			rowIP = ip
		}
		if port <= 0 || port > 65535 {
			continue
		}
		if protocol == "" {
			protocol = "tcp"
		}

		service := classifyServiceFromFOFA(port, protocol, server, title, host)
		out = append(out, outputRecord{
			Provider: "fofa",
			IP:       rowIP,
			Port:     port,
			Protocol: protocol,
			Service:  service,
			Product:  strings.TrimSpace(server),
			Version:  "",
			Banner:   strings.TrimSpace(title),
			Risk:     classifyRisk(nil, port, service),
		})
		if len(out) >= maxServices {
			break
		}
	}

	return out, nil
}

func classifyService(b shodanBanner) string {
	mod := strings.ToLower(strings.TrimSpace(b.Shodan.Module))
	if mod != "" {
		if i := strings.Index(mod, "-"); i > 0 {
			return mod[:i]
		}
		return mod
	}

	prod := strings.ToLower(strings.TrimSpace(b.Product))
	if prod != "" {
		if strings.Contains(prod, "nginx") || strings.Contains(prod, "apache") {
			return "http"
		}
		if strings.Contains(prod, "redis") {
			return "redis"
		}
		if strings.Contains(prod, "ssh") {
			return "ssh"
		}
		if strings.Contains(prod, "smtp") {
			return "smtp"
		}
	}

	if svc, ok := commonPortServices[b.Port]; ok {
		return svc
	}

	return "unknown"
}

func classifyRisk(cve []string, port int, service string) string {
	if len(cve) > 0 {
		return "high"
	}
	if sensitiveService[service] {
		return "medium"
	}
	if sensitivePort[port] {
		return "medium"
	}
	return "low"
}

func mapKeys(m map[string]json.RawMessage) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, strings.TrimSpace(k))
	}
	sort.Strings(out)
	return out
}

func toStringAt(row []any, idx int) string {
	if idx < 0 || idx >= len(row) || row[idx] == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", row[idx]))
}

func toIntAt(row []any, idx int) int {
	if idx < 0 || idx >= len(row) || row[idx] == nil {
		return 0
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", row[idx]))
	if s == "" {
		return 0
	}
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0
	}
	return n
}

func classifyServiceFromFOFA(port int, protocol, server, title, host string) string {
	joined := strings.ToLower(strings.TrimSpace(protocol + " " + server + " " + title + " " + host))
	if strings.Contains(joined, "http") || strings.Contains(joined, "https") {
		if strings.Contains(joined, "https") || port == 443 {
			return "https"
		}
		return "http"
	}
	if strings.Contains(joined, "ssh") {
		return "ssh"
	}
	if strings.Contains(joined, "redis") {
		return "redis"
	}
	if strings.Contains(joined, "smtp") {
		return "smtp"
	}
	if svc, ok := commonPortServices[port]; ok {
		return svc
	}
	return "unknown"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var commonPortServices = map[int]string{
	22:   "ssh",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	445:  "smb",
	587:  "submission",
	993:  "imaps",
	995:  "pop3s",
	1433: "mssql",
	1521: "oracle",
	3306: "mysql",
	3389: "rdp",
	5432: "postgresql",
	6379: "redis",
	9200: "elasticsearch",
	2375: "docker",
	6443: "kubernetes",
}

var sensitiveService = map[string]bool{
	"ssh":           true,
	"rdp":           true,
	"redis":         true,
	"mongodb":       true,
	"elasticsearch": true,
	"kubernetes":    true,
	"docker":        true,
	"mysql":         true,
	"postgresql":    true,
	"smb":           true,
}

var sensitivePort = map[int]bool{
	22:   true,
	445:  true,
	3389: true,
	5432: true,
	6379: true,
	9200: true,
	2375: true,
	6443: true,
}
