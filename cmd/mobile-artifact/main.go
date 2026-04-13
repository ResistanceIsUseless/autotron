package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type config struct {
	artifactURL  string
	artifactType string
	jsonOutput   bool
	maxEndpoints int
	timeout      time.Duration
	maxBytes     int64
	userAgent    string
}

type outputRecord struct {
	ArtifactURL  string `json:"artifact_url"`
	ArtifactType string `json:"artifact_type"`
	EndpointURL  string `json:"endpoint_url,omitempty"`
	Method       string `json:"method,omitempty"`
	Path         string `json:"path,omitempty"`
	Finding      string `json:"finding"`
	Severity     string `json:"severity"`
	Confidence   string `json:"confidence"`
	Details      string `json:"details"`
	Evidence     string `json:"evidence,omitempty"`
}

type endpointCandidate struct {
	endpointURL string
	method      string
	path        string
	kind        string
	evidence    string
}

var (
	absoluteURLRe = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	relativeAPIRe = regexp.MustCompile(`/(?:api|v[0-9]+|graphql|oauth|auth|login)[A-Za-z0-9._~:/?#%&=+-]*`)
)

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "mobile-artifact error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.artifactURL, "artifact-url", "", "URL to mobile artifact (.apk/.ipa)")
	flag.StringVar(&cfg.artifactType, "artifact-type", "", "artifact type override (apk|ipa)")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.IntVar(&cfg.maxEndpoints, "max-endpoints", 200, "maximum endpoint findings to emit")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "HTTP timeout per request")
	flag.Int64Var(&cfg.maxBytes, "max-bytes", 8<<20, "max bytes to fetch from artifact")
	flag.StringVar(&cfg.userAgent, "user-agent", "autotron-mobile-artifact/1.0", "HTTP User-Agent")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	artifactURL := strings.TrimSpace(cfg.artifactURL)
	if artifactURL == "" {
		return errors.New("--artifact-url is required")
	}

	parsed, err := url.Parse(artifactURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid --artifact-url: %s", cfg.artifactURL)
	}
	if cfg.maxEndpoints <= 0 {
		return errors.New("--max-endpoints must be > 0")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}
	if cfg.maxBytes <= 0 {
		return errors.New("--max-bytes must be > 0")
	}

	artifactType := inferArtifactType(artifactURL, cfg.artifactType)
	if artifactType == "" {
		artifactType = "mobile"
	}

	client := &http.Client{Timeout: cfg.timeout}
	body, err := fetchArtifact(context.Background(), client, artifactURL, cfg.userAgent, cfg.maxBytes)
	if err != nil {
		return err
	}

	strs := extractPrintableStrings(body, 10)
	candidates := extractEndpointCandidates(strs, parsed, cfg.maxEndpoints)

	for _, c := range candidates {
		rec := outputRecord{
			ArtifactURL:  artifactURL,
			ArtifactType: artifactType,
			EndpointURL:  c.endpointURL,
			Method:       c.method,
			Path:         c.path,
			Finding:      "mobile-endpoint-discovered",
			Severity:     "low",
			Confidence:   "tentative",
			Details:      fmt.Sprintf("%s endpoint extracted from mobile artifact", c.kind),
			Evidence:     shorten(c.evidence, 220),
		}

		if cfg.jsonOutput {
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
		} else {
			fmt.Println(rec.EndpointURL)
		}
	}

	return nil
}

func fetchArtifact(ctx context.Context, client *http.Client, target, userAgent string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/octet-stream,*/*")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBytes-1))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("artifact fetch status: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func inferArtifactType(artifactURL, override string) string {
	o := strings.ToLower(strings.TrimSpace(override))
	switch o {
	case "apk", "ipa":
		return o
	}

	u, err := url.Parse(strings.TrimSpace(artifactURL))
	if err != nil {
		return ""
	}
	path := strings.ToLower(strings.TrimSpace(u.Path))
	switch {
	case strings.HasSuffix(path, ".apk"):
		return "apk"
	case strings.HasSuffix(path, ".ipa"):
		return "ipa"
	default:
		return ""
	}
}

func extractPrintableStrings(data []byte, minLen int) []string {
	if minLen < 1 {
		minLen = 1
	}

	seen := make(map[string]bool)
	out := make([]string, 0, 2048)
	buf := make([]byte, 0, 128)
	flush := func() {
		if len(buf) < minLen {
			buf = buf[:0]
			return
		}
		s := strings.TrimSpace(string(buf))
		buf = buf[:0]
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	for _, b := range data {
		if b >= 32 && b <= 126 {
			buf = append(buf, b)
			continue
		}
		flush()
	}
	flush()

	return out
}

func extractEndpointCandidates(strs []string, artifact *url.URL, max int) []endpointCandidate {
	if max <= 0 {
		return nil
	}

	base := artifact.Scheme + "://" + artifact.Host
	seen := make(map[string]bool)
	out := make([]endpointCandidate, 0, max)

	add := func(c endpointCandidate) {
		if c.endpointURL == "" || c.path == "" {
			return
		}
		key := c.method + "|" + c.endpointURL + "|" + c.path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, c)
	}

	for _, s := range strs {
		if len(out) >= max {
			break
		}

		for _, raw := range absoluteURLRe.FindAllString(s, -1) {
			raw = strings.TrimSpace(strings.Trim(raw, `"'()[]{}<>,;`))
			u, err := url.Parse(raw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				continue
			}
			path := normalizedPathWithQuery(u)
			if looksStaticAssetPath(path) {
				continue
			}
			endpointURL := u.Scheme + "://" + u.Host
			add(endpointCandidate{
				endpointURL: endpointURL,
				method:      "GET",
				path:        path,
				kind:        "absolute",
				evidence:    raw,
			})
			if len(out) >= max {
				break
			}
		}

		if len(out) >= max {
			break
		}

		for _, rel := range relativeAPIRe.FindAllString(s, -1) {
			rel = strings.TrimSpace(strings.Trim(rel, `"'()[]{}<>,;`))
			if rel == "" || looksStaticAssetPath(rel) {
				continue
			}
			add(endpointCandidate{
				endpointURL: base,
				method:      "GET",
				path:        rel,
				kind:        "relative",
				evidence:    rel,
			})
			if len(out) >= max {
				break
			}
		}
	}

	return out
}

func normalizedPathWithQuery(u *url.URL) string {
	p := strings.TrimSpace(u.EscapedPath())
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

func looksStaticAssetPath(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return true
	}
	for _, suffix := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webm"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

func shorten(v string, max int) string {
	v = strings.TrimSpace(v)
	if len(v) <= max {
		return v
	}
	if max < 4 {
		return v[:max]
	}
	return v[:max-3] + "..."
}
