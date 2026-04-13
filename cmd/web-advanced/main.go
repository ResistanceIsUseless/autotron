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
	"strings"
	"time"
)

type config struct {
	targetURL   string
	check       string
	jsonOutput  bool
	timeout     time.Duration
	userAgent   string
	maxBodyRead int64
	idorPath    string
}

type outputRecord struct {
	URL        string `json:"url"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Signal     string `json:"signal"`
	Details    string `json:"details"`
}

type idorCandidate struct {
	path       string
	confidence string
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "web-advanced error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.targetURL, "url", "", "target URL")
	flag.StringVar(&cfg.check, "check", "desync", "check to run: desync|cache-poison|waf-diff|ssrf-gadget|idor-map|csrf-audit")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "HTTP request timeout")
	flag.StringVar(&cfg.userAgent, "user-agent", "autotron-web-advanced/1.0", "HTTP User-Agent")
	flag.Int64Var(&cfg.maxBodyRead, "max-body", 1<<20, "maximum response body bytes to read")
	flag.StringVar(&cfg.idorPath, "idor-path", "", "optional endpoint path hint for idor-map/csrf-audit")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	target := strings.TrimSpace(cfg.targetURL)
	if target == "" {
		return errors.New("--url is required")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid --url: %s", cfg.targetURL)
	}
	check := normalizeCheck(cfg.check)
	if check == "" {
		return fmt.Errorf("unsupported --check %q (supported: desync|cache-poison|waf-diff|ssrf-gadget|idor-map|csrf-audit)", cfg.check)
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}
	if cfg.maxBodyRead <= 0 {
		return errors.New("--max-body must be > 0")
	}

	ctx := context.Background()
	client := &http.Client{Timeout: cfg.timeout}

	var recs []outputRecord
	switch check {
	case "desync":
		recs, err = checkDesync(ctx, client, target, cfg)
	case "cache-poison":
		recs, err = checkCachePoison(ctx, client, target, cfg)
	case "waf-diff":
		recs, err = checkWAFDiff(ctx, client, target, cfg)
	case "ssrf-gadget":
		recs, err = checkSSRFGadget(ctx, client, target, cfg)
	case "idor-map":
		recs, err = checkIDORMap(ctx, client, target, cfg)
	case "csrf-audit":
		recs, err = checkCSRFAudit(ctx, client, target, cfg)
	}
	if err != nil {
		return err
	}

	for _, r := range recs {
		if cfg.jsonOutput {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s\t%s\n", r.Type, r.Details)
		}
	}

	return nil
}

func checkDesync(ctx context.Context, client *http.Client, target string, cfg config) ([]outputRecord, error) {
	base, err := probeGET(ctx, client, target, cfg, nil)
	if err != nil {
		return nil, err
	}

	mutHeaders := map[string]string{
		"Transfer-Encoding": "chunked",
		"Content-Length":    "4",
		"Connection":        "keep-alive",
	}
	mut, err := probeGET(ctx, client, target, cfg, mutHeaders)
	if err != nil {
		return nil, nil
	}

	if statusDrift(base.status, mut.status) || headerDrift(base.server, mut.server) {
		return []outputRecord{{
			URL:        target,
			Type:       "request-smuggling-candidate",
			Severity:   "high",
			Confidence: "firm",
			Signal:     fmt.Sprintf("baseline=%d/%s mutated=%d/%s", base.status, base.server, mut.status, mut.server),
			Details:    "response behavior changed under CL/TE ambiguity headers",
		}}, nil
	}

	return nil, nil
}

func checkCachePoison(ctx context.Context, client *http.Client, target string, cfg config) ([]outputRecord, error) {
	cacheBuster := fmt.Sprintf("autotron-%d", time.Now().UTC().UnixNano())
	qTarget := appendQuery(target, "cb", cacheBuster)

	base, err := probeGET(ctx, client, qTarget, cfg, map[string]string{"X-Forwarded-Host": "probe.attacker.invalid"})
	if err != nil {
		return nil, err
	}
	refetch, err := probeGET(ctx, client, qTarget, cfg, nil)
	if err != nil {
		return nil, nil
	}

	if strings.Contains(strings.ToLower(refetch.body), "probe.attacker.invalid") {
		return []outputRecord{{
			URL:        target,
			Type:       "cache-poisoning-candidate",
			Severity:   "high",
			Confidence: "firm",
			Signal:     "refetched response contained injected host marker",
			Details:    "possible cache key poisoning via forwarding headers",
		}}, nil
	}

	if base.cache != "" && refetch.cache != "" && strings.EqualFold(base.cache, refetch.cache) && statusDrift(base.status, refetch.status) {
		return []outputRecord{{
			URL:        target,
			Type:       "cache-poisoning-candidate",
			Severity:   "medium",
			Confidence: "tentative",
			Signal:     fmt.Sprintf("cache header stable (%s) but status drifted (%d->%d)", base.cache, base.status, refetch.status),
			Details:    "cache behavior inconsistency under header manipulation",
		}}, nil
	}

	return nil, nil
}

func checkWAFDiff(ctx context.Context, client *http.Client, target string, cfg config) ([]outputRecord, error) {
	base, err := probeGET(ctx, client, target, cfg, nil)
	if err != nil {
		return nil, err
	}

	probe, err := probeGET(ctx, client, appendQuery(target, "id", "1' OR '1'='1"), cfg, map[string]string{"X-Original-URL": "/admin"})
	if err != nil {
		return nil, nil
	}

	if statusDrift(base.status, probe.status) || headerDrift(base.server, probe.server) {
		return []outputRecord{{
			URL:        target,
			Type:       "waf-bypass-diff",
			Severity:   "medium",
			Confidence: "tentative",
			Signal:     fmt.Sprintf("baseline=%d/%s probe=%d/%s", base.status, base.server, probe.status, probe.server),
			Details:    "request tampering produced materially different response profile",
		}}, nil
	}

	return nil, nil
}

type probeResult struct {
	status     int
	server     string
	cache      string
	body       string
	csrfHeader string
	setCookie  string
}

func probeGET(ctx context.Context, client *http.Client, target string, cfg config, headers map[string]string) (probeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return probeResult{}, err
	}
	req.Header.Set("User-Agent", cfg.userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, cfg.maxBodyRead))
	return probeResult{
		status:     resp.StatusCode,
		server:     strings.TrimSpace(resp.Header.Get("Server")),
		cache:      strings.TrimSpace(resp.Header.Get("X-Cache")),
		body:       string(body),
		csrfHeader: strings.TrimSpace(resp.Header.Get("X-CSRF-Token")),
		setCookie:  strings.TrimSpace(strings.Join(resp.Header.Values("Set-Cookie"), "; ")),
	}, nil
}

func normalizeCheck(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "desync", "cache-poison", "waf-diff", "ssrf-gadget", "idor-map", "csrf-audit":
		return v
	default:
		return ""
	}
}

func checkSSRFGadget(ctx context.Context, client *http.Client, target string, cfg config) ([]outputRecord, error) {
	base, err := probeGET(ctx, client, target, cfg, nil)
	if err != nil {
		return nil, err
	}

	probeHeaders := map[string]string{
		"X-Forwarded-Host": "169.254.169.254",
		"X-Original-URL":   "/latest/meta-data/",
		"X-Rewrite-URL":    "/latest/meta-data/",
	}
	probe, err := probeGET(ctx, client, target, cfg, probeHeaders)
	if err != nil {
		return nil, nil
	}

	lowerBody := strings.ToLower(probe.body)
	hitMetadataMarker := strings.Contains(lowerBody, "ami-id") || strings.Contains(lowerBody, "instance-id") || strings.Contains(lowerBody, "security-credentials")
	if hitMetadataMarker || statusDrift(base.status, probe.status) || headerDrift(base.server, probe.server) {
		confidence := "tentative"
		severity := "medium"
		signal := fmt.Sprintf("baseline=%d/%s probe=%d/%s", base.status, base.server, probe.status, probe.server)
		if hitMetadataMarker {
			confidence = "firm"
			severity = "high"
			signal = "metadata-like marker observed in probe response"
		}

		return []outputRecord{{
			URL:        target,
			Type:       "ssrf-gadget-candidate",
			Severity:   severity,
			Confidence: confidence,
			Signal:     signal,
			Details:    "header/path tampering produced SSRF-like behavior change",
		}}, nil
	}

	return nil, nil
}

func checkIDORMap(ctx context.Context, client *http.Client, target string, cfg config) ([]outputRecord, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(u.Path)
	if p := strings.TrimSpace(cfg.idorPath); p != "" {
		path = p
	}
	candidates := idorCandidates(path)
	if len(candidates) == 0 {
		return nil, nil
	}

	base, err := probeGET(ctx, client, target, cfg, nil)
	if err != nil {
		return nil, err
	}

	var out []outputRecord
	for _, c := range candidates {
		candURL := replacePath(target, c.path)
		probe, err := probeGET(ctx, client, candURL, cfg, nil)
		if err != nil {
			continue
		}
		if statusDrift(base.status, probe.status) {
			sev := "low"
			if c.confidence == "firm" {
				sev = "medium"
			}
			out = append(out, outputRecord{
				URL:        candURL,
				Type:       "idor-candidate",
				Severity:   sev,
				Confidence: c.confidence,
				Signal:     fmt.Sprintf("status drift baseline=%d candidate=%d", base.status, probe.status),
				Details:    "resource identifier variation changed authorization behavior",
			})
		}
	}

	return out, nil
}

func checkCSRFAudit(ctx context.Context, client *http.Client, target string, cfg config) ([]outputRecord, error) {
	res, err := probeGET(ctx, client, target, cfg, nil)
	if err != nil {
		return nil, err
	}

	body := strings.ToLower(res.body)
	headers := strings.ToLower(strings.TrimSpace(res.csrfHeader + " " + res.setCookie))
	hasToken := strings.Contains(body, "csrf") || strings.Contains(body, "xsrf") || strings.Contains(body, "authenticity_token")
	hasToken = hasToken || strings.Contains(headers, "csrf") || strings.Contains(headers, "xsrf")
	if hasToken {
		return nil, nil
	}

	rec := outputRecord{
		URL:        target,
		Type:       "csrf-policy-gap",
		Severity:   "low",
		Confidence: "tentative",
		Signal:     "no csrf/xsrf/authenticity token marker observed in body",
		Details:    "state-changing surfaces may require anti-CSRF verification",
	}

	if looksStateChangingPath(target) {
		rec.Severity = "medium"
		rec.Confidence = "firm"
		rec.Signal = "state-changing path with no CSRF marker"
	}

	return []outputRecord{rec}, nil
}

func idorCandidates(path string) []idorCandidate {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	segments := strings.Split(path, "/")
	out := make([]idorCandidate, 0, 4)

	for i := len(segments) - 1; i >= 0; i-- {
		seg := strings.TrimSpace(segments[i])
		if seg == "" {
			continue
		}
		if isNumeric(seg) {
			mut := append([]string(nil), segments...)
			mut[i] = "1"
			out = append(out, idorCandidate{path: strings.Join(mut, "/"), confidence: "firm"})
			mut2 := append([]string(nil), segments...)
			mut2[i] = "9999"
			out = append(out, idorCandidate{path: strings.Join(mut2, "/"), confidence: "firm"})
			break
		}
		if strings.Contains(strings.ToLower(seg), "me") {
			mut := append([]string(nil), segments...)
			mut[i] = "admin"
			out = append(out, idorCandidate{path: strings.Join(mut, "/"), confidence: "tentative"})
			break
		}
	}

	return dedupeCandidates(out)
}

func dedupeCandidates(in []idorCandidate) []idorCandidate {
	seen := make(map[string]bool)
	out := make([]idorCandidate, 0, len(in))
	for _, c := range in {
		k := strings.TrimSpace(c.path)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

func replacePath(target, p string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	u.Path = p
	u.RawPath = ""
	u.RawQuery = ""
	return u.String()
}

func isNumeric(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksStateChangingPath(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(u.Path))
	for _, key := range []string{"/update", "/delete", "/create", "/settings", "/profile", "/account", "/admin"} {
		if strings.Contains(p, key) {
			return true
		}
	}
	return false
}

func appendQuery(target, key, val string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}

func statusDrift(a, b int) bool {
	if a == b {
		return false
	}
	if (a >= 200 && a < 300) != (b >= 200 && b < 300) {
		return true
	}
	if (a >= 300 && a < 400) != (b >= 300 && b < 400) {
		return true
	}
	if (a >= 400 && a < 500) != (b >= 400 && b < 500) {
		return true
	}
	if (a >= 500) != (b >= 500) {
		return true
	}
	return false
}

func headerDrift(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	return a != b
}
