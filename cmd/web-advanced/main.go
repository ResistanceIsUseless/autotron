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
}

type outputRecord struct {
	URL        string `json:"url"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Signal     string `json:"signal"`
	Details    string `json:"details"`
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
	flag.StringVar(&cfg.check, "check", "desync", "check to run: desync|cache-poison|waf-diff")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "HTTP request timeout")
	flag.StringVar(&cfg.userAgent, "user-agent", "autotron-web-advanced/1.0", "HTTP User-Agent")
	flag.Int64Var(&cfg.maxBodyRead, "max-body", 1<<20, "maximum response body bytes to read")
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
		return fmt.Errorf("unsupported --check %q (supported: desync|cache-poison|waf-diff)", cfg.check)
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
	status int
	server string
	cache  string
	body   string
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
		status: resp.StatusCode,
		server: strings.TrimSpace(resp.Header.Get("Server")),
		cache:  strings.TrimSpace(resp.Header.Get("X-Cache")),
		body:   string(body),
	}, nil
}

func normalizeCheck(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "desync", "cache-poison", "waf-diff":
		return v
	default:
		return ""
	}
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
