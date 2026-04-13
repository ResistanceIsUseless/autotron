package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type config struct {
	baseURL      string
	mode         string
	jsonOutput   bool
	maxEndpoints int
	timeout      time.Duration
}

type record struct {
	BaseURL    string   `json:"base_url"`
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	Params     []string `json:"params,omitempty"`
	Finding    string   `json:"finding,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Details    string   `json:"details,omitempty"`
}

type basicAuthzResult struct {
	status  int
	headers http.Header
	body    string
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "api-surface error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.baseURL, "url", "", "target base URL")
	flag.StringVar(&cfg.mode, "mode", "openapi", "scan mode: openapi|graphql|authz")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.IntVar(&cfg.maxEndpoints, "max-endpoints", 200, "max discovered endpoints to emit")
	flag.DurationVar(&cfg.timeout, "timeout", 20*time.Second, "request timeout")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	if strings.TrimSpace(cfg.baseURL) == "" {
		return errors.New("--url is required")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid --url: %s", cfg.baseURL)
	}
	if cfg.maxEndpoints <= 0 {
		return errors.New("--max-endpoints must be > 0")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.mode))
	if mode != "openapi" && mode != "graphql" && mode != "authz" {
		return fmt.Errorf("unsupported --mode %q (supported: openapi|graphql|authz)", cfg.mode)
	}

	ctx := context.Background()
	client := &http.Client{Timeout: cfg.timeout}

	var records []record
	if mode == "openapi" {
		records, err = openapiProbe(ctx, client, u, cfg.maxEndpoints)
	} else if mode == "graphql" {
		records, err = graphqlProbe(ctx, client, u)
	} else {
		records, err = authzProbe(ctx, client, u, cfg.maxEndpoints)
	}
	if err != nil {
		return err
	}

	for _, r := range records {
		if cfg.jsonOutput {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		} else {
			if r.Path != "" {
				fmt.Println(r.Path)
			}
		}
	}

	return nil
}

func openapiProbe(ctx context.Context, client *http.Client, base *url.URL, maxEndpoints int) ([]record, error) {
	candidates := []string{
		"/openapi.json",
		"/swagger.json",
		"/v3/api-docs",
		"/api-docs",
		"/swagger/v1/swagger.json",
	}

	var out []record
	seenEP := make(map[string]bool)

	for _, p := range candidates {
		full := joinURL(base, p)
		body, status, err := httpGet(ctx, client, full)
		if err != nil {
			continue
		}
		if status != http.StatusOK {
			continue
		}

		lower := strings.ToLower(string(body))
		if !strings.Contains(lower, "\"openapi\"") && !strings.Contains(lower, "\"swagger\"") {
			continue
		}

		out = append(out, record{
			BaseURL:    base.String(),
			Method:     "GET",
			Path:       p,
			Finding:    "openapi-exposed",
			Severity:   "medium",
			Confidence: "firm",
			Details:    fmt.Sprintf("OpenAPI/Swagger document exposed at %s", p),
		})

		for _, ep := range extractOpenAPIEndpoints(base.String(), body, maxEndpoints) {
			k := ep.Method + "|" + ep.Path
			if seenEP[k] {
				continue
			}
			seenEP[k] = true
			out = append(out, ep)
			if len(seenEP) >= maxEndpoints {
				break
			}
		}
		if len(seenEP) >= maxEndpoints {
			break
		}
	}

	return out, nil
}

func graphqlProbe(ctx context.Context, client *http.Client, base *url.URL) ([]record, error) {
	candidates := []string{"/graphql", "/api/graphql"}
	var out []record

	for _, p := range candidates {
		full := joinURL(base, p)
		introspected, details, err := graphqlIntrospection(ctx, client, full)
		if err != nil {
			continue
		}

		out = append(out, record{BaseURL: base.String(), Method: "POST", Path: p})
		if introspected {
			out = append(out, record{
				BaseURL:    base.String(),
				Method:     "POST",
				Path:       p,
				Finding:    "graphql-introspection-enabled",
				Severity:   "medium",
				Confidence: "confirmed",
				Details:    details,
			})
			continue
		}

		if strings.Contains(strings.ToLower(details), "graphql") {
			out = append(out, record{
				BaseURL:    base.String(),
				Method:     "POST",
				Path:       p,
				Finding:    "graphql-endpoint-exposed",
				Severity:   "low",
				Confidence: "tentative",
				Details:    details,
			})
		}
	}

	return out, nil
}

func authzProbe(ctx context.Context, client *http.Client, base *url.URL, maxEndpoints int) ([]record, error) {
	paths := []string{
		"/api",
		"/api/v1",
		"/v1",
		"/graphql",
		"/users",
		"/admin",
		"/me",
		"/profile",
		"/account",
	}

	var out []record
	seen := make(map[string]bool)
	for _, p := range paths {
		full := joinURL(base, p)
		result, err := authzCheckEndpoint(ctx, client, full)
		if err != nil {
			continue
		}

		targetPath := p
		for _, rec := range toAuthzFindings(base.String(), targetPath, result) {
			k := rec.Method + "|" + rec.Path + "|" + rec.Finding + "|" + rec.Details
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, rec)
			if len(out) >= maxEndpoints {
				return out, nil
			}
		}
	}

	return out, nil
}

func authzCheckEndpoint(ctx context.Context, client *http.Client, endpoint string) (basicAuthzResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return basicAuthzResult{}, err
	}
	req.Header.Set("Accept", "application/json,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return basicAuthzResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return basicAuthzResult{status: resp.StatusCode, headers: resp.Header.Clone(), body: string(body)}, nil
}

func toAuthzFindings(baseURL, path string, r basicAuthzResult) []record {
	var out []record
	lb := strings.ToLower(r.body)

	if r.status >= 200 && r.status < 300 {
		out = append(out, record{
			BaseURL:    baseURL,
			Method:     "GET",
			Path:       path,
			Finding:    "bola-candidate",
			Severity:   "medium",
			Confidence: "tentative",
			Details:    fmt.Sprintf("endpoint responded %d without explicit auth challenge", r.status),
		})
	}

	if r.status == http.StatusForbidden || r.status == http.StatusUnauthorized {
		return out
	}

	if strings.Contains(lb, "jwt") || strings.Contains(lb, "token") || strings.Contains(lb, "authorization") {
		if r.status >= 200 && r.status < 300 {
			out = append(out, record{
				BaseURL:    baseURL,
				Method:     "GET",
				Path:       path,
				Finding:    "api-authz-heuristic",
				Severity:   "medium",
				Confidence: "tentative",
				Details:    "token/auth indicators observed in successful response",
			})
		}
	}

	if wa := strings.TrimSpace(r.headers.Get("WWW-Authenticate")); wa != "" {
		out = append(out, record{
			BaseURL:    baseURL,
			Method:     "GET",
			Path:       path,
			Finding:    "auth-challenge-observed",
			Severity:   "info",
			Confidence: "firm",
			Details:    "WWW-Authenticate present",
		})
	}

	return out
}

func extractOpenAPIEndpoints(baseURL string, body []byte, max int) []record {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}

	pathsRaw, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil
	}

	keys := make([]string, 0, len(pathsRaw))
	for p := range pathsRaw {
		keys = append(keys, p)
	}
	sort.Strings(keys)

	var out []record
	for _, p := range keys {
		methodMap, ok := pathsRaw[p].(map[string]any)
		if !ok {
			continue
		}
		for m := range methodMap {
			method := strings.ToUpper(strings.TrimSpace(m))
			switch method {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD":
			default:
				continue
			}
			out = append(out, record{BaseURL: baseURL, Method: method, Path: p})
			if len(out) >= max {
				return out
			}
		}
	}

	return out
}

func graphqlIntrospection(ctx context.Context, client *http.Client, endpoint string) (bool, string, error) {
	payload := `{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(payload))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 500 {
		return false, string(body), nil
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err == nil {
		if data, ok := parsed["data"].(map[string]any); ok {
			if _, ok := data["__schema"]; ok {
				return true, "GraphQL introspection returned __schema", nil
			}
		}
		if errs, ok := parsed["errors"]; ok {
			return false, fmt.Sprintf("graphql errors: %v", errs), nil
		}
	}

	return false, string(body), nil
}

func joinURL(base *url.URL, p string) string {
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + p
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func httpGet(ctx context.Context, client *http.Client, target string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return body, resp.StatusCode, nil
}
