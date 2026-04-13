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
	baseURL    string
	mode       string
	jsonOutput bool
	timeout    time.Duration
}

type outputRecord struct {
	URL        string `json:"url"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Details    string `json:"details"`
}

type oidcDiscovery struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

type jwksDocument struct {
	Keys []map[string]any `json:"keys"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "auth-surface error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.baseURL, "url", "", "target URL")
	flag.StringVar(&cfg.mode, "mode", "oidc", "scan mode: oidc")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL records")
	flag.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "HTTP timeout per request")
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
	mode := strings.ToLower(strings.TrimSpace(cfg.mode))
	if mode != "oidc" {
		return fmt.Errorf("unsupported --mode %q (supported: oidc)", cfg.mode)
	}

	ctx := context.Background()
	client := &http.Client{Timeout: cfg.timeout}

	records, err := oidcProbe(ctx, client, u)
	if err != nil {
		return err
	}

	for _, rec := range records {
		if cfg.jsonOutput {
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s\t%s\n", rec.Type, rec.URL)
		}
	}

	return nil
}

func oidcProbe(ctx context.Context, client *http.Client, target *url.URL) ([]outputRecord, error) {
	candidates := discoveryCandidates(target)
	var records []outputRecord

	for _, c := range candidates {
		doc, status, body, err := fetchDiscovery(ctx, client, c)
		if err != nil {
			continue
		}
		if status != http.StatusOK {
			continue
		}

		records = append(records, outputRecord{
			URL:        c,
			Type:       "oidc-discovery-exposed",
			Severity:   "low",
			Confidence: "firm",
			Details:    "OIDC discovery document is publicly accessible",
		})

		records = append(records, analyzeDiscovery(target, c, doc)...)
		records = append(records, analyzeJWKS(ctx, client, doc)...)

		if len(records) == 1 {
			records = append(records, outputRecord{
				URL:        c,
				Type:       "oidc-discovery-baseline",
				Severity:   "info",
				Confidence: "firm",
				Details:    fmt.Sprintf("OIDC discovery present (%d bytes)", len(body)),
			})
		}

		return records, nil
	}

	return nil, nil
}

func discoveryCandidates(target *url.URL) []string {
	base := *target
	base.RawQuery = ""
	base.Fragment = ""

	root := base
	root.Path = ""

	paths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	}

	out := make([]string, 0, len(paths)+2)
	for _, p := range paths {
		u := root
		u.Path = p
		out = append(out, u.String())
	}

	if strings.TrimSpace(target.Path) != "" && target.Path != "/" {
		trimmed := strings.TrimSuffix(target.Path, "/")
		for _, p := range paths {
			u := root
			u.Path = trimmed + p
			out = append(out, u.String())
		}
	}

	return dedupeStrings(out)
}

func fetchDiscovery(ctx context.Context, client *http.Client, target string) (oidcDiscovery, int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return oidcDiscovery{}, 0, nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return oidcDiscovery{}, 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var doc oidcDiscovery
	if len(body) > 0 {
		if err := json.Unmarshal(body, &doc); err != nil {
			return oidcDiscovery{}, resp.StatusCode, body, nil
		}
	}

	return doc, resp.StatusCode, body, nil
}

func analyzeDiscovery(target *url.URL, discoveryURL string, doc oidcDiscovery) []outputRecord {
	var out []outputRecord

	if strings.TrimSpace(doc.JWKSURI) == "" {
		out = append(out, outputRecord{
			URL:        discoveryURL,
			Type:       "oidc-missing-jwks-uri",
			Severity:   "medium",
			Confidence: "firm",
			Details:    "jwks_uri is missing from discovery document",
		})
	}

	if strings.TrimSpace(doc.Issuer) != "" {
		iss, err := url.Parse(doc.Issuer)
		if err == nil {
			if !strings.EqualFold(iss.Hostname(), target.Hostname()) {
				out = append(out, outputRecord{
					URL:        discoveryURL,
					Type:       "oidc-issuer-host-mismatch",
					Severity:   "medium",
					Confidence: "firm",
					Details:    fmt.Sprintf("issuer host %s differs from target host %s", iss.Hostname(), target.Hostname()),
				})
			}
			if iss.Scheme != "https" {
				out = append(out, outputRecord{
					URL:        discoveryURL,
					Type:       "oidc-issuer-non-https",
					Severity:   "medium",
					Confidence: "firm",
					Details:    "issuer is not HTTPS",
				})
			}
		}
	}

	if len(doc.CodeChallengeMethodsSupported) > 0 && !containsFold(doc.CodeChallengeMethodsSupported, "S256") {
		out = append(out, outputRecord{
			URL:        discoveryURL,
			Type:       "oidc-pkce-s256-missing",
			Severity:   "medium",
			Confidence: "firm",
			Details:    "code_challenge_methods_supported does not include S256",
		})
	}

	return out
}

func analyzeJWKS(ctx context.Context, client *http.Client, doc oidcDiscovery) []outputRecord {
	var out []outputRecord
	jwks := strings.TrimSpace(doc.JWKSURI)
	if jwks == "" {
		return out
	}

	u, err := url.Parse(jwks)
	if err != nil {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-jwks-uri-invalid", Severity: "medium", Confidence: "firm", Details: "jwks_uri is not a valid URL"})
		return out
	}
	if u.Scheme != "https" {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-jwks-non-https", Severity: "medium", Confidence: "firm", Details: "jwks_uri is not HTTPS"})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwks, nil)
	if err != nil {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-jwks-unreachable", Severity: "low", Confidence: "tentative", Details: err.Error()})
		return out
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-jwks-unreachable", Severity: "low", Confidence: "tentative", Details: err.Error()})
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 400 {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-jwks-http-error", Severity: "low", Confidence: "firm", Details: fmt.Sprintf("jwks_uri returned HTTP %d", resp.StatusCode)})
		return out
	}

	var parsed jwksDocument
	if err := json.Unmarshal(body, &parsed); err != nil {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-jwks-invalid-json", Severity: "medium", Confidence: "firm", Details: "jwks response is not valid JSON"})
		return out
	}

	if len(parsed.Keys) == 0 {
		out = append(out, outputRecord{URL: jwks, Type: "oidc-empty-jwks", Severity: "medium", Confidence: "firm", Details: "jwks document has zero keys"})
	}

	return out
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
