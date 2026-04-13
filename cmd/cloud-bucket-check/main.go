package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type config struct {
	provider      string
	domain        string
	jsonOutput    bool
	maxCandidates int
	timeout       time.Duration
}

type outputRecord struct {
	Provider string   `json:"provider"`
	Bucket   string   `json:"bucket"`
	Region   string   `json:"region"`
	Public   bool     `json:"public"`
	Listable bool     `json:"listable"`
	Readable bool     `json:"readable"`
	Objects  []string `json:"objects,omitempty"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "cloud-bucket-check error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.provider, "provider", "aws", "provider to check (aws|gcp|azure)")
	flag.StringVar(&cfg.domain, "domain", "", "target domain")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL records")
	flag.IntVar(&cfg.maxCandidates, "max-candidates", 8, "max bucket candidates to test")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "HTTP timeout per request")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	domain := normalizeDomain(cfg.domain)
	if domain == "" {
		return errors.New("--domain is required")
	}
	if cfg.maxCandidates <= 0 {
		return errors.New("--max-candidates must be > 0")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.provider))
	if provider != "aws" && provider != "gcp" && provider != "azure" {
		return fmt.Errorf("unsupported --provider %q (supported: aws|gcp|azure)", cfg.provider)
	}

	candidates := bucketCandidates(domain, cfg.maxCandidates)
	client := &http.Client{Timeout: cfg.timeout}
	ctx := context.Background()

	for _, bucket := range candidates {
		rec, ok := probeBucket(ctx, client, provider, bucket)
		if !ok {
			continue
		}
		if cfg.jsonOutput {
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
		} else {
			fmt.Println(rec.Bucket)
		}
	}

	return nil
}

func probeBucket(ctx context.Context, client *http.Client, provider, bucket string) (outputRecord, bool) {
	switch provider {
	case "aws":
		return probeAWS(ctx, client, bucket)
	case "gcp":
		return probeGCP(ctx, client, bucket)
	case "azure":
		return probeAzure(ctx, client, bucket)
	default:
		return outputRecord{}, false
	}
}

func probeAWS(ctx context.Context, client *http.Client, bucket string) (outputRecord, bool) {
	target := fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
	body, status, err := httpGet(ctx, client, target)
	if err != nil {
		return outputRecord{}, false
	}

	rec := outputRecord{Provider: "aws", Bucket: bucket}
	if status == http.StatusNotFound {
		return outputRecord{}, false
	}

	if status == http.StatusOK {
		rec.Public = true
		rec.Listable = strings.Contains(strings.ToLower(string(body)), "listbucketresult")
		rec.Readable = rec.Listable
		rec.Objects = extractObjectsFromXML(body)
		return rec, true
	}

	if status == http.StatusForbidden {
		if strings.Contains(strings.ToLower(string(body)), "nosuchbucket") {
			return outputRecord{}, false
		}
		return rec, true
	}

	if status == http.StatusMovedPermanently || status == http.StatusTemporaryRedirect {
		rec.Region = parseAWSRegionHint(body)
		return rec, true
	}

	return outputRecord{}, false
}

func probeGCP(ctx context.Context, client *http.Client, bucket string) (outputRecord, bool) {
	target := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
	body, status, err := httpGet(ctx, client, target)
	if err != nil {
		return outputRecord{}, false
	}

	rec := outputRecord{Provider: "gcp", Bucket: bucket}
	if status == http.StatusNotFound {
		return outputRecord{}, false
	}

	if status == http.StatusOK {
		rec.Public = true
		rec.Listable = strings.Contains(strings.ToLower(string(body)), "listbucketresult")
		rec.Readable = rec.Listable
		rec.Objects = extractObjectsFromXML(body)
		return rec, true
	}

	if status == http.StatusForbidden {
		if strings.Contains(strings.ToLower(string(body)), "nosuchbucket") {
			return outputRecord{}, false
		}
		return rec, true
	}

	return outputRecord{}, false
}

func probeAzure(ctx context.Context, client *http.Client, bucket string) (outputRecord, bool) {
	target := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", bucket)
	body, status, err := httpGet(ctx, client, target)
	if err != nil {
		return outputRecord{}, false
	}

	rec := outputRecord{Provider: "azure", Bucket: bucket}
	if status == http.StatusNotFound {
		return outputRecord{}, false
	}

	if status == http.StatusOK {
		rec.Public = true
		rec.Listable = strings.Contains(strings.ToLower(string(body)), "enumerationresults")
		rec.Readable = rec.Listable
		rec.Objects = extractObjectsFromAzureXML(body)
		return rec, true
	}

	if status == http.StatusForbidden {
		if strings.Contains(strings.ToLower(string(body)), "containernotfound") {
			return outputRecord{}, false
		}
		return rec, true
	}

	return outputRecord{}, false
}

func httpGet(ctx context.Context, client *http.Client, target string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/xml,application/json,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return body, resp.StatusCode, nil
}

func bucketCandidates(domain string, max int) []string {
	parts := strings.Split(domain, ".")
	candidates := []string{
		domain,
		strings.ReplaceAll(domain, ".", "-"),
		strings.ReplaceAll(domain, ".", ""),
	}
	if len(parts) > 0 {
		candidates = append(candidates, parts[0])
	}
	if len(parts) > 1 {
		candidates = append(candidates, parts[0]+"-"+parts[1])
	}

	set := make(map[string]bool)
	uniq := make([]string, 0, len(candidates))
	for _, c := range candidates {
		c = sanitizeBucketName(c)
		if c == "" || set[c] {
			continue
		}
		set[c] = true
		uniq = append(uniq, c)
	}

	sort.Strings(uniq)
	if len(uniq) > max {
		uniq = uniq[:max]
	}
	return uniq
}

func sanitizeBucketName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.Trim(v, "-.")
	v = strings.ReplaceAll(v, "_", "-")
	v = strings.ReplaceAll(v, " ", "-")
	v = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			return r
		}
		return -1
	}, v)
	if len(v) < 3 {
		return ""
	}
	return v
}

func normalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimSuffix(v, ".")
	return v
}

func extractObjectsFromXML(body []byte) []string {
	text := string(body)
	objs := extractXMLTagValues(text, "Key")
	if len(objs) > 3 {
		objs = objs[:3]
	}
	return objs
}

func extractObjectsFromAzureXML(body []byte) []string {
	text := string(body)
	objs := extractXMLTagValues(text, "Name")
	if len(objs) > 3 {
		objs = objs[:3]
	}
	return objs
}

func extractXMLTagValues(text, tag string) []string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	vals := []string{}

	for {
		i := strings.Index(text, open)
		if i < 0 {
			break
		}
		text = text[i+len(open):]
		j := strings.Index(text, close)
		if j < 0 {
			break
		}
		val := strings.TrimSpace(text[:j])
		if val != "" {
			vals = append(vals, val)
		}
		text = text[j+len(close):]
	}

	return vals
}

func parseAWSRegionHint(body []byte) string {
	vals := extractXMLTagValues(string(body), "Region")
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}
