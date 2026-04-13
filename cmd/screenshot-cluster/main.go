package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type config struct {
	url          string
	screenshot   string
	jsonOutput   bool
	clusterBytes int
}

type outputRecord struct {
	URL            string `json:"url"`
	ScreenshotPath string `json:"screenshot_path"`
	ClusterKey     string `json:"cluster_key"`
	Label          string `json:"label"`
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Confidence     string `json:"confidence"`
	Details        string `json:"details"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "screenshot-cluster error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.url, "url", "", "target URL")
	flag.StringVar(&cfg.screenshot, "screenshot", "", "path to screenshot file")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.IntVar(&cfg.clusterBytes, "cluster-bytes", 65536, "bytes to hash for cluster key")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	urlVal := strings.TrimSpace(cfg.url)
	if urlVal == "" {
		return errors.New("--url is required")
	}
	screenshot := strings.TrimSpace(cfg.screenshot)
	if screenshot == "" {
		return errors.New("--screenshot is required")
	}
	if cfg.clusterBytes <= 0 {
		return errors.New("--cluster-bytes must be > 0")
	}

	b, err := os.ReadFile(screenshot)
	if err != nil {
		return err
	}
	if len(b) > cfg.clusterBytes {
		b = b[:cfg.clusterBytes]
	}

	h := sha1.Sum(b)
	clusterKey := hex.EncodeToString(h[:8])

	label, findingType, severity := classifyScreenshot(filepath.Base(screenshot), b)
	rec := outputRecord{
		URL:            urlVal,
		ScreenshotPath: screenshot,
		ClusterKey:     clusterKey,
		Label:          label,
		Type:           findingType,
		Severity:       severity,
		Confidence:     "tentative",
		Details:        fmt.Sprintf("Visual cluster %s (%s)", clusterKey, label),
	}

	if cfg.jsonOutput {
		payload, _ := json.Marshal(rec)
		fmt.Println(string(payload))
	} else {
		fmt.Println(rec.ClusterKey)
	}

	return nil
}

func classifyScreenshot(name string, data []byte) (label, findingType, severity string) {
	ln := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(ln, "login") || strings.Contains(ln, "signin") || strings.Contains(ln, "auth") {
		return "login", "exposed-login-panel", "medium"
	}
	if strings.Contains(ln, "admin") || strings.Contains(ln, "dashboard") {
		return "admin", "admin-ui-detected", "medium"
	}

	text := strings.ToLower(string(data))
	if strings.Contains(text, "grafana") || strings.Contains(text, "jenkins") || strings.Contains(text, "kibana") {
		return "known-product", "known-product-panel", "medium"
	}

	return "generic", "visual-cluster-observed", "low"
}
