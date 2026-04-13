package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

type config struct {
	domain     string
	jsonOutput bool
	timeout    time.Duration
}

type outputRecord struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
	Domain   string `json:"domain"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "mail-posture error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.domain, "domain", "", "target domain")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL output")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "DNS lookup timeout")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(cfg.domain, ".")))
	if domain == "" {
		return errors.New("--domain is required")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	recs := evaluateMailPosture(ctx, domain)
	for _, rec := range recs {
		if cfg.jsonOutput {
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s\t%s\n", rec.Type, rec.Details)
		}
	}

	return nil
}

func evaluateMailPosture(ctx context.Context, domain string) []outputRecord {
	out := make([]outputRecord, 0)

	mx, _ := net.DefaultResolver.LookupMX(ctx, domain)
	if len(mx) == 0 {
		out = append(out, rec(domain, "missing-mx", "medium", "No MX records found"))
	} else {
		mxHosts := make([]string, 0, len(mx))
		for _, m := range mx {
			mxHosts = append(mxHosts, strings.TrimSuffix(strings.ToLower(m.Host), "."))
		}
		sort.Strings(mxHosts)
		out = append(out, rec(domain, "mx-records-present", "info", "MX hosts: "+strings.Join(mxHosts, ", ")))
	}

	txt, _ := net.DefaultResolver.LookupTXT(ctx, domain)
	spf := firstTXTWithPrefix(txt, "v=spf1")
	if spf == "" {
		out = append(out, rec(domain, "missing-spf", "medium", "No SPF TXT record found"))
	} else {
		out = append(out, rec(domain, "spf-present", "info", shorten("SPF: "+spf, 220)))
		if strings.Contains(spf, "+all") {
			out = append(out, rec(domain, "weak-spf-permissive", "high", "SPF contains +all (overly permissive)"))
		} else if strings.Contains(spf, "~all") {
			out = append(out, rec(domain, "softfail-spf", "low", "SPF uses ~all softfail"))
		} else if !strings.Contains(spf, "-all") {
			out = append(out, rec(domain, "spf-hardfail-missing", "low", "SPF does not include explicit -all"))
		}
	}

	dmarcDomain := "_dmarc." + domain
	dmarcTXT, _ := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	dmarc := firstTXTWithPrefix(dmarcTXT, "v=DMARC1")
	if dmarc == "" {
		out = append(out, rec(domain, "missing-dmarc", "medium", "No DMARC record found at _dmarc"))
	} else {
		out = append(out, rec(domain, "dmarc-present", "info", shorten("DMARC: "+dmarc, 220)))
		policy := extractDMARCPolicy(dmarc)
		switch policy {
		case "none":
			out = append(out, rec(domain, "weak-dmarc-policy", "medium", "DMARC policy is p=none"))
		case "quarantine", "reject":
			out = append(out, rec(domain, "dmarc-policy-enforced", "info", "DMARC policy is p="+policy))
		default:
			out = append(out, rec(domain, "dmarc-policy-unknown", "low", "Unable to parse DMARC policy"))
		}
	}

	return out
}

func rec(domain, typ, severity, details string) outputRecord {
	return outputRecord{Type: typ, Severity: severity, Details: details, Domain: domain}
}

func firstTXTWithPrefix(txt []string, prefix string) string {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), prefix) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

func extractDMARCPolicy(v string) string {
	parts := strings.Split(v, ";")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if strings.HasPrefix(p, "p=") {
			return strings.TrimPrefix(p, "p=")
		}
	}
	return ""
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
