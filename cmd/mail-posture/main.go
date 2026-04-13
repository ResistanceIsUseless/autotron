package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"sort"
	"strings"
	"time"
)

type config struct {
	domain     string
	check      string
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
	flag.StringVar(&cfg.check, "check", "all", "check to run: all|mx|spf-dkim-dmarc|smtp-relay")
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
	check := normalizeCheck(cfg.check)
	if check == "" {
		return fmt.Errorf("unsupported --check %q (supported: all|mx|spf-dkim-dmarc|smtp-relay)", cfg.check)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	recs := evaluateMailPosture(ctx, domain, check, cfg.timeout)
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

func evaluateMailPosture(ctx context.Context, domain string, check string, timeout time.Duration) []outputRecord {
	out := make([]outputRecord, 0)

	mxHosts := make([]string, 0)
	if check == "all" || check == "mx" || check == "smtp-relay" {
		mx, _ := net.DefaultResolver.LookupMX(ctx, domain)
		if len(mx) == 0 {
			out = append(out, rec(domain, "missing-mx", "medium", "No MX records found"))
		} else {
			for _, m := range mx {
				mxHosts = append(mxHosts, strings.TrimSuffix(strings.ToLower(m.Host), "."))
			}
			sort.Strings(mxHosts)
			out = append(out, rec(domain, "mx-records-present", "info", "MX hosts: "+strings.Join(mxHosts, ", ")))
		}
	}

	if check == "all" || check == "spf-dkim-dmarc" {
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

		dkimSelectors := []string{"default", "google", "selector1", "selector2", "mail", "smtp", "k1"}
		if !hasAnyDKIM(ctx, domain, dkimSelectors) {
			out = append(out, rec(domain, "missing-dkim", "medium", "No DKIM record found for common selectors"))
		} else {
			out = append(out, rec(domain, "dkim-present", "info", "At least one common DKIM selector resolved"))
		}
	}

	if check == "all" || check == "smtp-relay" {
		for _, host := range mxHosts {
			isOpen, reason := smtpOpenRelayProbe(host, timeout)
			if isOpen {
				out = append(out, rec(domain, "open-relay-risk", "high", "SMTP host "+host+" appears to permit unauthenticated relay"))
			} else if reason != "" {
				out = append(out, rec(domain, "smtp-relay-check", "info", "SMTP host "+host+": "+reason))
			}
		}
	}

	return out
}

func normalizeCheck(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "all", "mx", "spf-dkim-dmarc", "smtp-relay":
		return v
	default:
		return ""
	}
}

func hasAnyDKIM(ctx context.Context, domain string, selectors []string) bool {
	for _, sel := range selectors {
		fqdn := strings.TrimSpace(sel) + "._domainkey." + domain
		txt, _ := net.DefaultResolver.LookupTXT(ctx, fqdn)
		for _, t := range txt {
			if strings.Contains(strings.ToLower(t), "v=dkim1") {
				return true
			}
		}
	}
	return false
}

func smtpOpenRelayProbe(mxHost string, timeout time.Duration) (bool, string) {
	mxHost = strings.TrimSpace(strings.TrimSuffix(mxHost, "."))
	if mxHost == "" {
		return false, ""
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(mxHost, "25"), timeout)
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	r := textproto.NewReader(bufio.NewReader(conn))
	w := textproto.NewWriter(bufio.NewWriter(conn))

	line, err := r.ReadLine()
	if err != nil {
		return false, "banner read failed"
	}
	if !strings.HasPrefix(line, "220") {
		return false, "unexpected banner"
	}

	if err := w.PrintfLine("EHLO autotron.local"); err != nil {
		return false, "ehlo failed"
	}
	if _, err := readSMTPResponse(r); err != nil {
		return false, "ehlo response failed"
	}

	if err := w.PrintfLine("MAIL FROM:<relay-test@autotron.invalid>"); err != nil {
		return false, "mail from failed"
	}
	code, err := readSMTPResponse(r)
	if err != nil || (code != 250 && code != 251) {
		return false, "mail from rejected"
	}

	if err := w.PrintfLine("RCPT TO:<relay-test@external.invalid>"); err != nil {
		return false, "rcpt to failed"
	}
	rcptCode, err := readSMTPResponse(r)
	if err != nil {
		return false, "rcpt response failed"
	}

	_ = w.PrintfLine("QUIT")
	_, _ = readSMTPResponse(r)

	if rcptCode == 250 || rcptCode == 251 {
		return true, ""
	}
	return false, fmt.Sprintf("relay blocked (code %d)", rcptCode)
}

func readSMTPResponse(r *textproto.Reader) (int, error) {
	for {
		line, err := r.ReadLine()
		if err != nil {
			return 0, err
		}
		if len(line) < 3 {
			continue
		}
		var code int
		if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
			continue
		}
		if len(line) == 3 || line[3] != '-' {
			return code, nil
		}
	}
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
