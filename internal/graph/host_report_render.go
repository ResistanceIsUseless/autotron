package graph

import (
	"fmt"
	"strings"
)

func RenderHostReportMarkdown(r *HostReport) string {
	if r == nil {
		return ""
	}

	b := &strings.Builder{}
	b.WriteString(fmt.Sprintf("### %s (%s)\n", r.Host, fallback(r.PrimaryIP, "unknown")))
	b.WriteString("\n")

	b.WriteString("**DNS**\n")
	if len(r.DNS) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, rec := range r.DNS {
			b.WriteString(fmt.Sprintf("- %s -> %s\n", rec.Type, rec.Value))
		}
	}
	if len(r.AlsoResolves) > 0 {
		b.WriteString(fmt.Sprintf("- Also resolves: %s\n", strings.Join(r.AlsoResolves, ", ")))
	}
	b.WriteString("\n")

	b.WriteString("**Open Ports**\n")
	if len(r.OpenPorts) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, p := range r.OpenPorts {
			details := []string{}
			if p.Product != "" && p.Product != "<nil>" {
				details = append(details, p.Product)
			}
			if p.Version != "" && p.Version != "<nil>" {
				details = append(details, p.Version)
			}
			if p.TLS {
				tls := "TLS"
				if p.CertCN != "" && p.CertCN != "<nil>" {
					tls += fmt.Sprintf(", cert CN=%s", p.CertCN)
				}
				if p.CertNotAfter != "" && p.CertNotAfter != "<nil>" {
					tls += fmt.Sprintf(", expires %s", p.CertNotAfter)
				}
				details = append(details, tls)
			}
			b.WriteString(fmt.Sprintf("- %d/%s - %s - %s\n", p.Port, fallback(p.Protocol, "tcp"), fallback(p.Service, "unknown"), fallback(strings.Join(details, ", "), "unknown")))
		}
	}
	b.WriteString("\n")

	b.WriteString("**Discovered URL Paths**\n")
	b.WriteString("\n")
	b.WriteString("| Path | Status | Title / Notes | Notable |\n")
	b.WriteString("|---|---:|---|---|\n")
	if len(r.Paths) == 0 {
		b.WriteString("| (none) |  |  |  |\n")
	} else {
		for _, p := range r.Paths {
			notes := sanitizeTableCell(p.Title)
			if p.HasRedirect && p.FinalURL != "" {
				notes = sanitizeTableCell(strings.TrimSpace(notes + " -> " + p.FinalURL))
			}
			b.WriteString(fmt.Sprintf("| %s | %d | %s | %s |\n", sanitizeTableCell(p.Path), p.Status, fallback(notes, " "), fallback(sanitizeTableCell(p.Notable), " ")))
		}
	}
	b.WriteString("\n")

	b.WriteString("**Host Metadata**\n")
	b.WriteString(fmt.Sprintf("- ASN: %s\n", fallback(r.Metadata.ASN, "unknown")))
	b.WriteString(fmt.Sprintf("- Hosting: %s\n", fallback(r.Metadata.Hosting, "unknown")))
	b.WriteString(fmt.Sprintf("- Tech stack: %s\n", fallback(strings.Join(r.Metadata.TechStack, ", "), "unknown")))
	b.WriteString(fmt.Sprintf("- First seen: %s\n", fallback(r.Metadata.FirstSeen, "unknown")))
	b.WriteString(fmt.Sprintf("- Last seen: %s\n", fallback(r.Metadata.LastSeen, "unknown")))
	b.WriteString(fmt.Sprintf("- Tags: %s\n", fallback(strings.Join(r.Metadata.Tags, ", "), "none")))
	b.WriteString("\n")

	b.WriteString("**Findings Attached**\n")
	if len(r.Findings) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, f := range r.Findings {
			b.WriteString(fmt.Sprintf("- %s (%s) - %s\n", fallback(f.ID, "finding"), severityLabel(f.Severity), fallback(f.Title, f.Type)))
		}
	}

	return b.String()
}

func fallback(v, d string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "<nil>" {
		return d
	}
	return v
}

func sanitizeTableCell(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "|", "\\|")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}

func severityLabel(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "Info"
	}
	return strings.ToUpper(v[:1]) + v[1:]
}
