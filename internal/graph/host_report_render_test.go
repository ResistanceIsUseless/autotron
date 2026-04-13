package graph

import (
	"strings"
	"testing"
)

func TestRenderHostReportMarkdown_BasicSections(t *testing.T) {
	r := &HostReport{
		Host:      "app.example.com",
		PrimaryIP: "203.0.113.45",
		DNS:       []HostDNSRecord{{Type: "A", Value: "203.0.113.45"}},
		OpenPorts: []HostPort{{Port: 443, Protocol: "tcp", Service: "https", Product: "nginx", TLS: true, CertCN: "*.example.com"}},
		Paths:     []HostPath{{Path: "/", Status: 200, Title: "home"}},
		Findings:  []HostFindingRef{{ID: "F-1", Severity: "high", Title: "test finding"}},
		Metadata:  HostMetadata{ASN: "AS64500", Hosting: "Self-hosted", TechStack: []string{"nginx"}, Tags: []string{"internet-facing"}},
	}

	out := RenderHostReportMarkdown(r)
	checks := []string{
		"### app.example.com (203.0.113.45)",
		"**DNS**",
		"**Open Ports**",
		"**Discovered URL Paths**",
		"**Host Metadata**",
		"**Findings Attached**",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q in output:\n%s", want, out)
		}
	}
}
