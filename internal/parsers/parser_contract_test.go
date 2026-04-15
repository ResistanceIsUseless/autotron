package parsers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestHostnameListParser_SuccessAndEmpty(t *testing.T) {
	p := &hostnameListParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}

	stdout := fixture(t, "hostname_list_success.txt")
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(result.Nodes) != 1 {
		t.Fatalf("expected 1 deduped node, got %d", len(result.Nodes))
	}
	if result.Nodes[0].PrimaryKey != "api.example.com" {
		t.Fatalf("unexpected fqdn normalization: %q", result.Nodes[0].PrimaryKey)
	}
	if len(result.Edges) != 1 {
		t.Fatalf("expected 1 domain->subdomain edge, got %d", len(result.Edges))
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("\n\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty parse failed: %v", err)
	}
	if len(empty.Nodes) != 0 || len(empty.Edges) != 0 {
		t.Fatalf("expected no mutations for empty output, got nodes=%d edges=%d", len(empty.Nodes), len(empty.Edges))
	}
}

func TestDNSResolverParser_JSONAndPlain(t *testing.T) {
	p := &dnsResolverParser{}
	trigger := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "api.example.com", Props: map[string]any{"fqdn": "api.example.com"}}

	stdout := fixture(t, "dns_resolver_mixed.txt")

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if !hasNode(result.Nodes, graph.NodeIP, "1.2.3.4") {
		t.Fatal("expected resolved IP node")
	}
	if !hasNode(result.Nodes, graph.NodeSubdomain, "edge.example.net") {
		t.Fatal("expected cname target subdomain node")
	}
	if !hasEdgeType(result.Edges, graph.RelRESOLVES_TO) {
		t.Fatal("expected RESOLVES_TO edge")
	}
	if !hasEdgeType(result.Edges, graph.RelCNAME) {
		t.Fatal("expected CNAME edge")
	}
}

func TestPortScanParser_JSONAndFallback(t *testing.T) {
	p := &portScanParser{}
	trigger := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "api.example.com", Props: map[string]any{"fqdn": "api.example.com"}}

	stdout := fixture(t, "port_scan_mixed.txt")

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if !hasNode(result.Nodes, graph.NodeIP, "1.2.3.4") {
		t.Fatal("expected IP node")
	}
	if !hasNode(result.Nodes, graph.NodeService, "1.2.3.4:443") || !hasNode(result.Nodes, graph.NodeService, "1.2.3.4:80") {
		t.Fatal("expected service nodes for 443 and 80")
	}
	if len(result.Edges) != 2 {
		t.Fatalf("expected 2 HAS_SERVICE edges, got %d", len(result.Edges))
	}
}

func TestHTTPProbeParser_SuccessAndMalformed(t *testing.T) {
	p := &httpProbeParser{}
	trigger := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "api.example.com", Props: map[string]any{"fqdn": "api.example.com"}}

	stdout := fixture(t, "http_probe_mixed.jsonl")

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if !hasNode(result.Nodes, graph.NodeURL, "https://api.example.com") {
		t.Fatal("expected URL node")
	}
	if !hasNode(result.Nodes, graph.NodeTechnology, technologyID("nginx", "")) {
		t.Fatal("expected technology node for nginx")
	}
	if !hasEdgeType(result.Edges, graph.RelSERVES) || !hasEdgeType(result.Edges, graph.RelRUNS) {
		t.Fatal("expected SERVES and RUNS edges")
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("{bad\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("malformed-only parse failed: %v", err)
	}
	if len(empty.Nodes) != 0 && len(empty.Findings) != 0 {
		t.Fatalf("expected no mutations for malformed-only input, got nodes=%d findings=%d", len(empty.Nodes), len(empty.Findings))
	}
}

func TestURLListParser_MixedFormats(t *testing.T) {
	p := &urlListParser{}
	trigger := graph.Node{Type: graph.NodeSubdomain, PrimaryKey: "api.example.com", Props: map[string]any{"fqdn": "api.example.com"}}

	stdout := fixture(t, "url_list_mixed.txt")

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 URL nodes, got %d", len(result.Nodes))
	}
	if len(result.Edges) != 3 {
		t.Fatalf("expected 3 SERVES edges, got %d", len(result.Edges))
	}
	if !hasNode(result.Nodes, graph.NodeURL, "https://example.com/a") {
		t.Fatal("expected normalized URL without fragment")
	}
}

func TestNmapXMLParser_SuccessAndMalformedHostXML(t *testing.T) {
	p := &nmapXMLParser{}
	trigger := graph.Node{Type: graph.NodeService, PrimaryKey: "1.2.3.4:443", Props: map[string]any{"ip_port": "1.2.3.4:443"}}

	xmlOut := fixture(t, "nmap_success.xml")
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(xmlOut), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if !hasNode(result.Nodes, graph.NodeService, "1.2.3.4:443") {
		t.Fatal("expected service node from nmap XML")
	}
	if !hasNode(result.Nodes, graph.NodeSubdomain, "api.example.com") {
		t.Fatal("expected discovered hostname node")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected finding from nmap script output")
	}

	_, err = p.Parse(context.Background(), trigger, strings.NewReader("<nmaprun><host>"), strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for malformed XML containing host data")
	}
}

func TestTLSAuditParser_SuccessAndMalformed(t *testing.T) {
	p := &tlsAuditParser{}
	trigger := graph.Node{Type: graph.NodeService, PrimaryKey: "1.2.3.4:443", Props: map[string]any{"ip": "1.2.3.4", "port": 443}}

	stdout := fixture(t, "tls_audit_success.jsonl")
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if !hasNodeType(result.Nodes, graph.NodeCertificate) {
		t.Fatal("expected certificate node")
	}
	if !hasNode(result.Nodes, graph.NodeSubdomain, "api.example.com") {
		t.Fatal("expected SAN-derived subdomain node")
	}
	if len(result.Findings) < 2 {
		t.Fatalf("expected multiple TLS findings, got %d", len(result.Findings))
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("{bad-json}"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("malformed-only parse failed: %v", err)
	}
	if len(empty.Nodes) != 0 || len(empty.Findings) != 0 {
		t.Fatalf("expected no output for malformed-only TLS input, got nodes=%d findings=%d", len(empty.Nodes), len(empty.Findings))
	}
}

func TestNucleiJSONLParser_SuccessAndIgnoreMalformed(t *testing.T) {
	p := &nucleiJSONLParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://api.example.com", Props: map[string]any{"url": "https://api.example.com"}}

	stdout := fixture(t, "nuclei_mixed.jsonl")

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 nuclei finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != "high" || f.Type != "cve-cve-2023-9999" {
		t.Fatalf("unexpected finding fields: severity=%s type=%s", f.Severity, f.Type)
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty parse failed: %v", err)
	}
	if len(empty.Findings) != 0 {
		t.Fatalf("expected no findings for empty output, got %d", len(empty.Findings))
	}
}

func TestProxyhawkJSONParser_SuccessAndDecodeError(t *testing.T) {
	p := &proxyhawkJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://api.example.com", Props: map[string]any{"url": "https://api.example.com"}}

	stdout := fixture(t, "proxyhawk_success.json")
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity == "" || result.Findings[0].Confidence == "" {
		t.Fatal("expected severity/confidence defaults to be populated")
	}

	if _, err := p.Parse(context.Background(), trigger, strings.NewReader(""), strings.NewReader("")); err == nil {
		t.Fatal("expected decode error for empty proxyhawk output")
	}
}

func TestWebVulnGenericParser_Nikto25And26Shapes(t *testing.T) {
	p := &webVulnGenericParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://api.example.com", Props: map[string]any{"url": "https://api.example.com"}}

	// Nikto 2.5-ish shape: string id + vulnerabilities array.
	v25 := fixture(t, "nikto_25_sample.json")
	res25, err := p.Parse(context.Background(), trigger, strings.NewReader(v25), strings.NewReader(""))
	if err != nil {
		t.Fatalf("nikto 2.5 parse failed: %v", err)
	}
	if len(res25.Findings) != 2 {
		t.Fatalf("expected 2 findings for nikto 2.5 sample, got %d", len(res25.Findings))
	}
	if !strings.HasPrefix(res25.Findings[0].Type, "nikto-") {
		t.Fatalf("expected nikto type prefix, got %q", res25.Findings[0].Type)
	}

	// Nikto 2.6-ish shape: numeric id + references + server_banner.
	v26 := fixture(t, "nikto_26_sample.json")
	res26, err := p.Parse(context.Background(), trigger, strings.NewReader(v26), strings.NewReader(""))
	if err != nil {
		t.Fatalf("nikto 2.6 parse failed: %v", err)
	}
	if len(res26.Findings) != 2 {
		t.Fatalf("expected 2 findings for nikto 2.6 sample, got %d", len(res26.Findings))
	}

	var foundRefs bool
	var foundBannerChange bool
	for _, f := range res26.Findings {
		if refs, ok := f.Evidence["references"]; ok {
			if len(refs.([]string)) > 0 {
				foundRefs = true
			}
		}
		if f.Type == "nikto-999962" {
			foundBannerChange = true
		}
	}
	if !foundRefs {
		t.Fatalf("expected at least one nikto 2.6 finding with references evidence")
	}
	if !foundBannerChange {
		t.Fatalf("expected nikto-999962 banner-change finding")
	}

	if !hasNodeType(res26.Nodes, graph.NodeService) {
		t.Fatalf("expected service node update from nikto banner-change check")
	}
}

func TestSecretScannerParser_TrufflehogAndGitleaks(t *testing.T) {
	p := &secretScannerParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://api.example.com", Props: map[string]any{"url": "https://api.example.com"}}

	trufflehog := fixture(t, "secret_trufflehog.jsonl")
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(trufflehog), strings.NewReader(""))
	if err != nil {
		t.Fatalf("trufflehog parse failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 trufflehog finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != "critical" || result.Findings[0].Confidence != "confirmed" {
		t.Fatalf("unexpected verified trufflehog finding confidence/severity: %s/%s", result.Findings[0].Severity, result.Findings[0].Confidence)
	}

	gitleaks := fixture(t, "secret_gitleaks.json")
	result, err = p.Parse(context.Background(), trigger, strings.NewReader(gitleaks), strings.NewReader(""))
	if err != nil {
		t.Fatalf("gitleaks parse failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 gitleaks finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Tool != "gitleaks" {
		t.Fatalf("expected gitleaks tool tag, got %s", result.Findings[0].Tool)
	}

	empty, err := p.Parse(context.Background(), trigger, strings.NewReader("\n"), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty parse failed: %v", err)
	}
	if len(empty.Findings) != 0 {
		t.Fatalf("expected no findings for empty output, got %d", len(empty.Findings))
	}
}

func TestSubscopeJSONParser_ProgressPrefixAndNoJSONError(t *testing.T) {
	p := &subscopeJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}

	stdout := fixture(t, "subscope_progress_output.txt")

	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !hasNode(result.Nodes, graph.NodeSubdomain, "api.example.com") {
		t.Fatal("expected discovered subdomain")
	}
	if !hasNode(result.Nodes, graph.NodeIP, "1.2.3.4") {
		t.Fatal("expected resolved IP")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected cloud-tag finding, got %d", len(result.Findings))
	}

	if _, err := p.Parse(context.Background(), trigger, strings.NewReader("progress only"), strings.NewReader("")); err == nil {
		t.Fatal("expected error when no JSON object is present")
	}
}

func TestJSReconJSONParser_FindingsShape(t *testing.T) {
	p := &jsreconJSONParser{}
	trigger := graph.Node{Type: graph.NodeJSFile, PrimaryKey: "https://cdn.example.com/app.js", Props: map[string]any{"url": "https://app.example.com"}}

	stdout := fixture(t, "jsrecon_findings.json")
	result, err := p.Parse(context.Background(), trigger, strings.NewReader(stdout), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if !hasNodeType(result.Nodes, graph.NodeEndpoint) {
		t.Fatal("expected endpoint node from jsrecon path finding")
	}
	if !hasEdgeType(result.Edges, graph.RelEXPOSES) {
		t.Fatal("expected EXPOSES edge from parent URL to Endpoint")
	}
	if len(result.Findings) < 3 {
		t.Fatalf("expected at least 3 findings mirrored from jsrecon output, got %d", len(result.Findings))
	}

	findingTypes := map[string]bool{}
	for _, f := range result.Findings {
		findingTypes[f.Type] = true
	}
	if !findingTypes["jsrecon-secret-github_token"] {
		t.Fatal("expected secret-derived jsrecon finding type")
	}
	if !findingTypes["jsrecon-vulnerability-xss_dom_sink"] {
		t.Fatal("expected vulnerability-derived jsrecon finding type")
	}
}

func hasNode(nodes []graph.Node, nodeType graph.NodeType, key string) bool {
	for _, n := range nodes {
		if n.Type == nodeType && n.PrimaryKey == key {
			return true
		}
	}
	return false
}

func hasNodeType(nodes []graph.Node, nodeType graph.NodeType) bool {
	for _, n := range nodes {
		if n.Type == nodeType {
			return true
		}
	}
	return false
}

func hasEdgeType(edges []graph.Edge, rel graph.RelType) bool {
	for _, e := range edges {
		if e.Type == rel {
			return true
		}
	}
	return false
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("testdata", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}
