package parsers

import (
	"context"
	"strings"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func TestSearchDorkJSONParser_Basic(t *testing.T) {
	p := &searchDorkJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}

	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"engine":"google","query":"site:example.com ext:env","url":"https://app.example.com/.env","title":"Index"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) == 0 || len(out.Findings) == 0 {
		t.Fatalf("expected url node + finding, got nodes=%d findings=%d", len(out.Nodes), len(out.Findings))
	}
}

func TestExposurePassiveJSONParser_Basic(t *testing.T) {
	p := &exposurePassiveJSONParser{}
	trigger := graph.Node{Type: graph.NodeIP, PrimaryKey: "1.2.3.4", Props: map[string]any{"address": "1.2.3.4"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"provider":"shodan","ip":"1.2.3.4","port":443,"protocol":"tcp","service":"https","product":"nginx","risk":"high"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) == 0 || len(out.Findings) == 0 {
		t.Fatalf("expected service node + finding, got nodes=%d findings=%d", len(out.Nodes), len(out.Findings))
	}
}

func TestCloudBucketJSONParser_Basic(t *testing.T) {
	p := &cloudBucketJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"provider":"aws","bucket":"example-public","public":true,"readable":true}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}

func TestRepoLeakJSONParser_Basic(t *testing.T) {
	p := &repoLeakJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"provider":"github","repo":"org/app","path":".env","type":"repo-secret-leak","match":"API_KEY=..."}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}

func TestAPISurfaceJSONParser_Basic(t *testing.T) {
	p := &apiSurfaceJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://api.example.com", Props: map[string]any{"url": "https://api.example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"base_url":"https://api.example.com","method":"GET","path":"/v1/users","finding":"openapi-exposed","severity":"medium","confidence":"firm"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Nodes) == 0 || len(out.Findings) == 0 {
		t.Fatalf("expected endpoint + finding, got nodes=%d findings=%d", len(out.Nodes), len(out.Findings))
	}
}

func TestAuthSurfaceJSONParser_Basic(t *testing.T) {
	p := &authSurfaceJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://login.example.com", Props: map[string]any{"url": "https://login.example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"url":"https://login.example.com/.well-known/openid-configuration","type":"oidc-weak-config","severity":"medium"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}

func TestHTTPAdvancedVulnJSONParser_Basic(t *testing.T) {
	p := &httpAdvancedVulnJSONParser{}
	trigger := graph.Node{Type: graph.NodeURL, PrimaryKey: "https://app.example.com", Props: map[string]any{"url": "https://app.example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"url":"https://app.example.com","type":"request-smuggling-candidate","severity":"high","signal":"cl-te"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}

func TestMailPostureJSONParser_Basic(t *testing.T) {
	p := &mailPostureJSONParser{}
	trigger := graph.Node{Type: graph.NodeDomain, PrimaryKey: "example.com", Props: map[string]any{"fqdn": "example.com"}}
	out, err := p.Parse(context.Background(), trigger, strings.NewReader(`{"domain":"example.com","type":"missing-dmarc","severity":"medium","details":"No DMARC record"}`), strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}
