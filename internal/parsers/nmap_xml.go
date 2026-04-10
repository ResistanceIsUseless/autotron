package parsers

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// nmapXMLParser handles nmap's -oX XML output across all NSE script variants.
// Multiple YAML entries share this parser (nmap_ssh, nmap_smb, nmap_http, nmap_ssl).
type nmapXMLParser struct{}

func init() {
	Register(&nmapXMLParser{})
}

func (p *nmapXMLParser) Name() string { return "nmap_xml" }

// nmap XML structures — just enough to extract what we need.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
	Hostnames nmapHostnames `xml:"hostnames"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Tunnel  string `xml:"tunnel,attr"` // "ssl" if TLS
	Extra   string `xml:"extrainfo,attr"`
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []nmapTable `xml:"table"`
	Elems  []nmapElem  `xml:"elem"`
}

type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func (p *nmapXMLParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	raw, err := io.ReadAll(stdout)
	if err != nil {
		return Result{}, fmt.Errorf("read nmap output: %w", err)
	}

	// Some hosts return truncated XML (e.g. no response, connection refused).
	// If the output is empty or doesn't contain a closing tag, try to
	// decode what we have; on failure return empty result rather than an error.
	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		// If we got nothing useful, log it but don't fail the pipeline.
		if len(raw) == 0 || !bytes.Contains(raw, []byte("<host")) {
			return Result{}, nil // no host data to parse
		}
		return Result{}, fmt.Errorf("decode nmap XML: %w", err)
	}

	var result Result

	for _, host := range run.Hosts {
		// Get primary IP from address list.
		var ip string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			ipPort := fmt.Sprintf("%s:%d", ip, port.PortID)

			// Determine product/service name.
			product := port.Service.Name
			if product == "" {
				product = "unknown"
			}

			tls := port.Service.Tunnel == "ssl"

			// Upsert/update Service node with version info from nmap.
			props := map[string]any{
				"ip_port":  ipPort,
				"ip":       ip,
				"port":     port.PortID,
				"protocol": port.Protocol,
				"product":  product,
				"status":   "open",
				"tls":      tls,
			}
			if port.Service.Product != "" {
				props["product_name"] = port.Service.Product
			}
			if port.Service.Version != "" {
				props["version"] = port.Service.Version
			}
			if port.Service.Extra != "" {
				props["extra_info"] = port.Service.Extra
			}

			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeService,
				PrimaryKey: ipPort,
				Props:      props,
			})

			// Process NSE script results as findings.
			for _, script := range port.Scripts {
				finding := p.scriptToFinding(script, ipPort, ip, port.PortID)
				if finding != nil {
					result.Findings = append(result.Findings, *finding)
				}
			}
		}

		// Extract hostnames discovered by nmap.
		for _, hn := range host.Hostnames.Hostnames {
			fqdn := strings.ToLower(strings.TrimSuffix(hn.Name, "."))
			if fqdn == "" {
				continue
			}
			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeSubdomain,
				PrimaryKey: fqdn,
				Props: map[string]any{
					"fqdn":   fqdn,
					"status": "discovered",
					"source": "nmap-hostname",
				},
			})
		}
	}

	return result, nil
}

// scriptToFinding converts an NSE script result into a Finding.
func (p *nmapXMLParser) scriptToFinding(script nmapScript, ipPort, ip string, port int) *graph.Finding {
	output := strings.TrimSpace(script.Output)
	if output == "" {
		return nil
	}

	// Classify severity based on script ID patterns.
	severity := p.classifyScriptSeverity(script.ID, output)

	finding := &graph.Finding{
		ID:         fmt.Sprintf("nmap-%s-%s", script.ID, ipPort),
		Type:       fmt.Sprintf("nmap-%s", script.ID),
		Title:      fmt.Sprintf("nmap %s on %s", script.ID, ipPort),
		Severity:   severity,
		Confidence: "confirmed",
		Tool:       "nmap",
		Evidence: map[string]any{
			"script_id": script.ID,
			"output":    output,
			"ip":        ip,
			"port":      port,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Extract table data as structured evidence.
	if len(script.Tables) > 0 {
		finding.Evidence["tables"] = p.flattenTables(script.Tables)
	}

	return finding
}

// classifyScriptSeverity assigns a severity based on the NSE script ID
// and output content. Conservative defaults — most are "info".
func (p *nmapXMLParser) classifyScriptSeverity(scriptID, output string) string {
	lower := strings.ToLower(output)

	// Known vulnerability scripts.
	if strings.Contains(scriptID, "vuln") {
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "exploitable") {
			return "high"
		}
		return "medium"
	}

	// Weak crypto / deprecated protocols.
	weakIndicators := []string{
		"des-cbc", "rc4", "md5", "sha1", "sslv2", "sslv3", "tlsv1.0",
		"diffie-hellman-group1", "diffie-hellman-group14-sha1",
	}
	for _, indicator := range weakIndicators {
		if strings.Contains(lower, indicator) {
			return "medium"
		}
	}

	// SMB enumeration / info leaks.
	if strings.HasPrefix(scriptID, "smb-enum") {
		return "low"
	}

	return "info"
}

// flattenTables converts nested nmap XML tables into a flat map structure.
func (p *nmapXMLParser) flattenTables(tables []nmapTable) []map[string]any {
	var out []map[string]any
	for _, t := range tables {
		m := make(map[string]any)
		if t.Key != "" {
			m["_key"] = t.Key
		}
		for _, e := range t.Elems {
			if e.Key != "" {
				m[e.Key] = e.Value
			} else {
				m["value"] = e.Value
			}
		}
		if len(t.Tables) > 0 {
			m["_children"] = p.flattenTables(t.Tables)
		}
		out = append(out, m)
	}
	return out
}
