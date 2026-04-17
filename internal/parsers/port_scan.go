package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// portScanParser handles tools that discover open ports:
// naabu, masscan, rustscan.
//
// Primary format: naabu JSON (-json), one object per line.
// Fallback: plain text "ip:port" per line.
//
// When triggered by a Subdomain node (the primary flow), the parser creates
// both IP and Service nodes from naabu output, plus IP→HAS_SERVICE edges.
// When triggered by an IP node (legacy/alternative scanners), it creates
// Service nodes and IP→HAS_SERVICE edges as before.
//
// Because naabu only reports open ports (not service identification), the parser
// infers product and TLS status from well-known port numbers so that downstream
// enrichers (httpx_probe, nmap_ssh, nmap_smb, tlsx_cert, etc.) can trigger.
type portScanParser struct{}

// wellKnownProducts maps port numbers to their most common service product.
// Aligned with the ASM scan port list: HTTP-like services use "http" or "https"
// so that httpx_probe and nmap_http_scripts enrichers trigger correctly.
var wellKnownProducts = map[int]string{
	// Core infrastructure
	21:  "ftp",
	22:  "ssh",
	23:  "telnet",
	25:  "smtp",
	53:  "dns",
	110: "pop3",
	111: "rpcbind",
	135: "msrpc",
	139: "netbios-ssn",
	143: "imap",
	445: "smb",
	465: "smtps",
	587: "smtp",
	623: "ipmi",
	631: "ipp",
	636: "ldaps",
	993: "imaps",
	995: "pop3s",

	// HTTP services
	80:    "http",
	999:   "http",
	1080:  "http",
	1880:  "http", // Node-RED
	1098:  "http", // JMX / Java RMI
	1099:  "http", // Java RMI
	2379:  "http", // etcd
	3128:  "http", // Squid proxy
	3632:  "http", // distcc
	4001:  "http", // etcd
	4848:  "http", // GlassFish
	5001:  "http", // Docker registry / Synology
	5002:  "http",
	5800:  "http", // VNC HTTP
	5836:  "http",
	6002:  "http",
	6379:  "redis",
	6739:  "http",
	6782:  "http", // Weave Scope
	6783:  "http",
	6784:  "http",
	7001:  "http", // WebLogic
	7002:  "http", // WebLogic
	7071:  "http", // Zimbra
	8000:  "http",
	8001:  "http",
	8002:  "http",
	8003:  "http",
	8004:  "http",
	8005:  "http",
	8006:  "http",
	8007:  "http",
	8008:  "http",
	8009:  "http", // AJP
	8010:  "http",
	8080:  "http",
	8081:  "http",
	8118:  "http", // Privoxy
	8444:  "http",
	8500:  "http", // Consul
	8888:  "http",
	9001:  "http", // Supervisord
	9060:  "http", // WebSphere
	9090:  "http", // Prometheus / Cockpit
	9093:  "http", // Alertmanager
	9099:  "http",
	9100:  "http", // node_exporter
	9901:  "http", // Envoy admin
	9999:  "http",
	10000: "http", // Webmin
	10250: "http", // Kubelet API
	10255: "http", // Kubelet read-only
	10256: "http", // kube-proxy healthz
	38801: "http",
	53281: "http",

	// HTTPS services
	443:  "https",
	2443: "https",
	3443: "https",
	4443: "https",
	5443: "https",
	6443: "https", // Kubernetes API
	7443: "https",
	8443: "https",
	9443: "https",

	// Windows / RDP
	389:  "ldap",
	3389: "rdp",
	3390: "rdp",
	3391: "rdp",
	3392: "rdp",
	3393: "rdp",
	3394: "rdp",
	3395: "rdp",
	3396: "rdp",
	3397: "rdp",
	3398: "rdp",
	5985: "http",  // WinRM HTTP
	5986: "https", // WinRM HTTPS

	// VNC
	5900: "vnc",
	5901: "vnc",
	5902: "vnc",
	5903: "vnc",
	5904: "vnc",
	5905: "vnc",
	5906: "vnc",
	5907: "vnc",
	5908: "vnc",
	5909: "vnc",
	5910: "vnc",

	// Databases / caches
	1433:  "mssql",
	1521:  "oracle",
	2049:  "nfs",
	3306:  "mysql",
	5432:  "postgresql",
	9200:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

// tlsPorts is the set of ports that typically use TLS.
var tlsPorts = map[int]bool{
	443:  true,
	465:  true,
	636:  true,
	993:  true,
	995:  true,
	2443: true,
	3443: true,
	4443: true,
	5443: true,
	5986: true,
	6443: true,
	7443: true,
	8443: true,
	9443: true,
}

func init() {
	Register(&portScanParser{})
}

func (p *portScanParser) Name() string { return "port_scan" }

// naabuRecord represents a single naabu JSON output line.
type naabuRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (p *portScanParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result
	seen := make(map[string]bool)
	seenIPs := make(map[string]bool)

	// The trigger is a Subdomain node — use its FQDN as the canonical hostname
	// for any Service nodes we create. naabu's "host" field should match but
	// we prefer the trigger FQDN as the authoritative source.
	triggerFQDN, _ := trigger.Props["fqdn"].(string)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var ip string
		var host string
		var port int

		// Try JSON first (naabu -json output).
		if strings.HasPrefix(line, "{") {
			var rec naabuRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			ip = rec.IP
			host = rec.Host
			port = rec.Port
		} else {
			// Fallback: "ip:port" or "host:port".
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			host = strings.TrimSpace(parts[0])
			if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
				continue
			}
		}

		if port <= 0 || port > 65535 {
			continue
		}

		// Determine the FQDN for the Service key. Prefer trigger FQDN,
		// fall back to naabu's host field, then IP as last resort.
		fqdn := triggerFQDN
		if fqdn == "" {
			fqdn = host
		}
		if fqdn == "" {
			fqdn = ip
		}
		if fqdn == "" {
			continue
		}

		fqdnPort := fmt.Sprintf("%s:%d", fqdn, port)
		if seen[fqdnPort] {
			continue
		}
		seen[fqdnPort] = true

		// Upsert IP node if we have one and haven't seen it yet.
		if ip != "" && !seenIPs[ip] {
			seenIPs[ip] = true
			result.Nodes = append(result.Nodes, graph.Node{
				Type:       graph.NodeIP,
				PrimaryKey: ip,
				Props: map[string]any{
					"address": ip,
				},
			})
		}

		// Infer product and TLS from well-known port numbers.
		props := map[string]any{
			"fqdn_port": fqdnPort,
			"fqdn":      fqdn,
			"port":      port,
			"status":    "open",
		}
		// Store IP as informational metadata (not part of the key).
		if ip != "" {
			props["ip"] = ip
		}
		if product, ok := wellKnownProducts[port]; ok {
			props["product"] = product
		}
		if tlsPorts[port] {
			props["tls"] = true
		}

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeService,
			PrimaryKey: fqdnPort,
			Props:      props,
		})

		// Subdomain → HAS_SERVICE → Service (primary relationship).
		if triggerFQDN != "" {
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelHAS_SERVICE,
				FromType: graph.NodeSubdomain,
				FromKey:  triggerFQDN,
				ToType:   graph.NodeService,
				ToKey:    fqdnPort,
			})
		}

		// IP → HAS_SERVICE → Service (informational, for reverse lookups).
		if ip != "" {
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelHAS_SERVICE,
				FromType: graph.NodeIP,
				FromKey:  ip,
				ToType:   graph.NodeService,
				ToKey:    fqdnPort,
			})
		}
	}

	return result, scanner.Err()
}
