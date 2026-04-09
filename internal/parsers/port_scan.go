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

// portScanParser handles tools that discover open ports on IPs:
// naabu, masscan, rustscan.
//
// Primary format: naabu JSON (-json), one object per line.
// Fallback: plain text "ip:port" per line.
type portScanParser struct{}

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

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var ip string
		var port int

		// Try JSON first (naabu -json output).
		if strings.HasPrefix(line, "{") {
			var rec naabuRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			ip = rec.IP
			if ip == "" {
				ip = rec.Host
			}
			port = rec.Port
		} else {
			// Fallback: "ip:port" or "host:port".
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			ip = strings.TrimSpace(parts[0])
			if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
				continue
			}
		}

		if ip == "" || port <= 0 || port > 65535 {
			continue
		}

		ipPort := fmt.Sprintf("%s:%d", ip, port)
		if seen[ipPort] {
			continue
		}
		seen[ipPort] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeService,
			PrimaryKey: ipPort,
			Props: map[string]any{
				"ip_port": ipPort,
				"ip":      ip,
				"port":    port,
				"status":  "open",
			},
		})

		// Edge from triggering IP to the service.
		if trigger.Type == graph.NodeIP {
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelHAS_SERVICE,
				FromType: graph.NodeIP,
				FromKey:  trigger.PrimaryKey,
				ToType:   graph.NodeService,
				ToKey:    ipPort,
			})
		}
	}

	return result, scanner.Err()
}
