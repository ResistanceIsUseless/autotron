package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type exposurePassiveJSONParser struct{}

func init() {
	Register(&exposurePassiveJSONParser{})
}

func (p *exposurePassiveJSONParser) Name() string { return "exposure_passive_json" }

type exposureRecord struct {
	Provider string   `json:"provider"`
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Service  string   `json:"service"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Banner   string   `json:"banner"`
	CVE      []string `json:"cve"`
	Risk     string   `json:"risk"`
}

func (p *exposurePassiveJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var out Result
	seenService := make(map[string]bool)

	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec exposureRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Port <= 0 || rec.Port > 65535 {
			continue
		}
		ip := strings.TrimSpace(rec.IP)
		if ip == "" {
			ip = trigger.PrimaryKey
		}

		svcKey := fmt.Sprintf("%s:%d", ip, rec.Port)
		if !seenService[svcKey] {
			seenService[svcKey] = true
			out.Nodes = append(out.Nodes, graph.Node{
				Type:       graph.NodeService,
				PrimaryKey: svcKey,
				Props: map[string]any{
					"ip_port":      svcKey,
					"ip":           ip,
					"port":         rec.Port,
					"protocol":     fallbackString(rec.Protocol, "tcp"),
					"product":      strings.ToLower(fallbackString(rec.Service, rec.Product)),
					"product_name": rec.Product,
					"version":      rec.Version,
					"banner":       rec.Banner,
					"source":       fallbackString(strings.ToLower(rec.Provider), "passive-intel"),
				},
			})

			out.Edges = append(out.Edges, graph.Edge{
				Type:     graph.RelHAS_SERVICE,
				FromType: graph.NodeIP,
				FromKey:  ip,
				ToType:   graph.NodeService,
				ToKey:    svcKey,
			})
		}

		severity := "info"
		risk := strings.ToLower(strings.TrimSpace(rec.Risk))
		switch risk {
		case "critical", "high", "medium", "low":
			severity = risk
		}

		fid := fmt.Sprintf("passive-exposure-%s", hashKey(svcKey+"|"+strings.Join(rec.CVE, ",")))
		out.Findings = append(out.Findings, graph.Finding{
			ID:         fid,
			Type:       "exposed-service-passive",
			Title:      fmt.Sprintf("Passive exposure: %s %d/%s", fallbackString(rec.Service, "service"), rec.Port, fallbackString(rec.Protocol, "tcp")),
			Severity:   severity,
			Confidence: "firm",
			Tool:       fallbackString(strings.ToLower(rec.Provider), "passive-intel"),
			CVE:        rec.CVE,
			Evidence: map[string]any{
				"ip":       ip,
				"port":     rec.Port,
				"service":  rec.Service,
				"product":  rec.Product,
				"version":  rec.Version,
				"banner":   rec.Banner,
				"provider": rec.Provider,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		})
	}

	if err := s.Err(); err != nil {
		return Result{}, err
	}
	return out, nil
}
