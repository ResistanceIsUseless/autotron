package parsers

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// hostnameListParser handles tools that emit one hostname per line:
// subfinder, assetfinder, amass, crt.sh, dnstwist, theHarvester.
type hostnameListParser struct{}

func init() {
	Register(&hostnameListParser{})
}

func (p *hostnameListParser) Name() string { return "hostname_list" }

func (p *hostnameListParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result

	scanner := bufio.NewScanner(stdout)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize: lowercase, strip trailing dot.
		fqdn := strings.ToLower(strings.TrimSuffix(line, "."))

		// Deduplicate within this parse run.
		if seen[fqdn] {
			continue
		}
		seen[fqdn] = true

		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props: map[string]any{
				"fqdn":   fqdn,
				"status": "discovered",
			},
		})

		// Edge from trigger domain to discovered subdomain.
		if trigger.Type == graph.NodeDomain {
			result.Edges = append(result.Edges, graph.Edge{
				Type:     graph.RelHAS,
				FromType: graph.NodeDomain,
				FromKey:  trigger.PrimaryKey,
				ToType:   graph.NodeSubdomain,
				ToKey:    fqdn,
			})
		}
	}

	return result, scanner.Err()
}
