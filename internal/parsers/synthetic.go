package parsers

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// syntheticTestParser is a fake parser used to verify the dispatch loop
// end-to-end without real tools. It reads stdin lines formatted as
// "subdomain.example.com" and creates Subdomain nodes — same shape as
// hostname_list but registered under a different name for testing.
//
// Enable it with a YAML entry:
//   - name: test_synthetic
//     parser: synthetic_test
//     subscribes:
//     node_type: Domain
//     predicate: "n.in_scope = true"
//     command:
//     bin: echo
//     args: ["sub1.{{.Node.fqdn}}\nsub2.{{.Node.fqdn}}"]
//     timeout: 10s
//     concurrency: 1
//     enabled: true
type syntheticTestParser struct{}

func init() {
	Register(&syntheticTestParser{})
}

func (p *syntheticTestParser) Name() string { return "synthetic_test" }

func (p *syntheticTestParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result

	scanner := bufio.NewScanner(stdout)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fqdn := strings.ToLower(strings.TrimSuffix(line, "."))
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
				"source": "synthetic_test",
			},
		})

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
