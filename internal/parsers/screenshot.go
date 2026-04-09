package parsers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// screenshotParser handles screenshot tools: gowitness.
//
// gowitness outputs JSON to stdout with the screenshot file path and metadata.
// If no JSON is detected, falls back to scanning stderr/stdout for file paths.
//
// Emits: URL property update (screenshot_path). No new nodes.
type screenshotParser struct{}

func init() {
	Register(&screenshotParser{})
}

func (p *screenshotParser) Name() string { return "screenshot" }

// gowitnessSingleResult represents gowitness "single" command JSON output.
type gowitnessSingleResult struct {
	URL            string `json:"url"`
	FinalURL       string `json:"final_url"`
	StatusCode     int    `json:"status_code"`
	Filename       string `json:"filename"`
	ScreenshotPath string `json:"screenshot_path"`
	Title          string `json:"title"`
	Failed         bool   `json:"failed"`
}

func (p *screenshotParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var result Result

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	var screenshotPath string
	var parsedJSON bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try JSON parsing.
		if strings.HasPrefix(line, "{") {
			var rec gowitnessSingleResult
			if err := json.Unmarshal([]byte(line), &rec); err == nil {
				parsedJSON = true
				if rec.Failed {
					continue
				}

				// Prefer screenshot_path, fall back to filename.
				path := rec.ScreenshotPath
				if path == "" {
					path = rec.Filename
				}
				if path != "" {
					screenshotPath = path
				}
			}
		}

		// Fallback: look for file path output on stdout.
		if !parsedJSON && screenshotPath == "" {
			if strings.HasSuffix(line, ".png") || strings.HasSuffix(line, ".jpg") || strings.HasSuffix(line, ".jpeg") {
				screenshotPath = line
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return result, err
	}

	// Update the triggering URL node with the screenshot path.
	if screenshotPath != "" && trigger.Type == graph.NodeURL {
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeURL,
			PrimaryKey: trigger.PrimaryKey,
			Props: map[string]any{
				"url":             trigger.PrimaryKey,
				"screenshot_path": screenshotPath,
			},
		})
	}

	return result, nil
}
