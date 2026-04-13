package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type config struct {
	provider    string
	domain      string
	jsonOutput  bool
	maxResults  int
	timeout     time.Duration
	delay       time.Duration
	githubToken string
	githubAPI   string
}

type outputRecord struct {
	Provider string `json:"provider"`
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	Type     string `json:"type"`
	Match    string `json:"match"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
}

type githubSearchResponse struct {
	Items []struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		TextMatches []struct {
			Fragment string `json:"fragment"`
			Matches  []struct {
				Text string `json:"text"`
			} `json:"matches"`
		} `json:"text_matches"`
	} `json:"items"`
	Message string `json:"message"`
}

type searchQuery struct {
	Query string
	Type  string
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "repo-intel error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.provider, "provider", "github", "provider to query (github)")
	flag.StringVar(&cfg.domain, "domain", "", "target domain to pivot on")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL records")
	flag.IntVar(&cfg.maxResults, "max-results", 50, "max output records")
	flag.DurationVar(&cfg.timeout, "timeout", 20*time.Second, "HTTP timeout")
	flag.DurationVar(&cfg.delay, "delay", 400*time.Millisecond, "delay between API calls")
	flag.StringVar(&cfg.githubToken, "github-token", "", "GitHub token (or GITHUB_TOKEN)")
	flag.StringVar(&cfg.githubAPI, "github-api", "https://api.github.com", "GitHub API base URL")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	if strings.TrimSpace(cfg.domain) == "" {
		return errors.New("--domain is required")
	}
	if cfg.maxResults <= 0 {
		return errors.New("--max-results must be > 0")
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.provider))
	if provider != "github" {
		return fmt.Errorf("unsupported --provider %q (supported: github)", cfg.provider)
	}

	token := strings.TrimSpace(cfg.githubToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if token == "" {
		return errors.New("missing GitHub token (set GITHUB_TOKEN)")
	}

	client := &http.Client{Timeout: cfg.timeout}
	ctx := context.Background()

	queries := defaultRepoQueries(strings.ToLower(strings.TrimSpace(cfg.domain)))
	emitted := 0
	for i, q := range queries {
		if emitted >= cfg.maxResults {
			break
		}

		remaining := cfg.maxResults - emitted
		records, err := githubCodeSearch(ctx, client, cfg.githubAPI, token, q, remaining)
		if err != nil {
			fmt.Fprintf(os.Stderr, "github query failed (%s): %v\n", q.Query, err)
			continue
		}

		for _, r := range records {
			if cfg.jsonOutput {
				b, _ := json.Marshal(r)
				fmt.Println(string(b))
			} else {
				fmt.Println(r.URL)
			}
			emitted++
			if emitted >= cfg.maxResults {
				break
			}
		}

		if i < len(queries)-1 {
			time.Sleep(cfg.delay)
		}
	}

	return nil
}

func defaultRepoQueries(domain string) []searchQuery {
	return []searchQuery{
		{Query: fmt.Sprintf("\"%s\" (apikey OR secret OR token OR password)", domain), Type: "repo-secret-leak"},
		{Query: fmt.Sprintf("\"%s\" (.env OR config OR credentials)", domain), Type: "repo-internal-host-leak"},
		{Query: fmt.Sprintf("\"%s\" (corp OR internal OR staging)", domain), Type: "repo-internal-host-leak"},
	}
}

func githubCodeSearch(ctx context.Context, client *http.Client, apiBase, token string, sq searchQuery, maxResults int) ([]outputRecord, error) {
	apiBase = strings.TrimSuffix(strings.TrimSpace(apiBase), "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}

	u, err := url.Parse(apiBase + "/search/code")
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Set("q", sq.Query)
	v.Set("per_page", strconv.Itoa(min(maxResults, 100)))
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.text-match+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var parsed githubSearchResponse
	if len(body) > 0 {
		_ = json.Unmarshal(body, &parsed)
	}

	if resp.StatusCode >= 400 {
		msg := resp.Status
		if strings.TrimSpace(parsed.Message) != "" {
			msg = parsed.Message
		}
		return nil, fmt.Errorf("github api: %s", msg)
	}

	out := make([]outputRecord, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		fragment := ""
		match := ""
		if len(item.TextMatches) > 0 {
			fragment = strings.TrimSpace(item.TextMatches[0].Fragment)
			if len(item.TextMatches[0].Matches) > 0 {
				match = strings.TrimSpace(item.TextMatches[0].Matches[0].Text)
			}
		}

		sev := classifyRepoSeverity(sq.Type, item.Path, fragment)
		out = append(out, outputRecord{
			Provider: "github",
			Repo:     item.Repository.FullName,
			Path:     item.Path,
			URL:      item.HTMLURL,
			Type:     sq.Type,
			Match:    fallback(match, fragment),
			Line:     0,
			Severity: sev,
		})
		if len(out) >= maxResults {
			break
		}
	}

	return out, nil
}

func classifyRepoSeverity(findingType, path, fragment string) string {
	joined := strings.ToLower(path + " " + fragment + " " + findingType)
	if strings.Contains(joined, "private_key") || strings.Contains(joined, "aws_access_key") || strings.Contains(joined, "token") {
		return "high"
	}
	if strings.Contains(joined, ".env") || strings.Contains(joined, "credentials") || strings.Contains(joined, "secret") {
		return "medium"
	}
	return "low"
}

func fallback(v, d string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return d
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
