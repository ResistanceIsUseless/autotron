package main

import (
	"context"
	"encoding/base64"
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
	gitlabToken string
	gitlabAPI   string
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

type gitlabProject struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	DefaultBranch     string `json:"default_branch"`
}

type gitlabBlob struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
	Ref      string `json:"ref"`
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
	flag.StringVar(&cfg.provider, "provider", "github", "provider to query (github|gitlab)")
	flag.StringVar(&cfg.domain, "domain", "", "target domain to pivot on")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL records")
	flag.IntVar(&cfg.maxResults, "max-results", 50, "max output records")
	flag.DurationVar(&cfg.timeout, "timeout", 20*time.Second, "HTTP timeout")
	flag.DurationVar(&cfg.delay, "delay", 400*time.Millisecond, "delay between API calls")
	flag.StringVar(&cfg.githubToken, "github-token", "", "GitHub token (or GITHUB_TOKEN)")
	flag.StringVar(&cfg.githubAPI, "github-api", "https://api.github.com", "GitHub API base URL")
	flag.StringVar(&cfg.gitlabToken, "gitlab-token", "", "GitLab token (or GITLAB_TOKEN)")
	flag.StringVar(&cfg.gitlabAPI, "gitlab-api", "https://gitlab.com/api/v4", "GitLab API base URL")
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
	if provider != "github" && provider != "gitlab" {
		return fmt.Errorf("unsupported --provider %q (supported: github|gitlab)", cfg.provider)
	}

	token := strings.TrimSpace(cfg.githubToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	gitlabToken := strings.TrimSpace(cfg.gitlabToken)
	if gitlabToken == "" {
		gitlabToken = strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
	}

	if provider == "github" && token == "" {
		return errors.New("missing GitHub token (set GITHUB_TOKEN)")
	}
	if provider == "gitlab" && gitlabToken == "" {
		return errors.New("missing GitLab token (set GITLAB_TOKEN)")
	}

	client := &http.Client{Timeout: cfg.timeout}
	ctx := context.Background()

	domain := strings.ToLower(strings.TrimSpace(cfg.domain))
	queries := defaultRepoQueries(domain)
	emitted := 0
	for i, q := range queries {
		if emitted >= cfg.maxResults {
			break
		}

		remaining := cfg.maxResults - emitted
		var records []outputRecord
		var err error
		switch provider {
		case "github":
			records, err = githubCodeSearch(ctx, client, cfg.githubAPI, token, q, remaining)
		case "gitlab":
			records, err = gitlabCodeSearch(ctx, client, cfg.gitlabAPI, gitlabToken, domain, q, remaining)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s query failed (%s): %v\n", provider, q.Query, err)
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

func gitlabCodeSearch(ctx context.Context, client *http.Client, apiBase, token, domain string, sq searchQuery, maxResults int) ([]outputRecord, error) {
	apiBase = strings.TrimSuffix(strings.TrimSpace(apiBase), "/")
	if apiBase == "" {
		apiBase = "https://gitlab.com/api/v4"
	}

	projects, err := gitlabSearchProjects(ctx, client, apiBase, token, domain, min(maxResults, 25))
	if err != nil {
		return nil, err
	}

	patterns := queryPatternsForType(domain, sq.Type)
	out := make([]outputRecord, 0, maxResults)
	for _, p := range projects {
		branch := strings.TrimSpace(p.DefaultBranch)
		if branch == "" {
			branch = "main"
		}

		tree, err := gitlabListProjectTree(ctx, client, apiBase, token, p.ID, branch, 150)
		if err != nil {
			continue
		}

		for _, filePath := range tree {
			if !likelySensitivePath(filePath) {
				continue
			}

			blob, err := gitlabGetFile(ctx, client, apiBase, token, p.ID, filePath, branch)
			if err != nil {
				continue
			}
			content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob.Content))
			if err != nil {
				continue
			}

			fragment := strings.ToLower(string(content))
			if !strings.Contains(fragment, domain) {
				continue
			}

			matched := ""
			for _, pat := range patterns {
				if strings.Contains(fragment, pat) {
					matched = pat
					break
				}
			}
			if matched == "" {
				continue
			}

			sev := classifyRepoSeverity(sq.Type, filePath, matched)
			repoPath := p.PathWithNamespace
			webURL := strings.TrimSpace(p.WebURL)
			if webURL == "" {
				webURL = fmt.Sprintf("https://gitlab.com/%s", strings.TrimPrefix(repoPath, "/"))
			}
			recordURL := fmt.Sprintf("%s/-/blob/%s/%s", strings.TrimSuffix(webURL, "/"), branch, escapePathSegments(filePath))

			out = append(out, outputRecord{
				Provider: "gitlab",
				Repo:     repoPath,
				Path:     filePath,
				URL:      recordURL,
				Type:     sq.Type,
				Match:    matched,
				Line:     0,
				Severity: sev,
			})
			if len(out) >= maxResults {
				return out, nil
			}
		}
	}

	return out, nil
}

func gitlabSearchProjects(ctx context.Context, client *http.Client, apiBase, token, domain string, maxProjects int) ([]gitlabProject, error) {
	u, err := url.Parse(apiBase + "/projects")
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Set("search", domain)
	v.Set("simple", "true")
	v.Set("order_by", "last_activity_at")
	v.Set("sort", "desc")
	v.Set("per_page", strconv.Itoa(min(maxProjects, 100)))
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gitlab api: %s", resp.Status)
	}

	var projects []gitlabProject
	if err := json.Unmarshal(body, &projects); err != nil {
		return nil, fmt.Errorf("decode gitlab projects: %w", err)
	}
	return projects, nil
}

func gitlabListProjectTree(ctx context.Context, client *http.Client, apiBase, token string, projectID int, branch string, max int) ([]string, error) {
	u, err := url.Parse(fmt.Sprintf("%s/projects/%d/repository/tree", apiBase, projectID))
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Set("ref", branch)
	v.Set("recursive", "true")
	v.Set("per_page", strconv.Itoa(min(max, 1000)))
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gitlab api: %s", resp.Status)
	}

	var entries []struct {
		Type string `json:"type"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decode gitlab tree: %w", err)
	}

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type != "blob" || strings.TrimSpace(e.Path) == "" {
			continue
		}
		out = append(out, e.Path)
		if len(out) >= max {
			break
		}
	}
	return out, nil
}

func gitlabGetFile(ctx context.Context, client *http.Client, apiBase, token string, projectID int, filePath, branch string) (gitlabBlob, error) {
	encodedPath := url.PathEscape(filePath)
	u, err := url.Parse(fmt.Sprintf("%s/projects/%d/repository/files/%s", apiBase, projectID, encodedPath))
	if err != nil {
		return gitlabBlob{}, err
	}
	v := u.Query()
	v.Set("ref", branch)
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return gitlabBlob{}, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return gitlabBlob{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	if resp.StatusCode >= 400 {
		return gitlabBlob{}, fmt.Errorf("gitlab api: %s", resp.Status)
	}

	var blob gitlabBlob
	if err := json.Unmarshal(body, &blob); err != nil {
		return gitlabBlob{}, fmt.Errorf("decode gitlab file: %w", err)
	}
	return blob, nil
}

func likelySensitivePath(path string) bool {
	lp := strings.ToLower(strings.TrimSpace(path))
	if lp == "" {
		return false
	}
	for _, s := range []string{".env", "config", "secret", "credentials", "token", "key", "settings", "yaml", "yml", "json", "ini", "toml"} {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

func queryPatternsForType(domain, findingType string) []string {
	base := []string{domain, "apikey", "api_key", "secret", "token", "password", "internal", "staging"}
	if findingType == "repo-secret-leak" {
		return append(base, "private_key", "aws_access_key", "bearer ")
	}
	if findingType == "repo-internal-host-leak" {
		return append(base, "corp", "vpn", "admin")
	}
	return base
}

func escapePathSegments(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
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
