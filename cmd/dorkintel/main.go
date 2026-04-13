package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	engine     string
	domain     string
	jsonOutput bool
	maxResults int
	delay      time.Duration
	timeout    time.Duration
	googleKey  string
	googleCX   string
	bingKey    string
}

type dorkQuery struct {
	Query string
	Class string
}

type outputRecord struct {
	Engine  string `json:"engine"`
	Query   string `json:"query"`
	URL     string `json:"url"`
	Title   string `json:"title"`
	Snippet string `json:"snippet"`
	Class   string `json:"class"`
	Rank    int    `json:"rank"`
}

type searchItem struct {
	Title   string
	Link    string
	Snippet string
}

type googleSearchResponse struct {
	Items []struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		Snippet string `json:"snippet"`
	} `json:"items"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type bingSearchResponse struct {
	WebPages *struct {
		Value []struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Snippet string `json:"snippet"`
		} `json:"value"`
	} `json:"webPages"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "dorkintel error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.engine, "engine", "google", "search engine provider (google)")
	flag.StringVar(&cfg.domain, "domain", "", "target domain to query")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL records")
	flag.IntVar(&cfg.maxResults, "max-results", 30, "maximum records to emit")
	flag.DurationVar(&cfg.delay, "delay", 500*time.Millisecond, "delay between API requests")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "HTTP timeout per request")
	flag.StringVar(&cfg.googleKey, "google-key", "", "Google CSE API key (or GOOGLE_CSE_API_KEY)")
	flag.StringVar(&cfg.googleCX, "google-cx", "", "Google CSE CX identifier (or GOOGLE_CSE_CX)")
	flag.StringVar(&cfg.bingKey, "bing-key", "", "Bing Search API key (or BING_SEARCH_API_KEY)")
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
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}

	engine := strings.ToLower(strings.TrimSpace(cfg.engine))
	if engine != "google" && engine != "bing" {
		return fmt.Errorf("unsupported --engine %q (supported: google, bing)", cfg.engine)
	}

	googleKey := strings.TrimSpace(cfg.googleKey)
	if googleKey == "" {
		googleKey = strings.TrimSpace(os.Getenv("GOOGLE_CSE_API_KEY"))
	}
	googleCX := strings.TrimSpace(cfg.googleCX)
	if googleCX == "" {
		googleCX = strings.TrimSpace(os.Getenv("GOOGLE_CSE_CX"))
	}
	bingKey := strings.TrimSpace(cfg.bingKey)
	if bingKey == "" {
		bingKey = strings.TrimSpace(os.Getenv("BING_SEARCH_API_KEY"))
	}

	if engine == "google" && (googleKey == "" || googleCX == "") {
		return errors.New("missing Google CSE credentials (set GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX)")
	}
	if engine == "bing" && bingKey == "" {
		return errors.New("missing Bing Search API key (set BING_SEARCH_API_KEY)")
	}

	client := &http.Client{Timeout: cfg.timeout}
	ctx := context.Background()
	queries := defaultDorks(cfg.domain)

	emitted := 0
	rank := 1
	for qi, q := range queries {
		if emitted >= cfg.maxResults {
			break
		}

		start := 1
		for {
			if emitted >= cfg.maxResults {
				break
			}
			remaining := cfg.maxResults - emitted
			num := remaining
			if num > 10 {
				num = 10
			}

			items, err := search(engine, ctx, client, googleKey, googleCX, bingKey, q.Query, start, num)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s query failed (%s): %v\n", engine, q.Query, err)
				break
			}
			if len(items) == 0 {
				break
			}

			for _, item := range items {
				rec := outputRecord{
					Engine:  engine,
					Query:   q.Query,
					URL:     item.Link,
					Title:   item.Title,
					Snippet: item.Snippet,
					Class:   q.Class,
					Rank:    rank,
				}
				rank++
				emitted++

				if cfg.jsonOutput {
					b, _ := json.Marshal(rec)
					fmt.Println(string(b))
				} else {
					fmt.Println(rec.URL)
				}

				if emitted >= cfg.maxResults {
					break
				}
			}

			start += len(items)
			if start > 91 || len(items) < num {
				break
			}

			time.Sleep(cfg.delay)
		}

		if qi < len(queries)-1 {
			time.Sleep(cfg.delay)
		}
	}

	return nil
}

func search(engine string, ctx context.Context, client *http.Client, googleKey, googleCX, bingKey, query string, start, num int) ([]searchItem, error) {
	switch engine {
	case "google":
		return googleSearch(ctx, client, googleKey, googleCX, query, start, num)
	case "bing":
		return bingSearch(ctx, client, bingKey, query, start, num)
	default:
		return nil, fmt.Errorf("unsupported engine %q", engine)
	}
}

func defaultDorks(domain string) []dorkQuery {
	d := strings.TrimSpace(strings.ToLower(domain))
	return []dorkQuery{
		{Query: fmt.Sprintf("site:%s ext:env | ext:ini | ext:log", d), Class: "indexed-exposed-config"},
		{Query: fmt.Sprintf("site:%s inurl:admin | inurl:login", d), Class: "indexed-admin-surface"},
		{Query: fmt.Sprintf("site:%s \"index of\"", d), Class: "indexed-sensitive-path"},
		{Query: fmt.Sprintf("site:%s ext:sql | ext:bak | ext:zip", d), Class: "indexed-sensitive-path"},
		{Query: fmt.Sprintf("site:%s intext:apikey | intext:secret", d), Class: "indexed-secret"},
	}
}

func googleSearch(ctx context.Context, client *http.Client, key, cx, query string, start, num int) ([]searchItem, error) {
	u, err := url.Parse("https://customsearch.googleapis.com/customsearch/v1")
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Set("key", key)
	v.Set("cx", cx)
	v.Set("q", query)
	v.Set("start", fmt.Sprintf("%d", start))
	v.Set("num", fmt.Sprintf("%d", num))
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed googleSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode google response: %w", err)
	}

	if resp.StatusCode >= 400 {
		msg := resp.Status
		if parsed.Error != nil && strings.TrimSpace(parsed.Error.Message) != "" {
			msg = parsed.Error.Message
		}
		return nil, fmt.Errorf("google api: %s", msg)
	}

	items := make([]searchItem, 0, len(parsed.Items))
	for _, it := range parsed.Items {
		items = append(items, searchItem{Title: it.Title, Link: it.Link, Snippet: it.Snippet})
	}
	return items, nil
}

func bingSearch(ctx context.Context, client *http.Client, key, query string, start, num int) ([]searchItem, error) {
	u, err := url.Parse("https://api.bing.microsoft.com/v7.0/search")
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Set("q", query)
	v.Set("count", fmt.Sprintf("%d", num))
	v.Set("offset", fmt.Sprintf("%d", start-1))
	v.Set("responseFilter", "Webpages")
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed bingSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode bing response: %w", err)
	}

	if resp.StatusCode >= 400 {
		msg := resp.Status
		if parsed.Error != nil && strings.TrimSpace(parsed.Error.Message) != "" {
			msg = parsed.Error.Message
		}
		return nil, fmt.Errorf("bing api: %s", msg)
	}

	if parsed.WebPages == nil {
		return nil, nil
	}

	items := make([]searchItem, 0, len(parsed.WebPages.Value))
	for _, it := range parsed.WebPages.Value {
		items = append(items, searchItem{Title: it.Name, Link: it.URL, Snippet: it.Snippet})
	}
	return items, nil
}
