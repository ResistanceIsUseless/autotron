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
	"strings"
	"time"
)

type config struct {
	domain        string
	engine        string
	jsonOutput    bool
	maxResults    int
	requestDelay  time.Duration
	timeout       time.Duration
	googleKey     string
	googleCX      string
	bingKey       string
	yandexUser    string
	yandexKey     string
	maxRedirects  int
	expandTimeout time.Duration
}

type outputRecord struct {
	Engine      string `json:"engine"`
	Query       string `json:"query"`
	ShortURL    string `json:"short_url"`
	FinalURL    string `json:"final_url"`
	Host        string `json:"host"`
	Class       string `json:"class"`
	Rank        int    `json:"rank"`
	ChainLength int    `json:"chain_length"`
}

type searchItem struct {
	Title   string `json:"title"`
	Link    string `json:"link"`
	Snippet string `json:"snippet"`
}

type googleResp struct {
	Items []searchItem `json:"items"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type bingResp struct {
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
		fmt.Fprintln(os.Stderr, "url-shortener-intel error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.domain, "domain", "", "target domain")
	flag.StringVar(&cfg.engine, "engine", "google", "search engine provider (google|bing|yandex)")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "emit JSONL")
	flag.IntVar(&cfg.maxResults, "max-results", 40, "maximum records")
	flag.DurationVar(&cfg.requestDelay, "delay", 500*time.Millisecond, "delay between API calls")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "search API timeout")
	flag.StringVar(&cfg.googleKey, "google-key", "", "Google CSE API key (or GOOGLE_CSE_API_KEY)")
	flag.StringVar(&cfg.googleCX, "google-cx", "", "Google CSE CX (or GOOGLE_CSE_CX)")
	flag.StringVar(&cfg.bingKey, "bing-key", "", "Bing API key (or BING_SEARCH_API_KEY)")
	flag.StringVar(&cfg.yandexUser, "yandex-user", "", "Yandex XML user (or YANDEX_XML_USER)")
	flag.StringVar(&cfg.yandexKey, "yandex-key", "", "Yandex XML key (or YANDEX_XML_KEY)")
	flag.IntVar(&cfg.maxRedirects, "max-redirects", 6, "maximum redirects while expanding short URLs")
	flag.DurationVar(&cfg.expandTimeout, "expand-timeout", 10*time.Second, "timeout for short URL expansion")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	domain := strings.ToLower(strings.TrimSpace(cfg.domain))
	if domain == "" {
		return errors.New("--domain is required")
	}
	if cfg.maxResults <= 0 {
		return errors.New("--max-results must be > 0")
	}
	if cfg.maxRedirects < 1 {
		return errors.New("--max-redirects must be >= 1")
	}

	engine := strings.ToLower(strings.TrimSpace(cfg.engine))
	if engine != "google" && engine != "bing" && engine != "yandex" {
		return fmt.Errorf("unsupported --engine %q (supported: google|bing|yandex)", cfg.engine)
	}

	googleKey := fallbackEnv(cfg.googleKey, "GOOGLE_CSE_API_KEY")
	googleCX := fallbackEnv(cfg.googleCX, "GOOGLE_CSE_CX")
	bingKey := fallbackEnv(cfg.bingKey, "BING_SEARCH_API_KEY")
	yandexUser := fallbackEnv(cfg.yandexUser, "YANDEX_XML_USER")
	yandexKey := fallbackEnv(cfg.yandexKey, "YANDEX_XML_KEY")

	if engine == "google" && (googleKey == "" || googleCX == "") {
		return errors.New("missing Google CSE credentials (set GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX)")
	}
	if engine == "bing" && bingKey == "" {
		return errors.New("missing Bing Search API key (set BING_SEARCH_API_KEY)")
	}
	if engine == "yandex" && (yandexUser == "" || yandexKey == "") {
		return errors.New("missing Yandex XML credentials (set YANDEX_XML_USER and YANDEX_XML_KEY)")
	}

	searchClient := &http.Client{Timeout: cfg.timeout}
	expandClient := &http.Client{
		Timeout: cfg.expandTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	ctx := context.Background()

	queries := shortenerQueries(domain)
	emitted := 0
	rank := 1
	seen := make(map[string]bool)

	for i, q := range queries {
		if emitted >= cfg.maxResults {
			break
		}

		items, err := search(ctx, searchClient, engine, googleKey, googleCX, bingKey, yandexUser, yandexKey, q)
		if err != nil {
			fmt.Fprintf(os.Stderr, "search failed (%s): %v\n", q, err)
			continue
		}

		for _, it := range items {
			if emitted >= cfg.maxResults {
				break
			}
			shortURL := strings.TrimSpace(it.Link)
			if shortURL == "" || seen[shortURL] {
				continue
			}
			seen[shortURL] = true

			finalURL, hops, err := expandShortURL(ctx, expandClient, shortURL, cfg.maxRedirects)
			if err != nil || finalURL == "" {
				continue
			}
			u, err := url.Parse(finalURL)
			if err != nil || u.Hostname() == "" {
				continue
			}

			rec := outputRecord{
				Engine:      engine,
				Query:       q,
				ShortURL:    shortURL,
				FinalURL:    finalURL,
				Host:        strings.ToLower(strings.TrimSpace(u.Hostname())),
				Class:       "shortener-resolved-asset",
				Rank:        rank,
				ChainLength: hops,
			}
			rank++
			emitted++

			if cfg.jsonOutput {
				b, _ := json.Marshal(rec)
				fmt.Println(string(b))
			} else {
				fmt.Println(rec.FinalURL)
			}
		}

		if i < len(queries)-1 {
			time.Sleep(cfg.requestDelay)
		}
	}

	return nil
}

func shortenerQueries(domain string) []string {
	d := strings.TrimSpace(strings.ToLower(domain))
	return []string{
		fmt.Sprintf(`site:bit.ly "%s"`, d),
		fmt.Sprintf(`site:t.co "%s"`, d),
		fmt.Sprintf(`site:tinyurl.com "%s"`, d),
		fmt.Sprintf(`site:rb.gy "%s"`, d),
		fmt.Sprintf(`site:ow.ly "%s"`, d),
		fmt.Sprintf(`site:rebrand.ly "%s"`, d),
	}
}

func search(ctx context.Context, client *http.Client, engine, googleKey, googleCX, bingKey, yandexUser, yandexKey, query string) ([]searchItem, error) {
	switch engine {
	case "google":
		return googleSearch(ctx, client, googleKey, googleCX, query)
	case "bing":
		return bingSearch(ctx, client, bingKey, query)
	case "yandex":
		return yandexSearch(ctx, client, yandexUser, yandexKey, query)
	default:
		return nil, fmt.Errorf("unsupported engine %q", engine)
	}
}

func googleSearch(ctx context.Context, client *http.Client, key, cx, query string) ([]searchItem, error) {
	u, _ := url.Parse("https://www.googleapis.com/customsearch/v1")
	v := u.Query()
	v.Set("key", key)
	v.Set("cx", cx)
	v.Set("q", query)
	v.Set("num", "10")
	u.RawQuery = v.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed googleResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	if parsed.Error != nil && strings.TrimSpace(parsed.Error.Message) != "" {
		return nil, errors.New(parsed.Error.Message)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("google api: %s", resp.Status)
	}
	return parsed.Items, nil
}

func bingSearch(ctx context.Context, client *http.Client, key, query string) ([]searchItem, error) {
	u, _ := url.Parse("https://api.bing.microsoft.com/v7.0/search")
	v := u.Query()
	v.Set("q", query)
	v.Set("count", "10")
	u.RawQuery = v.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Ocp-Apim-Subscription-Key", key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed bingResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	if parsed.Error != nil && strings.TrimSpace(parsed.Error.Message) != "" {
		return nil, errors.New(parsed.Error.Message)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("bing api: %s", resp.Status)
	}

	if parsed.WebPages == nil {
		return nil, nil
	}
	out := make([]searchItem, 0, len(parsed.WebPages.Value))
	for _, v := range parsed.WebPages.Value {
		out = append(out, searchItem{Title: v.Name, Link: v.URL, Snippet: v.Snippet})
	}
	return out, nil
}

func yandexSearch(ctx context.Context, client *http.Client, user, key, query string) ([]searchItem, error) {
	u, _ := url.Parse("https://yandex.com/search/xml")
	v := u.Query()
	v.Set("user", user)
	v.Set("key", key)
	v.Set("query", query)
	v.Set("l10n", "en")
	v.Set("groupby", "attr=d.mode=deep.groups-on-page=10.docs-in-group=1")
	u.RawQuery = v.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("yandex api: %s", resp.Status)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	text := strings.ToLower(string(body))
	out := make([]searchItem, 0)
	for _, line := range strings.Split(text, "<url>") {
		if len(out) >= 10 {
			break
		}
		end := strings.Index(line, "</url>")
		if end <= 0 {
			continue
		}
		link := strings.TrimSpace(line[:end])
		if link == "" {
			continue
		}
		out = append(out, searchItem{Link: link})
	}
	return out, nil
}

func expandShortURL(ctx context.Context, client *http.Client, shortURL string, maxRedirects int) (string, int, error) {
	current := strings.TrimSpace(shortURL)
	if current == "" {
		return "", 0, errors.New("short url empty")
	}

	hops := 0
	for hops < maxRedirects {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, current, nil)
		if err != nil {
			return "", hops, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", hops, err
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			if loc == "" {
				return current, hops, nil
			}
			u, err := url.Parse(current)
			if err != nil {
				return "", hops, err
			}
			nextURL, err := u.Parse(loc)
			if err != nil {
				return "", hops, err
			}
			current = nextURL.String()
			hops++
			continue
		}

		if resp.StatusCode == http.StatusMethodNotAllowed {
			reqGet, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
			if err != nil {
				return "", hops, err
			}
			respGet, err := client.Do(reqGet)
			if err != nil {
				return "", hops, err
			}
			_ = respGet.Body.Close()
			if respGet.Request != nil && respGet.Request.URL != nil {
				return respGet.Request.URL.String(), hops + 1, nil
			}
			return current, hops, nil
		}

		return current, hops, nil
	}

	return current, hops, nil
}

func fallbackEnv(v, envName string) string {
	v = strings.TrimSpace(v)
	if v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(envName))
}
