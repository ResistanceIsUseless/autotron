package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

type Server struct {
	graphClient   *graph.Client
	logger        *slog.Logger
	jsreconBase   string
	client        *http.Client
	enricherNames []string
}

func NewServer(graphClient *graph.Client, logger *slog.Logger, jsreconBase string, enricherNames ...string) *Server {
	if strings.TrimSpace(jsreconBase) == "" {
		jsreconBase = "http://localhost:37232"
	}
	return &Server{
		graphClient:   graphClient,
		logger:        logger.With("component", "webui"),
		jsreconBase:   strings.TrimRight(jsreconBase, "/"),
		client:        &http.Client{Timeout: 30 * time.Second},
		enricherNames: enricherNames,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/jsfiles", s.handleJSFiles)
	mux.HandleFunc("/api/scan-runs", s.handleScanRuns)
	mux.HandleFunc("/api/data/urls", s.handleURLs)
	mux.HandleFunc("/api/data/services", s.handleServices)
	mux.HandleFunc("/api/top-findings", s.handleTopFindings)
	mux.HandleFunc("/api/enricher-progress", s.handleEnricherProgress)
	mux.HandleFunc("/api/activity", s.handleActivity)
	mux.HandleFunc("/api/jsrecon/monitor", s.handleMonitorAdd)
	mux.HandleFunc("/api/jsrecon/monitor/check", s.handleMonitorCheck)
	mux.HandleFunc("/api/jsrecon/monitor/list", s.handleMonitorList)
	mux.HandleFunc("/api/jsrecon/monitor/changes", s.handleMonitorChanges)
	mux.HandleFunc("/api/jsrecon/analyze", s.handleAnalyzeNow)
	mux.HandleFunc("/api/jsrecon/health", s.handleJSReconHealth)
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	counts, err := s.graphClient.NodeCounts(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_counts": counts})
}

func (s *Server) handleJSFiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := parseInt(raw); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	files, err := s.graphClient.ListJSFiles(ctx, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": files, "count": len(files)})
}

func (s *Server) handleTopFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	findings, err := s.graphClient.TopFindingsWithOptions(ctx, graph.TopFindingsOptions{Limit: 25})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings, "count": len(findings)})
}

func (s *Server) handleScanRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := parseInt(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	items, err := s.graphClient.ListScanRuns(ctx, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleURLs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := parseInt(raw); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	items, err := s.graphClient.ListURLs(ctx, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := parseInt(raw); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	items, err := s.graphClient.ListServices(ctx, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

type monitorRequest struct {
	URL                 string `json:"url"`
	Label               string `json:"label"`
	CheckIntervalMinute int    `json:"check_interval_minutes"`
}

func (s *Server) handleMonitorAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var req monitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json body"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "url is required"})
		return
	}
	if _, err := url.ParseRequestURI(req.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid url"})
		return
	}
	if req.CheckIntervalMinute <= 0 {
		req.CheckIntervalMinute = 60
	}

	payload, _ := json.Marshal(map[string]any{
		"url":                    req.URL,
		"label":                  req.Label,
		"check_interval_minutes": req.CheckIntervalMinute,
	})

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.jsreconBase+"/api/monitor", bytes.NewReader(payload))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("jsrecon unavailable: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": string(body)})
		return
	}

	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		out = map[string]any{"raw": string(body)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "jsrecon": out})
}

func (s *Server) handleJSReconHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.jsreconBase+"/api/health", nil)
	resp, err := s.client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out any
	_ = json.Unmarshal(body, &out)
	writeJSON(w, http.StatusOK, map[string]any{"ok": resp.StatusCode < 400, "status": resp.StatusCode, "detail": out})
}

func (s *Server) handleMonitorList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	url := s.jsreconBase + "/api/monitor"
	if q := r.URL.RawQuery; strings.TrimSpace(q) != "" {
		url += "?" + q
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": string(body)})
		return
	}
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		out = map[string]any{"raw": string(body)}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMonitorChanges(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	url := s.jsreconBase + "/api/monitor/changes"
	if q := r.URL.RawQuery; strings.TrimSpace(q) != "" {
		url += "?" + q
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": string(body)})
		return
	}
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		out = map[string]any{"raw": string(body)}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMonitorCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json body"})
		return
	}
	if req.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id must be > 0"})
		return
	}

	upstreamURL := fmt.Sprintf("%s/api/monitor/%d/check", s.jsreconBase, req.ID)
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("jsrecon unavailable: %v", err)})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": string(body)})
		return
	}

	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		out = map[string]any{"raw": string(body)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "jsrecon": out})
}

func (s *Server) handleAnalyzeNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json body"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "url is required"})
		return
	}
	if _, err := url.ParseRequestURI(req.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid url"})
		return
	}

	payload, _ := json.Marshal(map[string]any{"url": req.URL})
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.jsreconBase+"/api/sources", bytes.NewReader(payload))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("jsrecon unavailable: %v", err)})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": string(body)})
		return
	}

	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		out = map[string]any{"raw": string(body)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "jsrecon": out})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func (s *Server) handleEnricherProgress(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	items, err := s.graphClient.ListEnricherProgress(ctx, s.enricherNames)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := parseInt(raw); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	items, err := s.graphClient.ListRecentActivity(ctx, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}
