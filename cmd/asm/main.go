// ASM Pipeline CLI entrypoint.
//
// Install: go install ./cmd/asm
// Usage:   asm scan -d example.com
//
//	asm validate
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/resistanceisuseless/autotron/internal/engine"
	"github.com/resistanceisuseless/autotron/internal/graph"
	"github.com/resistanceisuseless/autotron/internal/parsers"
	"github.com/resistanceisuseless/autotron/internal/webui"

	// Register all parsers via init().
	_ "github.com/resistanceisuseless/autotron/internal/parsers/register"
)

var (
	cfgFile       string
	enrichersFile string
	logLevel      string
	strictTools   bool
	version       = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "asm",
		Short: "Attack Surface Monitoring pipeline",
		Long:  "Data-type-driven enrichment engine backed by Neo4j.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			printSplash()
		},
	}

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "configs/asm.yaml", "path to global config")
	rootCmd.PersistentFlags().StringVarP(&enrichersFile, "enrichers", "e", "configs/enrichers.yaml", "path to enrichers config")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")

	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(reportCmd())
	rootCmd.AddCommand(profileCmd())
	rootCmd.AddCommand(webUICmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func printSplash() {
	fmt.Fprintf(os.Stderr, "Autotron ASM\\n")
	fmt.Fprintf(os.Stderr, "Version: %s\\n", version)
}

func webUICmd() *cobra.Command {
	var addr string
	var jsreconBase string

	cmd := &cobra.Command{
		Use:   "webui",
		Short: "Run a lightweight ASM web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := setupLogger()

			cfg, err := config.LoadConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			graphClient, err := graph.NewClient(ctx, cfg.Neo4j.URI, cfg.Neo4j.Username, cfg.Neo4j.Password, logger)
			if err != nil {
				return fmt.Errorf("graph client: %w", err)
			}
			defer graphClient.Close(ctx)

			if strings.TrimSpace(jsreconBase) == "" {
				jsreconBase = cfg.Scan.JSReconBase
			}

			// Load enricher names for progress tracking.
			var enricherNames []string
			if enrichersCfg, err := config.LoadEnrichers(enrichersFile); err == nil {
				for _, e := range enrichersCfg.EnabledEnrichers() {
					enricherNames = append(enricherNames, e.Name)
				}
			}

			srv := webui.NewServer(graphClient, logger, jsreconBase, enricherNames...)
			httpServer := &http.Server{
				Addr:    addr,
				Handler: srv.Routes(),
			}

			logger.Info("web ui listening", "addr", addr, "jsrecon_base", jsreconBase)

			errCh := make(chan error, 1)
			go func() {
				errCh <- httpServer.ListenAndServe()
			}()

			select {
			case <-ctx.Done():
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutdownCancel()
				_ = httpServer.Shutdown(shutdownCtx)
				return nil
			case err := <-errCh:
				if err != nil && err != http.ErrServerClosed {
					return err
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8090", "listen address")
	cmd.Flags().StringVar(&jsreconBase, "jsrecon", "", "jsRecon base URL (defaults to scan.jsrecon_base from config)")
	return cmd
}

func reportCmd() *cobra.Command {
	var top int
	var host string
	var out string
	var strict bool
	var severity string
	var confidence string
	var tool string
	var since string
	var asJSON bool
	var format string
	var save bool

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Show top findings or generate host report",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := setupLogger()

			normalizedFormat, err := normalizeReportFormat(format, asJSON)
			if err != nil {
				return err
			}

			cfg, err := config.LoadConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			ctx := context.Background()
			graphClient, err := graph.NewClient(ctx, cfg.Neo4j.URI, cfg.Neo4j.Username, cfg.Neo4j.Password, logger)
			if err != nil {
				return fmt.Errorf("graph client: %w", err)
			}
			defer graphClient.Close(ctx)

			if strings.TrimSpace(host) != "" {
				hostReport, err := graphClient.BuildHostReportWithOptions(ctx, host, graph.HostReportOptions{RequireData: strict})
				if err != nil {
					return fmt.Errorf("build host report: %w", err)
				}

				if save && strings.TrimSpace(out) == "" {
					out = defaultHostReportPath(hostReport.Host, normalizedFormat)
				}

				if normalizedFormat == "json" {
					payload, err := json.MarshalIndent(hostReport, "", "  ")
					if err != nil {
						return fmt.Errorf("marshal host report json: %w", err)
					}
					return writeReportOutput(out, string(payload)+"\n")
				}

				md := graph.RenderHostReportMarkdown(hostReport)
				return writeReportOutput(out, md+"\n")
			}

			findings, err := graphClient.TopFindingsWithOptions(ctx, graph.TopFindingsOptions{
				Limit:      top,
				Severity:   severity,
				Confidence: confidence,
				Tool:       tool,
				Since:      since,
			})
			if err != nil {
				return fmt.Errorf("query report: %w", err)
			}

			if len(findings) == 0 {
				if save && strings.TrimSpace(out) == "" {
					out = defaultTopFindingsPath(normalizedFormat)
				}

				if normalizedFormat == "json" {
					payload, err := json.MarshalIndent(map[string]any{
						"generated_at": time.Now().UTC().Format(time.RFC3339),
						"filters": map[string]any{
							"top":        top,
							"severity":   severity,
							"confidence": confidence,
							"tool":       tool,
							"since":      since,
						},
						"findings": []graph.FindingSummary{},
					}, "", "  ")
					if err != nil {
						return fmt.Errorf("marshal findings json: %w", err)
					}
					return writeReportOutput(out, string(payload)+"\n")
				}
				return writeReportOutput(out, "No findings available.\n")
			}

			if save && strings.TrimSpace(out) == "" {
				out = defaultTopFindingsPath(normalizedFormat)
			}

			if normalizedFormat == "json" {
				payload, err := json.MarshalIndent(map[string]any{
					"generated_at": time.Now().UTC().Format(time.RFC3339),
					"filters": map[string]any{
						"top":        top,
						"severity":   severity,
						"confidence": confidence,
						"tool":       tool,
						"since":      since,
					},
					"findings": findings,
				}, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal findings json: %w", err)
				}
				return writeReportOutput(out, string(payload)+"\n")
			}

			return writeReportOutput(out, renderTopFindingsText(findings))
		},
	}

	cmd.Flags().IntVar(&top, "top", 25, "number of top findings to show")
	cmd.Flags().StringVar(&host, "host", "", "host fqdn to generate markdown report for")
	cmd.Flags().StringVar(&out, "out", "", "output markdown file path for host report (default: stdout)")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail host report generation when host has no reportable data")
	cmd.Flags().StringVar(&severity, "severity", "", "filter top findings by severity (info|low|medium|high|critical)")
	cmd.Flags().StringVar(&confidence, "confidence", "", "filter top findings by confidence (tentative|firm|confirmed)")
	cmd.Flags().StringVar(&tool, "tool", "", "filter top findings by tool name")
	cmd.Flags().StringVar(&since, "since", "", "include findings last_seen >= value (RFC3339-like lexical match)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output report as JSON")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text|json|markdown")
	cmd.Flags().BoolVar(&save, "save", false, "write report to default path when --out is omitted")
	_ = cmd.Flags().MarkDeprecated("json", "use --format json instead")
	return cmd
}

func writeReportOutput(outPath, payload string) error {
	if strings.TrimSpace(outPath) == "" {
		fmt.Print(payload)
		return nil
	}

	resolved := outPath
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Clean(resolved)
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	if err := os.WriteFile(resolved, []byte(payload), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("wrote report: %s\n", resolved)
	return nil
}

func normalizeReportFormat(format string, jsonFlag bool) (string, error) {
	if jsonFlag {
		return "json", nil
	}
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" {
		f = "text"
	}
	switch f {
	case "text", "json", "markdown":
		return f, nil
	default:
		return "", fmt.Errorf("invalid --format %q (expected text|json|markdown)", format)
	}
}

func defaultHostReportPath(host, format string) string {
	ext := "md"
	if format == "json" {
		ext = "json"
	}
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	host = strings.ReplaceAll(host, "/", "-")
	host = strings.ReplaceAll(host, "\\", "-")
	return filepath.Join("reports", host+"."+ext)
}

func defaultTopFindingsPath(format string) string {
	ext := "txt"
	if format == "json" {
		ext = "json"
	}
	ts := time.Now().UTC().Format("20060102-150405")
	return filepath.Join("reports", "top-findings-"+ts+"."+ext)
}

func renderTopFindingsText(findings []graph.FindingSummary) string {
	b := &strings.Builder{}
	for i, f := range findings {
		fmt.Fprintf(b, "%d. [%s/%s] %s\n", i+1, strings.ToUpper(f.Severity), f.Confidence, f.Title)
		fmt.Fprintf(b, "   id=%s assets=%d tools=%s\n", f.ID, f.AssetCount, strings.Join(f.Tools, ","))
		if f.CanonicalKey != "" {
			fmt.Fprintf(b, "   key=%s\n", f.CanonicalKey)
		}
	}
	return b.String()
}

func setupLogger() *slog.Logger {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}

func scanCmd() *cobra.Command {
	var domains []string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run the enrichment pipeline against target domains",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(domains) == 0 {
				return fmt.Errorf("at least one domain required (-d)")
			}

			logger := setupLogger()

			// Load configs.
			cfg, err := config.LoadConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			scopeValidator := engine.NewScopeValidator(cfg)
			var inScopeDomains []string
			for _, domain := range domains {
				node := graph.Node{
					Type:       graph.NodeDomain,
					PrimaryKey: strings.TrimSpace(domain),
					Props: map[string]any{
						"fqdn": strings.TrimSpace(domain),
					},
				}
				if scopeValidator.IsInScope(node) {
					inScopeDomains = append(inScopeDomains, domain)
				}
			}

			if len(inScopeDomains) == 0 {
				logger.Warn("all seed domains are out of configured scope; no enrichers may dispatch",
					"domains", domains,
					"configured_scope_domains", cfg.Scope.Domains,
				)
			} else if len(inScopeDomains) < len(domains) {
				logger.Warn("some seed domains are out of configured scope",
					"domains", domains,
					"in_scope_domains", inScopeDomains,
					"configured_scope_domains", cfg.Scope.Domains,
				)
			}

			enrichersCfg, err := config.LoadEnrichers(enrichersFile)
			if err != nil {
				return fmt.Errorf("load enrichers: %w", err)
			}

			enabled := enrichersCfg.EnabledEnrichers()
			logger.Info("loaded enrichers",
				"total", len(enrichersCfg.Enrichers),
				"enabled", len(enabled),
			)

			// Connect to Neo4j.
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			graphClient, err := graph.NewClient(ctx, cfg.Neo4j.URI, cfg.Neo4j.Username, cfg.Neo4j.Password, logger)
			if err != nil {
				return fmt.Errorf("graph client: %w", err)
			}
			defer graphClient.Close(ctx)

			// Initialize schema.
			if err := graphClient.InitSchema(ctx); err != nil {
				return fmt.Errorf("init schema: %w", err)
			}

			// Run the engine.
			eng := engine.NewEngine(graphClient, cfg, enabled, logger)
			return eng.Run(ctx, domains)
		},
	}

	cmd.Flags().StringSliceVarP(&domains, "domain", "d", nil, "target domain(s) to scan")
	cmd.MarkFlagRequired("domain")

	return cmd
}

func validateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration files and parser registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := setupLogger()

			// Load and validate config.
			cfg, err := config.LoadConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			logger.Info("config OK",
				"neo4j_uri", cfg.Neo4j.URI,
				"scope_domains", len(cfg.Scope.Domains),
				"scope_cidrs", len(cfg.Scope.CIDRs),
			)

			// Load and validate enrichers.
			enrichersCfg, err := config.LoadEnrichers(enrichersFile)
			if err != nil {
				return fmt.Errorf("enrichers: %w", err)
			}

			// Check parser registry.
			registered := parsers.Names()
			logger.Info("parser registry", "count", len(registered), "names", registered)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			graphClient, err := graph.NewClient(ctx, cfg.Neo4j.URI, cfg.Neo4j.Username, cfg.Neo4j.Password, logger)
			if err != nil {
				return fmt.Errorf("predicate validation requires neo4j connectivity: %w", err)
			}
			defer graphClient.Close(ctx)

			var errs int
			for _, e := range enrichersCfg.Enrichers {
				// Verify parser exists.
				if _, err := parsers.Get(e.Parser); err != nil {
					logger.Error("missing parser", "enricher", e.Name, "parser", e.Parser)
					errs++
				}

				// Validate templates.
				if err := engine.ValidateTemplates(e.Command.Args, e.Command.Stdin); err != nil {
					logger.Error("bad template", "enricher", e.Name, "error", err)
					errs++
				}

				if err := graphClient.ValidatePendingQuery(
					ctx,
					e.Subscribes.NodeType,
					e.Subscribes.Predicate,
					e.Subscribes.Match,
					e.Subscribes.Returns,
				); err != nil {
					logger.Error("invalid subscription query", "enricher", e.Name, "error", err)
					errs++
				}

				if strictTools && e.Enabled {
					if _, err := exec.LookPath(e.Command.Bin); err != nil {
						logger.Error("missing tool binary", "enricher", e.Name, "bin", e.Command.Bin, "error", err)
						errs++
					}
				}
			}

			enabled := enrichersCfg.EnabledEnrichers()
			logger.Info("enrichers OK",
				"total", len(enrichersCfg.Enrichers),
				"enabled", len(enabled),
				"errors", errs,
			)

			if errs > 0 {
				return fmt.Errorf("%d validation errors", errs)
			}

			fmt.Println("All configuration valid.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&strictTools, "strict-tools", false, "fail validation if enabled enricher binaries are missing")
	return cmd
}
