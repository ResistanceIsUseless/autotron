package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/resistanceisuseless/autotron/internal/config"
	"github.com/spf13/cobra"
)

var profileGroups = map[string][]string{
	"passive-plus": {
		"google_dork_passive", "bing_dork_passive", "yandex_dork_passive",
		"url_shortener_search_passive",
		"shodan_host_passive", "censys_host_passive", "fofa_host_passive",
		"github_code_search_passive", "gitlab_code_search_passive",
		"s3_bucket_enum", "gcs_bucket_enum", "azure_blob_enum",
		"mx_posture_audit", "spf_dkim_dmarc_audit",
	},
	"auth-api": {
		"openapi_discovery", "graphql_surface", "api_authz_heuristics",
		"oidc_discovery", "oauth_misconfig_probe", "saml_metadata_enum",
	},
	"advanced-web": {
		"http_desync_probe", "cache_poison_probe", "waf_diff_probe",
		"ssrf_gadget_discovery", "idor_candidate_mapper", "csrf_policy_audit",
	},
}

func profileCmd() *cobra.Command {
	var name string
	var apply bool
	var list bool
	var disable bool

	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Preview or apply enricher profile changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if list || strings.TrimSpace(name) == "" {
				fmt.Println("Available profiles:")
				names := make([]string, 0, len(profileGroups))
				for n := range profileGroups {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					fmt.Printf("- %s (%d enrichers)\n", n, len(profileGroups[n]))
				}
				fmt.Println("\nUse: asm profile --name <profile> [--apply] [--disable]")
				return nil
			}

			groupName := strings.ToLower(strings.TrimSpace(name))
			target, ok := profileGroups[groupName]
			if !ok {
				return fmt.Errorf("unknown profile %q", name)
			}

			enrichersCfg, err := config.LoadEnrichers(enrichersFile)
			if err != nil {
				return fmt.Errorf("load enrichers: %w", err)
			}

			enabledByName := make(map[string]bool, len(enrichersCfg.Enrichers))
			for _, e := range enrichersCfg.Enrichers {
				enabledByName[e.Name] = e.Enabled
			}

			fmt.Printf("Profile: %s\n", groupName)
			missing := make([]string, 0)
			toChange := make([]string, 0)
			alreadyDesired := make([]string, 0)
			for _, n := range target {
				curr, ok := enabledByName[n]
				if !ok {
					missing = append(missing, n)
					continue
				}
				if curr == !disable {
					alreadyDesired = append(alreadyDesired, n)
				} else {
					toChange = append(toChange, n)
				}
			}

			action := "enable"
			alreadyLabel := "Already enabled:"
			if disable {
				action = "disable"
				alreadyLabel = "Already disabled:"
			}

			if len(toChange) > 0 {
				fmt.Printf("Will %s:\n", action)
				for _, n := range toChange {
					fmt.Printf("  - %s\n", n)
				}
			}
			if len(alreadyDesired) > 0 {
				fmt.Println(alreadyLabel)
				for _, n := range alreadyDesired {
					fmt.Printf("  - %s\n", n)
				}
			}
			if len(missing) > 0 {
				fmt.Println("Not found in enrichers config:")
				for _, n := range missing {
					fmt.Printf("  - %s\n", n)
				}
			}

			if !apply {
				fmt.Println("\nDry run only. Re-run with --apply to update the config.")
				return nil
			}

			raw, err := os.ReadFile(enrichersFile)
			if err != nil {
				return fmt.Errorf("read enrichers file: %w", err)
			}

			updated, changed, err := setEnrichersEnabledInYAML(string(raw), toChange, !disable)
			if err != nil {
				return err
			}
			if changed == 0 {
				fmt.Println("No changes applied.")
				return nil
			}

			if err := os.WriteFile(enrichersFile, []byte(updated), 0o644); err != nil {
				return fmt.Errorf("write enrichers file: %w", err)
			}
			fmt.Printf("Applied profile %s: %s %d enricher(s).\n", groupName, action+"d", changed)
			fmt.Println("Next: go run ./cmd/asm validate")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "profile name (passive-plus|auth-api|advanced-web)")
	cmd.Flags().BoolVar(&apply, "apply", false, "apply changes to enrichers config")
	cmd.Flags().BoolVar(&disable, "disable", false, "disable profile enrichers instead of enabling")
	cmd.Flags().BoolVar(&list, "list", false, "list available profiles")
	return cmd
}

func enableEnrichersInYAML(raw string, names []string) (string, int, error) {
	return setEnrichersEnabledInYAML(raw, names, true)
}

func setEnrichersEnabledInYAML(raw string, names []string, enabled bool) (string, int, error) {
	if len(names) == 0 {
		return raw, 0, nil
	}

	target := make(map[string]bool, len(names))
	for _, n := range names {
		target[strings.TrimSpace(n)] = true
	}

	nameRE := regexp.MustCompile(`^\s*-\s*name:\s*([^\s#]+)\s*$`)
	enabledRE := regexp.MustCompile(`^(\s*enabled:\s*)(true|false)(.*)$`)

	lines := strings.Split(raw, "\n")
	current := ""
	changed := 0

	for i, line := range lines {
		if m := nameRE.FindStringSubmatch(strings.TrimSpace(line)); len(m) == 2 {
			current = strings.Trim(strings.TrimSpace(m[1]), `"'`)
			continue
		}
		if current == "" || !target[current] {
			continue
		}
		m := enabledRE.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}
		targetEnabled := "false"
		if enabled {
			targetEnabled = "true"
		}
		if m[2] == targetEnabled {
			current = ""
			continue
		}
		lines[i] = m[1] + targetEnabled + m[3]
		changed++
		current = ""
	}

	return strings.Join(lines, "\n"), changed, nil
}
