package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// smbEnumParser handles SMB enumeration tools: enum4linux-ng, netexec.
//
// Formats handled:
//   - enum4linux-ng JSON (-oJ -): structured object with os_info, shares, users, groups
//   - netexec structured output: parsed for share names, users, auth status
//
// Emits: Subdomain leaks (from OS info/domain), Finding nodes for exposed shares,
// users, and policy issues.
type smbEnumParser struct{}

func init() {
	Register(&smbEnumParser{})
}

func (p *smbEnumParser) Name() string { return "smb_enum" }

// enum4linuxOutput represents enum4linux-ng's JSON output.
type enum4linuxOutput struct {
	Target          string                `json:"target"`
	OSInfo          enum4linuxOS          `json:"os_info"`
	Shares          []enum4linuxShare     `json:"shares"`
	Users           []enum4linuxUser      `json:"users"`
	Groups          []enum4linuxGroup     `json:"groups"`
	Domain          string                `json:"domain"`
	FQDN            string                `json:"fqdn"`
	Workgroup       string                `json:"workgroup"`
	PasswordPolicy  *enum4linuxPassPolicy `json:"password_policy"`
	SMBVersions     []string              `json:"smb_dialects"`
	SigningRequired bool                  `json:"signing_required"`
	NullSession     bool                  `json:"null_session"`
	GuestAccount    bool                  `json:"guest_account"`
}

type enum4linuxOS struct {
	OS     string `json:"os"`
	Build  string `json:"build"`
	Kernel string `json:"kernel"`
}

type enum4linuxShare struct {
	Name        string `json:"name"`
	Comment     string `json:"comment"`
	Type        string `json:"type"`
	ReadAccess  bool   `json:"read_access"`
	WriteAccess bool   `json:"write_access"`
}

type enum4linuxUser struct {
	Username string `json:"username"`
	RID      string `json:"rid"`
	FullName string `json:"full_name"`
}

type enum4linuxGroup struct {
	Name    string   `json:"name"`
	RID     string   `json:"rid"`
	Members []string `json:"members"`
}

type enum4linuxPassPolicy struct {
	MinLength        int  `json:"min_length"`
	Complexity       bool `json:"complexity"`
	LockoutThreshold int  `json:"lockout_threshold"`
}

func (p *smbEnumParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	data, err := io.ReadAll(stdout)
	if err != nil {
		return Result{}, fmt.Errorf("read smb enum output: %w", err)
	}

	if len(data) == 0 {
		return Result{}, nil
	}

	var result Result
	now := time.Now().UTC()
	trimmed := strings.TrimSpace(string(data))

	// Try enum4linux-ng JSON format.
	if strings.HasPrefix(trimmed, "{") {
		var output enum4linuxOutput
		if err := json.Unmarshal(data, &output); err != nil {
			return result, fmt.Errorf("decode enum4linux JSON: %w", err)
		}
		p.processEnum4linux(&result, output, trigger, now)
		return result, nil
	}

	// Fallback: netexec text output parsing.
	p.parseNetexecText(trimmed, trigger, &result, now)
	return result, nil
}

func (p *smbEnumParser) processEnum4linux(result *Result, output enum4linuxOutput, trigger graph.Node, now time.Time) {
	// Domain/FQDN -> Subdomain leak.
	if output.FQDN != "" {
		fqdn := strings.ToLower(strings.TrimSuffix(output.FQDN, "."))
		result.Nodes = append(result.Nodes, graph.Node{
			Type:       graph.NodeSubdomain,
			PrimaryKey: fqdn,
			Props: map[string]any{
				"fqdn":   fqdn,
				"status": "discovered",
				"source": "smb-enum",
			},
		})
	}

	// Null session access -> high severity finding.
	if output.NullSession {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("smb-null-session-%s", hashKey(trigger.PrimaryKey)),
			Type:       "smb-null-session",
			Title:      "SMB null session access permitted",
			Severity:   "high",
			Confidence: "confirmed",
			Tool:       "enum4linux-ng",
			Evidence: map[string]any{
				"target": output.Target,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// Guest account access.
	if output.GuestAccount {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("smb-guest-access-%s", hashKey(trigger.PrimaryKey)),
			Type:       "smb-guest-access",
			Title:      "SMB guest account access permitted",
			Severity:   "medium",
			Confidence: "confirmed",
			Tool:       "enum4linux-ng",
			Evidence: map[string]any{
				"target": output.Target,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// SMB signing not required.
	if !output.SigningRequired {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("smb-signing-disabled-%s", hashKey(trigger.PrimaryKey)),
			Type:       "smb-signing-not-required",
			Title:      "SMB signing not required",
			Severity:   "medium",
			Confidence: "confirmed",
			Tool:       "enum4linux-ng",
			Evidence: map[string]any{
				"target":       output.Target,
				"smb_versions": output.SMBVersions,
			},
			FirstSeen: now, LastSeen: now,
		})
	}

	// Exposed shares.
	for i, share := range output.Shares {
		if share.Name == "" {
			continue
		}
		severity := "info"
		if share.ReadAccess {
			severity = "medium"
		}
		if share.WriteAccess {
			severity = "high"
		}

		evidence := map[string]any{
			"share_name":   share.Name,
			"share_type":   share.Type,
			"comment":      share.Comment,
			"read_access":  share.ReadAccess,
			"write_access": share.WriteAccess,
		}

		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("smb-share-%s-%s-%d", share.Name, hashKey(trigger.PrimaryKey), i),
			Type:       "smb-exposed-share",
			Title:      fmt.Sprintf("SMB share exposed: %s", share.Name),
			Severity:   severity,
			Confidence: "confirmed",
			Tool:       "enum4linux-ng",
			Evidence:   evidence,
			FirstSeen:  now, LastSeen: now,
		})
	}

	// Enumerated users.
	if len(output.Users) > 0 {
		usernames := make([]string, 0, len(output.Users))
		for _, u := range output.Users {
			if u.Username != "" {
				usernames = append(usernames, u.Username)
			}
		}
		if len(usernames) > 0 {
			result.Findings = append(result.Findings, graph.Finding{
				ID:         fmt.Sprintf("smb-users-enum-%s", hashKey(trigger.PrimaryKey)),
				Type:       "smb-user-enumeration",
				Title:      fmt.Sprintf("SMB user enumeration: %d users found", len(usernames)),
				Severity:   "low",
				Confidence: "confirmed",
				Tool:       "enum4linux-ng",
				Evidence: map[string]any{
					"user_count": len(usernames),
					"users":      usernames,
				},
				FirstSeen: now, LastSeen: now,
			})
		}
	}

	// Weak password policy.
	if output.PasswordPolicy != nil {
		pp := output.PasswordPolicy
		if pp.MinLength < 8 || !pp.Complexity || pp.LockoutThreshold == 0 {
			evidence := map[string]any{
				"min_length":        pp.MinLength,
				"complexity":        pp.Complexity,
				"lockout_threshold": pp.LockoutThreshold,
			}
			result.Findings = append(result.Findings, graph.Finding{
				ID:         fmt.Sprintf("smb-weak-policy-%s", hashKey(trigger.PrimaryKey)),
				Type:       "smb-weak-password-policy",
				Title:      "Weak SMB password policy",
				Severity:   "medium",
				Confidence: "confirmed",
				Tool:       "enum4linux-ng",
				Evidence:   evidence,
				FirstSeen:  now, LastSeen: now,
			})
		}
	}

	// OS info as finding (informational).
	if output.OSInfo.OS != "" {
		result.Findings = append(result.Findings, graph.Finding{
			ID:         fmt.Sprintf("smb-os-info-%s", hashKey(trigger.PrimaryKey)),
			Type:       "smb-os-info",
			Title:      fmt.Sprintf("SMB OS: %s", output.OSInfo.OS),
			Severity:   "info",
			Confidence: "confirmed",
			Tool:       "enum4linux-ng",
			Evidence: map[string]any{
				"os":     output.OSInfo.OS,
				"build":  output.OSInfo.Build,
				"kernel": output.OSInfo.Kernel,
				"domain": output.Domain,
			},
			FirstSeen: now, LastSeen: now,
		})
	}
}

func (p *smbEnumParser) parseNetexecText(data string, trigger graph.Node, result *Result, now time.Time) {
	// netexec output is columnar text:
	// SMB  10.0.0.1  445  HOST  [*] Windows 10 Build 19041 x64
	// SMB  10.0.0.1  445  HOST  [+] Share: ADMIN$  (READ)
	// We parse for key indicators.

	lines := strings.Split(data, "\n")
	shareIdx := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)

		// Signing not required.
		if strings.Contains(lower, "signing") && strings.Contains(lower, "not required") {
			result.Findings = append(result.Findings, graph.Finding{
				ID:         fmt.Sprintf("netexec-signing-%s", hashKey(trigger.PrimaryKey)),
				Type:       "smb-signing-not-required",
				Title:      "SMB signing not required",
				Severity:   "medium",
				Confidence: "confirmed",
				Tool:       "netexec",
				Evidence:   map[string]any{"raw": line},
				FirstSeen:  now, LastSeen: now,
			})
		}

		// Share enumeration.
		if strings.Contains(lower, "share:") || (strings.Contains(lower, "[+]") && strings.Contains(lower, "read")) {
			result.Findings = append(result.Findings, graph.Finding{
				ID:         fmt.Sprintf("netexec-share-%s-%d", hashKey(trigger.PrimaryKey), shareIdx),
				Type:       "smb-exposed-share",
				Title:      fmt.Sprintf("SMB share found: %s", line),
				Severity:   "info",
				Confidence: "tentative",
				Tool:       "netexec",
				Evidence:   map[string]any{"raw": line},
				FirstSeen:  now, LastSeen: now,
			})
			shareIdx++
		}
	}
}
