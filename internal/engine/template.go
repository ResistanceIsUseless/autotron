package engine

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// TemplateData is the context passed to text/template for command arg expansion.
// Matches the variables documented in the plan (Section 3.4).
type TemplateData struct {
	Node    map[string]any // Properties on the triggering node
	Edge    map[string]any // Properties on the matched edge (for compound patterns)
	ScanRun ScanRunData    // Current scan run metadata
	Config  map[string]any // Values from asm.yaml global config
}

// ScanRunData holds metadata about the current scan run.
type ScanRunData struct {
	ID string
}

// ExpandArgs applies text/template expansion to each argument string using
// the provided template data. Returns the expanded argument list.
func ExpandArgs(args []string, data TemplateData) ([]string, error) {
	expanded := make([]string, 0, len(args))
	for i, arg := range args {
		result, err := expandSingle(arg, data)
		if err != nil {
			return nil, fmt.Errorf("arg[%d] %q: %w", i, arg, err)
		}
		expanded = append(expanded, result)
	}
	return expanded, nil
}

// ExpandStdin expands a stdin template string. Returns empty string if tmpl is empty.
func ExpandStdin(tmpl string, data TemplateData) (string, error) {
	if tmpl == "" {
		return "", nil
	}
	return expandSingle(tmpl, data)
}

// expandSingle expands a single template string.
func expandSingle(tmplStr string, data TemplateData) (string, error) {
	// Fast path: no template syntax.
	if !strings.Contains(tmplStr, "{{") {
		return tmplStr, nil
	}

	tmpl, err := template.New("arg").Option("missingkey=zero").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute: %w", err)
	}

	return buf.String(), nil
}

// BuildTemplateData constructs template data from a triggering node, optional
// edge properties, scan run ID, and global config values.
func BuildTemplateData(node graph.Node, edgeProps map[string]any, scanRunID string, configVals map[string]any) TemplateData {
	td := TemplateData{
		Node:    make(map[string]any),
		Edge:    make(map[string]any),
		ScanRun: ScanRunData{ID: scanRunID},
		Config:  make(map[string]any),
	}

	// Copy node props.
	for k, v := range node.Props {
		td.Node[k] = v
	}

	// Copy edge props if provided.
	for k, v := range edgeProps {
		td.Edge[k] = v
	}

	// Copy config values.
	for k, v := range configVals {
		td.Config[k] = v
	}

	return td
}

// ValidateTemplates checks that all enricher arg templates (and optional stdin
// template) parse and can execute against a synthetic node. Called at startup
// to catch typos before the first run.
func ValidateTemplates(args []string, stdinTmpl string) error {
	// Build synthetic data with placeholder values to verify templates parse.
	synth := TemplateData{
		Node: map[string]any{
			"fqdn":    "test.example.com",
			"ip":      "127.0.0.1",
			"port":    "443",
			"address": "127.0.0.1",
			"ip_port": "127.0.0.1:443",
			"url":     "https://test.example.com",
			"product": "http",
		},
		Edge: map[string]any{
			"resolved_ip":     "127.0.0.1",
			"port":            "443",
			"scheme":          "https",
			"service_product": "https",
		},
		ScanRun: ScanRunData{ID: "validate-run"},
		Config: map[string]any{
			"resolvers_file": "/tmp/resolvers.txt",
			"output_dir":     "/tmp/output",
		},
	}

	for i, arg := range args {
		if !strings.Contains(arg, "{{") {
			continue
		}
		tmpl, err := template.New("validate").Option("missingkey=error").Parse(arg)
		if err != nil {
			return fmt.Errorf("arg[%d] %q: parse error: %w", i, arg, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, synth); err != nil {
			return fmt.Errorf("arg[%d] %q: execution error: %w", i, arg, err)
		}
	}

	// Validate stdin template if provided.
	if stdinTmpl != "" && strings.Contains(stdinTmpl, "{{") {
		tmpl, err := template.New("validate-stdin").Option("missingkey=error").Parse(stdinTmpl)
		if err != nil {
			return fmt.Errorf("stdin %q: parse error: %w", stdinTmpl, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, synth); err != nil {
			return fmt.Errorf("stdin %q: execution error: %w", stdinTmpl, err)
		}
	}

	return nil
}
