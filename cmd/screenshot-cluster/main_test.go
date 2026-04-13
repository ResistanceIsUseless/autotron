package main

import "testing"

func TestClassifyScreenshot(t *testing.T) {
	label, typ, sev := classifyScreenshot("login-page.png", []byte("dummy"))
	if label != "login" || typ != "exposed-login-panel" || sev != "medium" {
		t.Fatalf("unexpected login classification: %s %s %s", label, typ, sev)
	}

	label, typ, sev = classifyScreenshot("home.png", []byte("grafana"))
	if label != "known-product" || typ != "known-product-panel" {
		t.Fatalf("unexpected known-product classification: %s %s %s", label, typ, sev)
	}
}
