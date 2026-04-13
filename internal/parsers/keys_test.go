package parsers

import "testing"

func TestTechnologyID_NormalizesCaseAndWhitespace(t *testing.T) {
	got := technologyID("  Nginx  ", "  1.25.4 ")
	want := "nginx|1.25.4"
	if got != want {
		t.Fatalf("technologyID mismatch: got %q want %q", got, want)
	}
}

func TestEndpointID_DefaultsMethod(t *testing.T) {
	got := endpointID("https://example.com", "", "/api")
	want := "https://example.com|GET|/api"
	if got != want {
		t.Fatalf("endpointID mismatch: got %q want %q", got, want)
	}
}

func TestFormID_Stable(t *testing.T) {
	got := formID("https://example.com", "/submit")
	want := "https://example.com|/submit"
	if got != want {
		t.Fatalf("formID mismatch: got %q want %q", got, want)
	}
}

func TestJSFileID_DefaultUnknownHash(t *testing.T) {
	got := jsFileID("https://example.com/app.js", "")
	want := "https://example.com/app.js|unknown"
	if got != want {
		t.Fatalf("jsFileID mismatch: got %q want %q", got, want)
	}
}
