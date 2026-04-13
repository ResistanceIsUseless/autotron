package main

import "testing"

func TestBucketCandidates(t *testing.T) {
	cs := bucketCandidates("app.example.com", 8)
	if len(cs) == 0 {
		t.Fatal("expected non-empty candidates")
	}
}

func TestSanitizeBucketName(t *testing.T) {
	if got := sanitizeBucketName("App_Example.Com"); got != "app-example.com" {
		t.Fatalf("unexpected sanitized value: %s", got)
	}
}

func TestExtractXMLTagValues(t *testing.T) {
	xml := "<ListBucketResult><Contents><Key>a.txt</Key></Contents><Contents><Key>b.txt</Key></Contents></ListBucketResult>"
	vals := extractXMLTagValues(xml, "Key")
	if len(vals) != 2 || vals[0] != "a.txt" || vals[1] != "b.txt" {
		t.Fatalf("unexpected extracted values: %#v", vals)
	}
}
