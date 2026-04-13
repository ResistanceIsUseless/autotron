package parsers

import (
	"fmt"
	"strings"
)

func technologyID(name, version string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	v := strings.ToLower(strings.TrimSpace(version))
	return fmt.Sprintf("%s|%s", n, v)
}

func endpointID(baseURL, method, path string) string {
	u := strings.TrimSpace(baseURL)
	m := strings.ToUpper(strings.TrimSpace(method))
	p := strings.TrimSpace(path)
	if m == "" {
		m = "GET"
	}
	return fmt.Sprintf("%s|%s|%s", u, m, p)
}

func formID(url, action string) string {
	u := strings.TrimSpace(url)
	a := strings.TrimSpace(action)
	return fmt.Sprintf("%s|%s", u, a)
}

func jsFileID(url, sha256 string) string {
	u := strings.TrimSpace(url)
	h := strings.ToLower(strings.TrimSpace(sha256))
	if h == "" {
		h = "unknown"
	}
	return fmt.Sprintf("%s|%s", u, h)
}
