package resource

import (
	"strings"
	"testing"
)

// FuzzNormalize は、受理した resource indicator の正規形が fragment を持たず、scheme が小文字で、
// もう一度正規化しても変わらないことを確かめる（RFC 8707 §2、RFC 3986 §6.2.2.1）。
//
// 正規化が冪等でないと、設定した URI（NewSet で正規化）とクライアントが提示した正規形
// （Protected Resource Metadata の resource をそのまま送る場合など）が一致しなくなる。
func FuzzNormalize(f *testing.F) {
	for _, seed := range []string{
		"https://mcp.example.com", "https://MCP.Example.com/Path/", "https://mcp.example.com/?q=1",
		"https://mcp.example.com#", "urn:example:resource", "HTTPS://[::1]:8443/mcp", "https://user@mcp.example.com/",
		"https://mcp.example.com/%7Euser", "https:///path", "mailto:a@example.com", "https://xn--r8jz45g.example/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := Normalize(raw)
		if err != nil {
			return
		}
		if strings.Contains(got, "#") {
			t.Fatalf("Normalize(%q) = %q contains a fragment", raw, got)
		}
		scheme, _, ok := strings.Cut(got, ":")
		if !ok || scheme == "" || scheme != strings.ToLower(scheme) {
			t.Fatalf("Normalize(%q) = %q has no lowercase scheme", raw, got)
		}
		again, err := Normalize(got)
		if err != nil || again != got {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q (%v)", raw, got, again, err)
		}
	})
}
