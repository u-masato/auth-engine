package token

import (
	"slices"
	"testing"
)

// parseScope は /authorize と共通の client.ParseScope を通る（#22）。
func TestParseScopeRejectsEmptyElements(t *testing.T) {
	for _, raw := range []string{"api  write", " api", "api "} {
		if _, perr := parseScope(raw); perr == nil || perr.Code != CodeInvalidScope {
			t.Fatalf("scope=%q: %+v", raw, perr)
		}
	}
	if scopes, perr := parseScope("api write api"); perr != nil || !slices.Equal(scopes, []string{"api", "write"}) {
		t.Fatalf("dedupe: %v %v", scopes, perr)
	}
	if scopes, perr := parseScope(""); perr != nil || scopes != nil {
		t.Fatalf("empty: %v %v", scopes, perr)
	}
}
