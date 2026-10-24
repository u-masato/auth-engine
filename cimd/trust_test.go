package cimd

import (
	"errors"
	"net/url"
	"testing"
)

func TestHostAllowlist(t *testing.T) {
	policy := HostAllowlist{"mcp-client.example", "*.trusted.example"}
	tests := []struct {
		id string
		ok bool
	}{
		{"https://mcp-client.example/client", true},
		{"https://MCP-Client.example/client", true},
		{"https://mcp-client.example:8443/client", true},
		{"https://app.trusted.example/client", true},
		{"https://a.b.trusted.example/client", true},
		{"https://trusted.example/client", false}, // *. はサブドメインだけ
		{"https://evil.example/client", false},
		{"https://mcp-client.example.evil/client", false},
	}
	for _, tt := range tests {
		u, _ := url.Parse(tt.id)
		err := policy.Allow(t.Context(), u)
		if (err == nil) != tt.ok {
			t.Errorf("%s: ok=%v err=%v", tt.id, tt.ok, err)
		}
		if err != nil && !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: want ErrUntrusted, got %v", tt.id, err)
		}
	}
	if err := (AllowAll{}).Allow(t.Context(), &url.URL{Host: "anything"}); err != nil {
		t.Error(err)
	}
}
