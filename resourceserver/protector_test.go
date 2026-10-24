package resourceserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQuote(t *testing.T) {
	tests := map[string]string{
		`plain`:           `"plain"`,
		`has "quotes"`:    `"has \"quotes\""`,
		`back\slash`:      `"back\\slash"`,
		"ctrl\x01char":    `"ctrl char"`,
		`https://a/b?c=d`: `"https://a/b?c=d"`,
	}
	for in, want := range tests {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header  string
		token   string
		present bool
		ok      bool
	}{
		{"", "", false, false},
		{"Bearer abc", "abc", true, true},
		{"bearer abc", "abc", true, true}, // スキームは大文字小文字を区別しない（RFC 7235 §2.1）
		{"Bearer  abc ", "abc", true, true},
		{"Bearer", "", true, false},
		{"Bearer ", "", true, false},
		{"Bearer a b", "", true, false},
		{"Basic abc", "", true, false},
		{"abc", "", true, false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tt.header != "" {
			r.Header.Set("Authorization", tt.header)
		}
		tok, present, ok := bearerToken(r)
		if tok != tt.token || present != tt.present || ok != tt.ok {
			t.Errorf("%q: got (%q, %v, %v), want (%q, %v, %v)", tt.header, tok, present, ok, tt.token, tt.present, tt.ok)
		}
	}
}

func TestMetadataURL(t *testing.T) {
	tests := []struct {
		issuer string
		want   string
		ok     bool
	}{
		{"https://as.example.com", "https://as.example.com/.well-known/oauth-authorization-server", true},
		{"https://as.example.com/", "https://as.example.com/.well-known/oauth-authorization-server", true},
		{"https://as.example.com/tenant1", "https://as.example.com/.well-known/oauth-authorization-server/tenant1", true}, // RFC 8414 §3.1
		{"http://localhost:8080", "http://localhost:8080/.well-known/oauth-authorization-server", true},
		{"as.example.com", "", false},
		{"https://as.example.com?x=1", "", false},
	}
	for _, tt := range tests {
		got, err := metadataURL(tt.issuer)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("%q: got %q, %v", tt.issuer, got, err)
		}
	}
}
