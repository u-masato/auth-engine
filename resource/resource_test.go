package resource

import (
	"errors"
	"slices"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		raw  string
		want string // 空なら ErrInvalid
	}{
		{"https://mcp.example.com", "https://mcp.example.com"},
		{"HTTPS://MCP.Example.COM", "https://mcp.example.com"},
		{"https://mcp.example.com/", "https://mcp.example.com/"},
		{"https://mcp.example.com/Path/To", "https://mcp.example.com/Path/To"}, // path は区別
		{"https://mcp.example.com:8443/mcp?x=1", "https://mcp.example.com:8443/mcp?x=1"},
		{"urn:example:api", "urn:example:api"},
		{"", ""},
		{"mcp.example.com", ""},              // 相対参照
		{"/mcp", ""},                         // 相対参照
		{"https://", ""},                     // host なし
		{"https:///mcp", ""},                 // host なし
		{"https://mcp.example.com#frag", ""}, // fragment
		{"https://mcp.example.com#", ""},     // 空 fragment
		{"https://mcp.example.com/a\x00b", ""},
	}
	for _, tt := range tests {
		got, err := Normalize(tt.raw)
		if tt.want == "" {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Normalize(%q) = %q, %v; want ErrInvalid", tt.raw, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
		}
	}
}

func TestNewSetAndLookup(t *testing.T) {
	set, err := NewSet([]Resource{
		{URI: "https://MCP.example.com", Name: "MCP", AccessTokenFormat: FormatJWT, Scopes: []string{"files:read", "files:write"}},
		{URI: "https://api.example.com/v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 || !slices.Equal(set.URIs(), []string{"https://mcp.example.com", "https://api.example.com/v1"}) {
		t.Fatalf("set: %v", set.URIs())
	}
	r, ok := set.Lookup("https://mcp.EXAMPLE.com")
	if !ok || r.URI != "https://mcp.example.com" || r.Name != "MCP" || r.EffectiveFormat() != FormatJWT || !slices.Equal(r.Scopes, []string{"files:read", "files:write"}) {
		t.Fatalf("lookup: %+v, %v", r, ok)
	}
	r, ok = set.Lookup("https://api.example.com/v1")
	if !ok || r.EffectiveFormat() != FormatOpaque {
		t.Fatalf("default format: %+v, %v", r, ok)
	}
	for _, miss := range []string{"https://api.example.com/v1/", "https://api.example.com", "https://other.example.com", "not a uri", ""} {
		if _, ok := set.Lookup(miss); ok {
			t.Errorf("Lookup(%q) must miss", miss)
		}
	}
}

func TestNewSetErrors(t *testing.T) {
	tests := []struct {
		name string
		rs   []Resource
		want error
	}{
		{"invalid uri", []Resource{{URI: "mcp.example.com"}}, ErrInvalid},
		{"fragment", []Resource{{URI: "https://mcp.example.com#x"}}, ErrInvalid},
		{"unknown format", []Resource{{URI: "https://mcp.example.com", AccessTokenFormat: "paseto"}}, ErrInvalid},
		{"bad scope", []Resource{{URI: "https://mcp.example.com", Scopes: []string{"a b"}}}, ErrInvalid},
		{"duplicate scope", []Resource{{URI: "https://mcp.example.com", Scopes: []string{"a", "a"}}}, ErrInvalid},
		{"duplicate uri after normalization", []Resource{{URI: "https://mcp.example.com"}, {URI: "https://MCP.example.com"}}, ErrDuplicate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSet(tt.rs); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNilSet(t *testing.T) {
	var set *Set
	if set.Len() != 0 || set.URIs() != nil {
		t.Fatal("nil set must be empty")
	}
	if _, ok := set.Lookup("https://mcp.example.com"); ok {
		t.Fatal("nil set must not match anything")
	}
	empty, err := NewSet(nil)
	if err != nil || empty.Len() != 0 {
		t.Fatalf("empty set: %v, %v", empty, err)
	}
}

func TestSetCopiesScopes(t *testing.T) {
	in := []Resource{{URI: "https://mcp.example.com", Scopes: []string{"a"}}}
	set, err := NewSet(in)
	if err != nil {
		t.Fatal(err)
	}
	in[0].Scopes[0] = "changed"
	if r, _ := set.Lookup("https://mcp.example.com"); r.Scopes[0] != "a" {
		t.Fatal("set must not share the caller's slice")
	}
}

func TestResolve(t *testing.T) {
	set, err := NewSet([]Resource{
		{URI: "https://api.example.com"},
		{URI: "https://mcp.example.com"},
		{URI: "https://jwt.example.com", AccessTokenFormat: FormatJWT},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := set.Resolve([]string{"https://API.example.com", "", "https://mcp.example.com", "https://api.example.com"})
	if err != nil || !slices.Equal(got, []string{"https://api.example.com", "https://mcp.example.com"}) {
		t.Fatalf("resolve must normalize, skip empty values and deduplicate: %v, %v", got, err)
	}
	if got, err := set.Resolve(nil); err != nil || got != nil {
		t.Fatalf("empty input: %v, %v", got, err)
	}
	tests := []struct {
		name string
		raw  []string
		want error
	}{
		{"relative", []string{"api.example.com"}, ErrInvalid},
		{"unknown", []string{"https://other.example.com"}, ErrUnknown},
		{"trailing slash", []string{"https://api.example.com/"}, ErrUnknown},
		{"mixed formats", []string{"https://api.example.com", "https://jwt.example.com"}, ErrMixedFormats},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := set.Resolve(tt.raw); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
	// nil の Set は空集合: 値があれば ErrUnknown、なければ nil
	var none *Set
	if _, err := none.Resolve([]string{"https://api.example.com"}); !errors.Is(err, ErrUnknown) {
		t.Fatalf("nil set: %v", err)
	}
	if got, err := none.Resolve(nil); err != nil || got != nil {
		t.Fatalf("nil set with no values: %v, %v", got, err)
	}
}

func TestScopeLimits(t *testing.T) {
	set, err := NewSet([]Resource{
		{URI: "https://open.example.com"},
		{URI: "https://files.example.com", Scopes: []string{"files:read"}},
		{URI: "https://mail.example.com", Scopes: []string{"mail:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	files, _ := set.Lookup("https://files.example.com")
	for scope, want := range map[string]bool{"files:read": true, "files:write": false, "openid": true, "offline_access": true, "profile": true} {
		if got := files.AllowsScope(scope); got != want {
			t.Errorf("AllowsScope(%q) = %v, want %v", scope, got, want)
		}
	}
	open, _ := set.Lookup("https://open.example.com")
	if !open.AllowsScope("anything") {
		t.Error("resource without Scopes must allow any scope")
	}

	scopes := []string{"openid", "files:read", "files:write", "mail:read"}
	if dis := set.DisallowedScopes(nil, scopes); dis != nil {
		t.Errorf("no audience means no limit: %v", dis)
	}
	if dis := set.DisallowedScopes([]string{"https://open.example.com"}, scopes); dis != nil {
		t.Errorf("unrestricted resource: %v", dis)
	}
	if dis := set.DisallowedScopes([]string{"https://files.example.com"}, scopes); !slices.Equal(dis, []string{"files:write", "mail:read"}) {
		t.Errorf("files only: %v", dis)
	}
	// 複数 resource ではどれかが許せばよい
	if dis := set.DisallowedScopes([]string{"https://files.example.com", "https://mail.example.com"}, scopes); !slices.Equal(dis, []string{"files:write"}) {
		t.Errorf("files + mail: %v", dis)
	}
	var none *Set
	if dis := none.DisallowedScopes([]string{"https://files.example.com"}, []string{"x"}); !slices.Equal(dis, []string{"x"}) {
		t.Errorf("nil set must not allow non-OIDC scopes for an audience: %v", dis)
	}
}
