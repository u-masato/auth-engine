package client

import (
	"errors"
	"slices"
	"testing"
)

func TestValidScopeToken(t *testing.T) {
	valid := []string{"openid", "api:read", "https://example.com/scope", "a-b_c.d", "!", "~"}
	for _, s := range valid {
		if !ValidScopeToken(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	invalid := []string{"", "with space", "quote\"", "back\\slash", "日本語", "tab\t", "\x7f"}
	for _, s := range invalid {
		if ValidScopeToken(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestScopesValidation(t *testing.T) {
	_, _, err := NewMachine(MachineParams{Name: "m", Scopes: []string{"a", "a"}}, now)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("duplicate scope: want ErrInvalid, got %v", err)
	}
	_, _, err = NewMachine(MachineParams{Name: "m", Scopes: []string{"bad scope"}}, now)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("bad token: want ErrInvalid, got %v", err)
	}
}

func TestDisallowedScopes(t *testing.T) {
	c, _, err := NewMachine(MachineParams{Name: "m", Scopes: []string{"a", "b"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.DisallowedScopes([]string{"a", "b"}); len(got) != 0 {
		t.Errorf("all allowed, got %v", got)
	}
	if got := c.DisallowedScopes([]string{"a", "c", "d"}); !slices.Equal(got, []string{"c", "d"}) {
		t.Errorf("got %v, want [c d]", got)
	}
}
