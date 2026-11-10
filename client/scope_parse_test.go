package client

import (
	"errors"
	"slices"
	"testing"
)

// ParseScope は /authorize と /token の共通の分解で、RFC 6749 §3.3 の文法
// （scope-token *( SP scope-token )）をそのまま適用する（#22）。
func TestParseScope(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
		bad  bool
	}{
		{raw: "", want: nil},
		{raw: "openid", want: []string{"openid"}},
		{raw: "openid profile", want: []string{"openid", "profile"}},
		{raw: "openid profile openid", want: []string{"openid", "profile"}},
		{raw: "openid  profile", bad: true},
		{raw: " openid", bad: true},
		{raw: "openid ", bad: true},
		{raw: "openid\tprofile", bad: true},
	}
	for _, tc := range cases {
		got, err := ParseScope(tc.raw)
		if tc.bad {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("ParseScope(%q) err = %v, want ErrInvalid", tc.raw, err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("ParseScope(%q) = %v, %v; want %v", tc.raw, got, err, tc.want)
		}
	}
}
