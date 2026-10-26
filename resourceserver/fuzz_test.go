package resourceserver

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzBearerToken は、Authorization ヘッダから取り出したトークンが空でなく空白を含まないこと、
// 取り出せるのは Bearer スキーム（大文字小文字を区別しない）のときだけであることを確かめる（RFC 6750 §2.1）。
func FuzzBearerToken(f *testing.F) {
	for _, seed := range []string{"", "Bearer abc", "bearer abc", "Bearer  abc ", "Bearer a b", "Bearer\tabc", "Basic YTpi", "Bearer", "Bearer "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		r, _ := http.NewRequest(http.MethodGet, "https://mcp.example.com/", nil)
		if header != "" {
			r.Header["Authorization"] = []string{header}
		}
		token, present, ok := bearerToken(r)
		if present != (header != "") {
			t.Fatalf("present = %v for header %q", present, header)
		}
		if !ok {
			if token != "" {
				t.Fatalf("rejected header %q still returned token %q", header, token)
			}
			return
		}
		scheme, _, _ := strings.Cut(header, " ")
		if !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") || !strings.Contains(header, token) {
			t.Fatalf("bearerToken(%q) = %q", header, token)
		}
	})
}

// FuzzJWKSTTL は、Cache-Control の max-age がどんな値でも、JWKS の保持期間が
// [MinJWKSTTL, MaxJWKSTTL] に収まり、max-age の値と単調に対応することを確かめる。
func FuzzJWKSTTL(f *testing.F) {
	for _, n := range []uint64{0, 30, 3600, 86400, math.MaxInt64 / uint64(time.Second), math.MaxInt64/uint64(time.Second) + 1, math.MaxUint64} {
		f.Add(n)
	}
	v := &JWTVerifier{}
	f.Fuzz(func(t *testing.T, sec uint64) {
		h := http.Header{"Cache-Control": {"public, max-age=" + strconv.FormatUint(sec, 10)}}
		got := v.jwksTTL(h)
		want := clampSeconds(sec, MinJWKSTTL, MaxJWKSTTL)
		if sec > math.MaxInt64 { // ParseInt で読めない値はヘッダーがないのと同じ（既定値）
			want = DefaultJWKSTTL
		}
		if got != want {
			t.Fatalf("max-age=%d: ttl = %v, want %v", sec, got, want)
		}
	})
}

// clampSeconds は sec 秒を [lo, hi] に収める。time.Duration の範囲を超える秒数は hi とみなす。
func clampSeconds(sec uint64, lo, hi time.Duration) time.Duration {
	if sec >= uint64(hi/time.Second)+1 {
		return hi
	}
	return min(max(time.Duration(sec)*time.Second, lo), hi)
}
