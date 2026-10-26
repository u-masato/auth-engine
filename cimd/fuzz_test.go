package cimd

import (
	"math"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// FuzzCacheTTL は、CIMD 文書の Cache-Control の max-age がどんな値でも、キャッシュ期間が
// [minTTL, maxTTL] に収まり、max-age の値と単調に対応することを確かめる（ADR-0008 §5）。
func FuzzCacheTTL(f *testing.F) {
	const minTTL, maxTTL = time.Minute, 24 * time.Hour
	for _, n := range []uint64{0, 30, 3600, 86400, math.MaxInt64 / uint64(time.Second), math.MaxInt64/uint64(time.Second) + 1, math.MaxUint64} {
		f.Add(n, false)
		f.Add(n, true)
	}
	f.Fuzz(func(t *testing.T, sec uint64, shared bool) {
		name := "max-age"
		if shared {
			name = "s-maxage"
		}
		h := http.Header{"Cache-Control": {"public, " + name + "=" + strconv.FormatUint(sec, 10)}}
		got := cacheTTL(h, minTTL, maxTTL)
		want := minTTL // int64 に収まらない値はヘッダーがないのと同じ
		if sec <= math.MaxInt64 {
			if sec > uint64(maxTTL/time.Second) {
				want = maxTTL
			} else {
				want = min(max(time.Duration(sec)*time.Second, minTTL), maxTTL)
			}
		}
		if got != want {
			t.Fatalf("%s=%d: ttl = %v, want %v", name, sec, got, want)
		}
	})
}
