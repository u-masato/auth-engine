package console

import (
	"testing"
	"time"
)

// 表示と編集フォームの初期値に使うので、time.ParseDuration で同じ値に読み戻せること。
func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "1h", 15 * time.Minute: "15m", 90 * time.Minute: "1h30m", 24 * time.Hour: "24h",
		90 * time.Second: "1m30s", time.Hour + time.Second: "1h0m1s",
	} {
		got := shortDuration(d)
		if got != want {
			t.Errorf("shortDuration(%v) = %q, want %q", d, got, want)
		}
		if back, err := time.ParseDuration(got); err != nil || back != d {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", got, back, err, d)
		}
	}
}
