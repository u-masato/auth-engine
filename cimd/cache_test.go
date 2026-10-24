package cimd

import (
	"net/http"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
)

func TestCacheTTL(t *testing.T) {
	const minTTL, maxTTL = time.Minute, 24 * time.Hour
	tests := []struct {
		cc   string
		want time.Duration
	}{
		{"", minTTL},                // ヘッダーなし → 下限
		{"max-age=3600", time.Hour}, // 尊重
		{"public, max-age=3600", time.Hour},
		{`max-age="3600"`, time.Hour},
		{"MAX-AGE=3600", time.Hour},
		{"max-age=10", minTTL}, // 下限に丸める
		{"max-age=0", minTTL},
		{"max-age=999999999", maxTTL}, // 上限に丸める
		{"no-store", minTTL},          // 下限を設ける判断（ADR-0008 §5）
		{"no-cache, max-age=3600", minTTL},
		{"max-age=abc", minTTL},
		{"max-age=-5", minTTL},
		{"s-maxage=7200, max-age=60", 2 * time.Hour}, // 共有キャッシュ向けの値を優先
	}
	for _, tt := range tests {
		h := http.Header{}
		if tt.cc != "" {
			h.Set("Cache-Control", tt.cc)
		}
		if got := cacheTTL(h, minTTL, maxTTL); got != tt.want {
			t.Errorf("%q: got %s, want %s", tt.cc, got, tt.want)
		}
	}
}

func TestCacheEviction(t *testing.T) {
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	c := newCache(3)
	dummy := &client.Client{ID: "x"}
	c.put("a", dummy, now.Add(time.Hour), now)
	c.put("b", dummy, now.Add(time.Second), now) // 最も早く切れる
	c.put("c", dummy, now.Add(time.Hour), now)
	if c.len() != 3 {
		t.Fatalf("len = %d", c.len())
	}
	// 満杯で期限切れがなければ、期限が最も近いものを捨てる
	c.put("d", dummy, now.Add(time.Hour), now)
	if c.len() != 3 || c.get("b", now) != nil || c.get("a", now) == nil || c.get("d", now) == nil {
		t.Fatalf("expected b evicted: len=%d", c.len())
	}
	// 既存キーの上書きは追い出さない
	c.put("a", dummy, now.Add(2*time.Hour), now)
	if c.len() != 3 {
		t.Fatalf("overwrite must not evict: len=%d", c.len())
	}
	// 期限切れがあればそれを先に捨てる
	later := now.Add(90 * time.Minute)
	c.put("e", dummy, later.Add(time.Hour), later) // a は 2h 後まで有効、c と d は切れている
	if c.get("a", later) == nil || c.get("e", later) == nil || c.get("c", later) != nil {
		t.Fatalf("expired entries must be evicted first")
	}
	// get は期限切れを返さない
	if c.get("e", later.Add(2*time.Hour)) != nil {
		t.Fatal("expired entry returned")
	}
}
