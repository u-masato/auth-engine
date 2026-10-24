package cimd

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/client"
)

// キャッシュ期間の既定値（ADR-0008 §5）。
const (
	DefaultMinCacheTTL     = time.Minute
	DefaultMaxCacheTTL     = 24 * time.Hour
	DefaultMaxCacheEntries = 1000
)

// cache は検証済みの Client をプロセス内メモリに保持する（CIMD §5.2）。
//
// エラー応答と不正な文書は保存しない（呼び出し側が成功時だけ put する）。件数の上限を超えたら
// 期限切れを捨て、それでも足りなければ期限が最も近いものを捨てる。未知の client_id を大量に送る
// 攻撃でメモリが際限なく増えないようにするための上限で、LRU のような精度は要らない。
type cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	max     int
}

type cacheEntry struct {
	client  *client.Client
	expires time.Time
}

func newCache(max int) *cache {
	return &cache{entries: make(map[string]cacheEntry), max: max}
}

// get は有効な Client を返す。期限切れは削除して nil。
func (c *cache) get(id string, now time.Time) *client.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return nil
	}
	if !now.Before(e.expires) {
		delete(c.entries, id)
		return nil
	}
	return e.client
}

func (c *cache) put(id string, cl *client.Client, expires time.Time, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[id]; !exists && len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[id] = cacheEntry{client: cl, expires: expires}
}

// evictLocked は 1 件以上の空きを作る。
func (c *cache) evictLocked(now time.Time) {
	for id, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, id)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	var (
		victim   string
		earliest time.Time
	)
	for id, e := range c.entries {
		if victim == "" || e.expires.Before(earliest) {
			victim, earliest = id, e.expires
		}
	}
	delete(c.entries, victim)
}

// len はテスト用。
func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// cacheTTL は応答ヘッダーからキャッシュ期間を決める（CIMD §5.2、RFC 9111 §5.2.2.1）。
//
// Cache-Control の max-age（s-maxage があれば優先）を [min, max] に収める。ヘッダーがない、
// 解析できない、no-store / no-cache のときは下限を使う（下限を設ける判断は ADR-0008 §5。
// 取得ごとに文書サーバーへ問い合わせるのを避ける）。
func cacheTTL(h http.Header, minTTL, maxTTL time.Duration) time.Duration {
	ttl := minTTL
	if v, ok := parseMaxAge(h.Get("Cache-Control")); ok {
		ttl = v
	}
	return min(max(ttl, minTTL), maxTTL)
}

func parseMaxAge(cc string) (time.Duration, bool) {
	var maxAge, sMaxAge time.Duration
	var hasMax, hasSMax bool
	for d := range strings.SplitSeq(cc, ",") {
		d = strings.TrimSpace(d)
		name, val, _ := strings.Cut(d, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch name {
		case "no-store", "no-cache":
			return 0, false
		case "max-age", "s-maxage":
			sec, err := strconv.ParseInt(val, 10, 64)
			if err != nil || sec < 0 {
				continue
			}
			if name == "max-age" {
				maxAge, hasMax = time.Duration(sec)*time.Second, true
			} else {
				sMaxAge, hasSMax = time.Duration(sec)*time.Second, true
			}
		}
	}
	switch {
	case hasSMax:
		return sMaxAge, true
	case hasMax:
		return maxAge, true
	}
	return 0, false
}
