package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

// 取得の既定値（ADR-0008 §5）。
const (
	DefaultTimeout     = 5 * time.Second
	DefaultMaxBodySize = 5 << 10 // 5 KB（CIMD §8.7 の推奨値）
)

// Config は Resolver の設定。ゼロ値で既定の動作になる。
type Config struct {
	// HTTPClient は文書の取得に使う。nil なら NewTransport(AllowLoopback) と Timeout から組み立てる。
	// 指定した場合もリダイレクトは追従しない（CheckRedirect を上書きする）が、接続先アドレスの
	// 検査（SSRF 対策）は Transport の責務なので、NewTransport を基に作ること。
	HTTPClient *http.Client

	// Timeout は 1 回の取得の上限。0 なら DefaultTimeout。HTTPClient を指定した場合は無視する。
	Timeout time.Duration

	// MaxBodySize は文書の最大バイト数。0 なら DefaultMaxBodySize。超えたらエラー（CIMD §8.7）。
	MaxBodySize int64

	// MinCacheTTL / MaxCacheTTL はキャッシュ期間の下限・上限。0 なら 1 分 / 24 時間（CIMD §5.2）。
	MinCacheTTL time.Duration
	MaxCacheTTL time.Duration

	// MaxCacheEntries はキャッシュの件数上限。0 なら DefaultMaxCacheEntries。
	MaxCacheEntries int

	// AllowLoopback は loopback アドレスで配信される文書の取得を許す開発用の緩和（CIMD §8.6）。
	// 本番では使わない。true のとき New が警告ログを出す。
	AllowLoopback bool

	// TrustPolicy は client_id URL の信頼判定。nil なら AllowAll。
	TrustPolicy TrustPolicy

	// Now は現在時刻の取得関数。nil なら time.Now。キャッシュの期限判定に使う。
	Now func() time.Time

	// Logger は取得失敗などの出力先。nil なら slog.Default()。
	Logger *slog.Logger
}

// Resolver は CIMD の URL 形式の client_id を解決する client.Resolver。
type Resolver struct {
	http        *http.Client
	maxBody     int64
	minTTL      time.Duration
	maxTTL      time.Duration
	trust       TrustPolicy
	now         func() time.Time
	logger      *slog.Logger
	cache       *cache
	allowLoopbk bool
}

var _ client.Resolver = (*Resolver)(nil)

// New は Config を検証して Resolver を返す。
func New(cfg Config) (*Resolver, error) {
	if cfg.Timeout < 0 || cfg.MaxBodySize < 0 || cfg.MinCacheTTL < 0 || cfg.MaxCacheTTL < 0 || cfg.MaxCacheEntries < 0 {
		return nil, errors.New("cimd: durations and sizes must not be negative")
	}
	r := &Resolver{
		maxBody:     cfg.MaxBodySize,
		minTTL:      cfg.MinCacheTTL,
		maxTTL:      cfg.MaxCacheTTL,
		trust:       cfg.TrustPolicy,
		now:         cfg.Now,
		logger:      cfg.Logger,
		allowLoopbk: cfg.AllowLoopback,
	}
	if r.maxBody == 0 {
		r.maxBody = DefaultMaxBodySize
	}
	if r.minTTL == 0 {
		r.minTTL = DefaultMinCacheTTL
	}
	if r.maxTTL == 0 {
		r.maxTTL = DefaultMaxCacheTTL
	}
	if r.minTTL > r.maxTTL {
		return nil, errors.New("cimd: MinCacheTTL must not exceed MaxCacheTTL")
	}
	entries := cfg.MaxCacheEntries
	if entries == 0 {
		entries = DefaultMaxCacheEntries
	}
	r.cache = newCache(entries)
	if r.trust == nil {
		r.trust = AllowAll{}
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.logger == nil {
		r.logger = slog.Default()
	}

	if cfg.HTTPClient != nil {
		hc := *cfg.HTTPClient // 呼び出し側の値を変えずに CheckRedirect を上書きする
		r.http = &hc
	} else {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = DefaultTimeout
		}
		r.http = &http.Client{Transport: NewTransport(cfg.AllowLoopback), Timeout: timeout}
	}
	r.http.CheckRedirect = noRedirect

	if cfg.AllowLoopback {
		r.logger.Warn("cimd: loopback addresses allowed for client id metadata documents; use only for local development",
			"event", "config.cimd_allow_loopback")
	}
	return r, nil
}

// GetClient は client_id が CIMD の URL なら文書を取得・検証して Client を返す。
//
//   - CIMD の形式でない client_id: storage.ErrNotFound（Store 側で解決されるべき値）
//   - 信頼ポリシーの拒否、取得失敗、文書の検証失敗: client.ErrUnresolvable（理由付き）
//
// 成功した結果だけをキャッシュする（CIMD §5.2）。
func (r *Resolver) GetClient(ctx context.Context, id string) (*client.Client, error) {
	u, err := client.ParseClientIDURL(id)
	if err != nil {
		return nil, storage.ErrNotFound
	}
	now := r.now()
	if c := r.cache.get(id, now); c != nil {
		return c, nil
	}
	if err := r.trust.Allow(ctx, u); err != nil {
		return nil, fmt.Errorf("%w: metadata document %s: %w", client.ErrUnresolvable, id, err)
	}
	c, ttl, err := r.fetch(ctx, id, now)
	if err != nil {
		r.logger.InfoContext(ctx, "cimd: client id metadata document rejected", "event", "cimd.rejected", "client_id", id, "error", err)
		return nil, fmt.Errorf("%w: metadata document %s: %w", client.ErrUnresolvable, id, err)
	}
	r.cache.put(id, c, now.Add(ttl), now)
	r.logger.InfoContext(ctx, "cimd: client id metadata document resolved", "event", "cimd.resolved", "client_id", id, "cache_ttl", ttl)
	return c, nil
}

// fetch は文書を取得し、検証済みの Client とキャッシュ期間を返す（CIMD §5、§8.7）。
func (r *Resolver) fetch(ctx context.Context, id string, now time.Time) (*client.Client, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "auth-engine-cimd/1.0")
	res, err := r.http.Do(req)
	if err != nil {
		switch {
		case isForbiddenAddress(err):
			return nil, 0, fmt.Errorf("fetch refused: %w", ErrForbiddenAddress)
		case errors.Is(err, errNoRedirect):
			return nil, 0, errors.New("fetch failed: redirects are not followed")
		}
		var uerr *url.Error
		if errors.As(err, &uerr) && uerr.Timeout() {
			return nil, 0, errors.New("fetch failed: timeout")
		}
		return nil, 0, fmt.Errorf("fetch failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch failed: status %d", res.StatusCode)
	}
	// 上限 + 1 バイト読み、上限を超えていたらエラー（切り詰めた文書を検証しない）。
	body, err := io.ReadAll(io.LimitReader(res.Body, r.maxBody+1))
	if err != nil {
		return nil, 0, fmt.Errorf("fetch failed: %w", err)
	}
	if int64(len(body)) > r.maxBody {
		return nil, 0, fmt.Errorf("document exceeds %d bytes", r.maxBody)
	}
	var doc client.MetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("document is not valid JSON: %w", err)
	}
	c, err := client.NewMCP(doc, id, now)
	if err != nil {
		return nil, 0, fmt.Errorf("document rejected: %w", err)
	}
	return c, cacheTTL(res.Header, r.minTTL, r.maxTTL), nil
}

// Invalidate はキャッシュから id を除く。利用者が文書の更新を即時に反映させたいときに使う。
func (r *Resolver) Invalidate(id string) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	delete(r.cache.entries, id)
}
