package client

import "context"

// Resolver は client_id から Client を得る。
//
// P0 では Store がそのまま Resolver となる。P1 の CIMD（Client ID Metadata Document）では、
// URL 形式の client_id を解決する別実装がこのインターフェースを満たす（ADR-0007 §4）。
//
// 不明な client_id には storage.ErrNotFound を返す。
type Resolver interface {
	GetClient(ctx context.Context, id string) (*Client, error)
}

// Store は Client の永続化 Port。Adapter が実装する。
type Store interface {
	Resolver

	// CreateClient は Client を保存する。同じ ID が既にあれば storage.ErrAlreadyExists を返す。
	CreateClient(ctx context.Context, c *Client) error
}
