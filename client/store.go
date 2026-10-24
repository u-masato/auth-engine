package client

import (
	"context"
	"errors"

	"github.com/u-masato/auth-engine/storage"
)

// Resolver は client_id から Client を得る。
//
// Store がそのまま Resolver となるほか、CIMD（Client ID Metadata Document）の URL 形式の client_id を
// 解決する cimd.Resolver がこのインターフェースを満たす。Engine は両者を ChainResolver で重ねる（ADR-0007 §4、ADR-0008 §5）。
//
// 不明な client_id には storage.ErrNotFound を返す。client_id の形式は正しいが解決に失敗した場合
// （CIMD 文書の取得・検証失敗、信頼ポリシーによる拒否）は ErrUnresolvable を返す。
type Resolver interface {
	GetClient(ctx context.Context, id string) (*Client, error)
}

// ErrUnresolvable は client_id に対応する Client を解決できなかったことを表す。
//
// storage.ErrNotFound（登録がない）と違い、呼び出し側が error_description に出せる理由を持つ
// （CIMD 文書の取得失敗、文書の検証失敗、信頼ポリシーによる拒否）。プロトコル上の扱いは
// ErrNotFound と同じで、認可要求ではリダイレクトしないエラー、トークン要求では invalid_client になる。
var ErrUnresolvable = errors.New("client: client_id could not be resolved")

// Store は Client の永続化 Port。Adapter が実装する。
type Store interface {
	Resolver

	// CreateClient は Client を保存する。同じ ID が既にあれば storage.ErrAlreadyExists を返す。
	CreateClient(ctx context.Context, c *Client) error
}

// ChainResolver は複数の Resolver を順に試す。先頭から storage.ErrNotFound 以外の結果が出るまで
// 進み、すべてが ErrNotFound なら ErrNotFound を返す（ADR-0008 §5: Store にあれば優先、なければ CIMD）。
type ChainResolver []Resolver

// GetClient は各 Resolver を順に呼ぶ。
func (r ChainResolver) GetClient(ctx context.Context, id string) (*Client, error) {
	for _, res := range r {
		c, err := res.GetClient(ctx, id)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		return c, err
	}
	return nil, storage.ErrNotFound
}
