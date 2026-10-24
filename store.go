package authengine

import (
	"context"
	"time"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/token"
)

// Store は Adapter が実装する永続化 Port の全体。
//
// 各文脈パッケージが自分に必要なメソッドだけを定義した Store インターフェースを、
// ここで合成する（docs/adr/0007-package-layout.md §2）。エンジン内部の各 Service は
// 自分の文脈の Store だけを受け取り、この合成型を参照しない。
//
// 契約: 各メソッドは単体で原子的であること（docs/adr/0005-storage-port.md）。
// 全 Adapter は storage/storagetest の契約テストを通さなければならない。
type Store interface {
	client.Store
	authorization.Store
	grant.Store
	token.Store

	// Purge は now 時点で期限切れの Transaction、Authorization Code、Access Token、
	// Refresh Token を削除する。呼び出し頻度は利用者のスケジューラに委ねる。
	Purge(ctx context.Context, now time.Time) error
}
