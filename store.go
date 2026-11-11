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

	// Purge は不要になった行を削除する。呼び出し頻度は利用者のスケジューラに委ねる。
	//
	//   - now 時点で期限切れの Transaction、Authorization Code（消費済みを含む）、
	//     Access Token、Refresh Token。
	//   - 上の削除の結果、配下に Access Token も Refresh Token もなくなった Token Family
	//     （active / revoked を問わない）。
	//   - 配下に Token Family がなくなった失効済みの Grant。
	//
	// active な Grant は Token Family がなくても削除しない（同意の記録であり、同意画面の
	// 省略に使う）。Client も削除しない。1 回の呼び出しで子と親を同時に消すので、子が残って
	// いるのに親がない状態を他の操作に見せない（docs/adr/0005-storage-port.md §7）。
	Purge(ctx context.Context, now time.Time) error
}
