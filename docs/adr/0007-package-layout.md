# ADR-0007: パッケージ・モジュール構成

- 状態: 採用（2026-10-24 合意）
- 日付: 2026-10-24

## 文脈

技術スタック案の構成:

```
domain/{client,authorization,grant,token,policy}
protocol/{oauth2,oidc}
usecase/{authorize,exchange,tokenops}
storage/  crypto/  transport/http/
adapters/{sqlite,postgres}（別 Go Module）
```

批判点:

1. `domain` / `protocol` / `usecase` の 3 層に分けると、1 つの流れ（例: Code 交換）が 3 ディレクトリに散り、参照実装として追いにくい。PKCE 検証は `protocol/oauth2` か `domain/authorization` か、という置き場所の議論が繰り返される。
2. Go では層ごとのパッケージ分割は循環参照と「型だけのパッケージ」を生みやすい。Go の慣習はレイヤーより **機能（文脈）ごとのパッケージ** である。
3. `policy`、`tokenops` は P0 の時点で中身が薄い。

## 決定

### 1. レイヤーではなく文脈でパッケージを切る

コアモジュール `github.com/muno/auth-engine`:

```
auth-engine/
├── go.mod                 # 依存: go-jose/v4 のみ
├── go.work                # ローカル開発用（adapters を束ねる）
├── engine.go              # ルートパッケージ authengine: Engine（配線の入口）と、Adapter が実装する合成 Store
├── client/                # Client 集約、Profile、redirect URI 照合、secret 検証
├── authorization/         # AuthorizationRequest の解析・検証、Transaction 状態機械、
│                          # Begin/Complete/Reject/Resume、PKCE、Authorization Code 発行
├── grant/                 # Grant 集約（client×subject、scopes、claims スナップショット）、失効
├── token/                 # Opaque Access/Refresh Token、Token Family、Rotation、Code 交換（/token）
├── oidc/                  # ID Token の組立と署名、Discovery メタデータ、UserInfo、scope→claims
├── keys/                  # 署名鍵セット（JWK）、ローテーション、go-jose の利用はここに閉じる
├── storage/               # 葉パッケージ。センチネルエラーだけを持ち、他のコアパッケージを import しない
│   ├── memory/            # テスト用 In-Memory 実装（ルートの Store を実装）
│   └── storagetest/       # Adapter 契約テスト（ルートの Store を検証）
├── httpapi/               # net/http ハンドラ。公開エンドポイント用と Interaction API 用の 2 つの Handler
├── internal/
│   ├── rand/              # 乱数トークン生成・ハッシュ
│   └── clock/             # 時刻の注入
├── adapters/
│   ├── sqlite/            # 別モジュール: github.com/muno/auth-engine/adapters/sqlite
│   └── postgres/          # 別モジュール（P2）
├── examples/standalone/   # 別モジュール: エンジン + デモ Interaction App（loginapp）+ サンプル Client（oauthclient）
├── docs/
└── tests/                 # 別モジュール: E2E（SQLite + httptest + loginapp）。コアから Adapter を import できないため
```

対応関係:

| 案のディレクトリ | 本決定での置き場所 |
| --- | --- |
| `domain/client`, `domain/policy` | `client/`（Profile が policy の実体） |
| `domain/authorization`, `protocol/oauth2` の認可要求部分, `usecase/authorize` | `authorization/` |
| `domain/grant` | `grant/` |
| `domain/token`, `usecase/exchange`, `usecase/tokenops` | `token/` |
| `protocol/oidc` | `oidc/` |
| `crypto/` | `keys/` と `internal/rand/`（「crypto」は標準ライブラリと名前が衝突する） |
| `transport/http/` | `httpapi/` |

#### パッケージ内のファイル構成

1 つの文脈パッケージの中に entity・値オブジェクト・ユースケースを同居させる。サブパッケージでは分けない。ファイルは **種類別（`entity.go`, `usecase.go`）ではなく概念別** に切る。`authorization/` の例:

```
authorization/
├── doc.go           # 責務、対応する RFC の節、永続化の規約
├── request.go       # AuthorizationRequest（値オブジェクト）: 解析・検証、リダイレクト可否の判定
├── pkce.go          # CodeChallenge（値オブジェクト）: S256 の検証
├── transaction.go   # Transaction（entity）: 状態機械と遷移メソッド
├── code.go          # AuthorizationCode（entity）
├── service.go       # Service: 依存（Store, Clock, Issuer）を束ねる。これがユースケースの置き場所
├── begin.go         # (*Service).Begin
├── complete.go      # (*Service).Complete / Reject
├── resume.go        # (*Service).Resume
├── store.go         # この文脈が必要とする Store インターフェース
├── errors.go        # この文脈のエラー型（RFC 6749 §4.1.2.1 のエラーコードへの対応）
└── *_test.go
```

- 「ユースケース」は `Service` 構造体のメソッドである。1 ユースケース 1 ファイルにし、ファイル名は操作名にする。
- 値オブジェクトは `Parse...` / `New...` で構築し、不正値は `error` で返す。不正な値を持つインスタンスを作らせない。
- entity とユースケースが同じパッケージにあるため、entity の非公開フィールドをユースケースから扱える。層で分けると全フィールドを公開するかアクセサを増やすことになり、不変条件が守れない。

### 2. 依存の向き

```
httpapi ──▶ authengine（ルート） ──▶ authorization, token, oidc, grant, client ──▶ storage（エラーのみ）, keys, internal/*
                 ▲
adapters/sqlite ─┘（ルートの Store を実装。コアを import するがコアからは参照されない）
storage/memory, storage/storagetest ──▶ authengine（ルート）
```

依存は一方向である。

| 向き | 内容 |
| --- | --- |
| 文脈パッケージ → `storage` | センチネルエラー（`ErrNotFound` 等）の参照のみ。`storage` は他のコアパッケージを import しない **葉パッケージ** |
| ルート → 文脈パッケージ | 各文脈の Store インターフェースを埋め込んで合成 `Store` を作り、`Service` 群を配線する |
| Adapter → ルート | `authengine.Store` を実装し、`sqlite.Open(...)` は `authengine.Store` を返す |
| `storage/memory`, `storage/storagetest` → ルート | 合成 `Store` を実装・検証する。ルートはこれらを import しないので循環しない |

#### Store インターフェースは「使う側」で定義する

Go の慣習に従い、インターフェースはそれを**使う文脈パッケージ**が、自分に必要なメソッドだけを定義する。保存対象の型もその文脈パッケージが定義する。`storage` に置くと、`storage` が文脈の型を参照し、文脈が `storage` のインターフェースを参照して循環する。

```go
// authorization/store.go
type Store interface {
    CreateTransaction(ctx context.Context, txn *Transaction) error
    GetTransaction(ctx context.Context, id TxnID) (*Transaction, error)
    TransitionTransaction(ctx context.Context, id TxnID, from, to Status, patch TransitionPatch) error
    CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
}

// engine.go（ルートパッケージ authengine）
type Store interface {
    client.Store
    authorization.Store
    grant.Store
    token.Store
    Purge(ctx context.Context, now time.Time) error
}
```

- 文脈をまたぐ操作（例: `token` の Code 交換が `authorization.AuthorizationCode` を消費する）は、**その操作を実行する文脈**のインターフェースに置く。`ConsumeAuthorizationCode` は `token.Store` に属し、引数・戻り値の型として `authorization` パッケージを import する（`authorization` は `token` を import しないので一方向）。
- `Service` は合成 `Store` ではなく自分の `Store` だけを受け取る。テストでは必要なメソッドだけを持つスタブを渡せる。

#### 永続化と不変条件（案 A）

Adapter は別パッケージなので非公開フィールドを読み書きできない。永続化対象の型は **フィールドを公開した素朴な構造体** とし、不変条件は次の規約で守る。

- 構築はコンストラクタ（`NewTransaction(...)`）のみ。ゼロ値や構造体リテラルからの構築はコア内で禁止する。
- 状態変更は遷移メソッド（`(*Transaction).Complete(...)`）のみ。公開フィールドへの直接代入は Adapter の直列化・復元に限る。
- 遷移メソッドは新しい状態を返すが、永続化の原子性（CAS）は Adapter の `TransitionTransaction` が担う（ADR-0005）。コアは「遷移の正当性」、Adapter は「遷移の原子性」を分担する。
- この規約はコンパイラでは強制できない。各パッケージの `doc.go` に明記し、レビューで守る。

永続化レコードを分離して非公開フィールドを保つ案（`Snapshot()` / `Restore()`）は、型と変換コードが倍になるため採らない。不変条件が複雑化して規約で守れなくなった型が出た場合に、その型だけ個別に見直す。

#### 外部依存

- コアが import してよい外部モジュールは `go-jose/v4` のみ。CI で `go list -deps` を使って検査する。

### 3. Adapter と examples は別モジュール（採用）

- コアの `go.mod` から `modernc.org/sqlite` や `pgx` を排除するため、Adapter は別モジュールにする。利用者のビルドに不要な依存が入らない。
- 単一モジュールにしてもビルド対象には含まれないが、`go.sum` と `go mod graph` に全推移依存が現れ、`govulncheck` の対象も広がる。参考実装として「コアの依存は 1 つ」を示したい。
- 代償: タグ付けが `adapters/sqlite/v0.1.0` 形式になり、`go.work` が必要になる。P0 では `v0.x` のまま進めるため負担は小さい。
- 「最終的に別リポジトリ」は決めない。モノレポのままでも成立する。
- `tests/` も別モジュールにする。コアモジュールのテストから Adapter を import すると依存の向きが逆転する（Adapter → コア → Adapter の循環）ため、Adapter と examples を参照できる外側のモジュールに置く。開発中は各モジュールの `go.mod` に `replace` を書き、`go.work` で束ねる。

### 4. 拡張点（P0 で「存在だけ」確保するインターフェース）

| インターフェース | P0 の実装 | 将来 |
| --- | --- | --- |
| `authengine.Store`（各文脈の `Store` の合成） | memory, sqlite | postgres |
| `client.Resolver`（`client_id` → Client） | `Store` を使う実装 | CIMD（P1） |
| `token.Issuer` | Opaque | JWT AT（P1） |
| `httpapi.InteractionAuthenticator` | 事前共有 Bearer | mTLS 等 |
| `httpapi.ErrorRenderer` | プレーン HTML | 利用者差し替え |
| `clock.Clock` | 実時刻 | テスト用固定時刻 |

これ以上の抽象（`policy` パッケージ、`tokenops` パッケージ、イベントバス等）は P0 では作らない。

## 影響

- パッケージ数はコアで 9（`internal` を含む）。読者は `authorization/` → `token/` → `oidc/` の順に読めばフローを追える。
- `storage` パッケージは葉として小さく保つ。エラー以外のものを置きたくなったら、それは文脈パッケージかルートに属する。
- 各パッケージの `doc.go` に「対応する RFC の節」を列挙する。
