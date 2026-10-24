# ADR-0002: 技術スタック

- 状態: 採用（2026-10-24 合意）
- 日付: 2026-10-24

## 文脈

ユーザー提示の技術スタック案を批判的に検討した。判断は「採用」「修正して採用」「却下」「保留」の4区分で示す。

## 決定

| 項目 | 案 | 判断 | 理由 |
| --- | --- | --- | --- |
| 言語 | Go 1.27+（1.27 でも CI） | 採用 | `go.mod` の `go` 行は 1.27 とし、CI は 1.27 で回す。 |
| HTTP | `net/http` のみ | 採用 | Go 1.22 以降の `ServeMux` でメソッド付きパターンが使える。エンドポイント数は 10 前後で、ルーターの追加価値はない。 |
| OAuth/OIDC | 独自実装 | 採用 | これが OSS の中核。既存ライブラリ（fosite 等）を使うと「参考実装」としての価値がなくなる。 |
| JOSE | `go-jose/v4` | 採用 | JWS 署名・検証と JWK/JWKS の直列化だけに使う。利用面は `keys` パッケージに閉じ込め、将来差し替え可能にする。JWE は P0 で使わない。 |
| 暗号 | 標準ライブラリ | 採用 | 乱数は `crypto/rand`、ハッシュは `crypto/sha256`、比較は `crypto/subtle`。プリミティブは自作しない。 |
| 本番 DB | PostgreSQL（`pgx/v5`） | 採用（P0 では着手しない） | ADR-0005 の Storage Port を SQLite で成立させてから着手する。 |
| 軽量 DB | SQLite（`modernc.org/sqlite`） | 採用 | CGO 不要で `go test -race` と相性がよい。`UPDATE ... RETURNING` が使えるので原子的消費を 1 文で書ける。WAL + `busy_timeout` を Adapter 側で固定する。 |
| Migration | `goose` | 修正して採用 | CLI ではなく **ライブラリとして** Adapter 内から呼ぶ（`goose.NewProvider` + `embed.FS`）。利用者に goose CLI の導入を求めない。Adapter の `Migrate(ctx, db)` が唯一の入口。 |
| ロギング | `log/slog` | 採用 | コアは `*slog.Logger` を受け取るだけ。出力先・形式は利用者が決める。 |
| Observability | OpenTelemetry（任意） | 保留 | コアに `otel` 依存を入れない。HTTP 層のミドルウェアとして利用者側で付けられる形にする。P0 では着手しない。 |
| コンテナ | Docker / Compose | 採用（P2 以降） | Conformance Suite 実行と PostgreSQL 統合テスト用。P0 では不要。 |
| CI | GitHub Actions | 採用 | `go vet`、`staticcheck`、`govulncheck`、`go test -race`、Adapter の契約テスト。 |
| ライセンス | Apache-2.0 | 採用 | — |
| ORM / クエリビルダ | 不採用 | 採用（不採用の方針を支持） | SQL は明示的に書く。参照実装として「どの文が原子性を担うか」が読める方が重要。`sqlc` は Adapter のクエリが 30 を超えたら検討。 |
| Testcontainers | 採用 | 採用（P2） | PostgreSQL Adapter 着手時に導入。 |
| Conformance Suite | OpenID Foundation Conformance Suite | 採用（P2） | 実行には「自動でログインを完了する Interaction App」が必要。ADR-0003 の契約で `examples/` にテストモードを持たせる。 |

## 補足判断

### JWT ライブラリの代替検討

- `lestrrat-go/jwx`: 機能が広く、依存も多い。参考実装としては過剰。
- `golang-jwt/jwt`: JWK/JWKS の取り扱いが弱く、鍵管理を自作する必要が出る。
- 標準ライブラリのみで JWS を実装: 可能だが、アルゴリズム混同などの実装ミスのリスクを OSS として負う理由がない。

### 署名アルゴリズム

- 既定の ID Token 署名は **RS256**（RSA 2048）。OIDC Core §15.1 で OP が必須サポートとされ、RP 側の互換性が最も高い。
- **ES256** を選択可能にする。鍵は `kid` 付きで複数保持し、署名鍵は 1 本、検証鍵は複数（ローテーション中の旧鍵）。
- `none`、HS256（共有秘密）は ID Token に許容しない（RFC 8725 §3.1, §3.2）。

### 設定の受け渡し

- 環境変数や設定ファイルの解釈はコアで行わない。コアは Go の構造体（`Config`）を受け取る。`examples/standalone` が環境変数を `Config` に変換する例を示す。
