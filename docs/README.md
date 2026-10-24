# 設計ドキュメント

Go 製ヘッドレス OAuth 2.0 / OIDC 認可サーバー「Protocol Engine」の設計判断をまとめる。
2026-10-24 にユーザーと合意し、すべて「採用」とした。以後の変更は新しい ADR で上書きし、既存 ADR には参照を追記する（M3 では ADR-0008 の決定を ADR-0001 / 0004 / 0005 / 0006 / 0007 に追記した。2026-10-25）。

## 文書一覧

| 文書 | 内容 |
| --- | --- |
| [準拠仕様一覧](specifications.md) | 準拠仕様の段階分け（P0〜P3） |
| [ADR-0001 スコープと設計原則](adr/0001-scope-and-principles.md) | 本体と外部アプリの責務分担、設計原則、P0 で提供しないもの |
| [ADR-0002 技術スタック](adr/0002-tech-stack.md) | 言語・ライブラリ・ツールの採否 |
| [ADR-0003 Interaction App との契約](adr/0003-interaction-contract.md) | **最重要**。Authorization Transaction の引き渡し、完了通知、認証、タイムアウト、ハイジャック対策 |
| [ADR-0004 Client Profile](adr/0004-client-profiles.md) | Web / Native・CLI / M2M で固定する項目と開放する項目 |
| [ADR-0005 Storage Port](adr/0005-storage-port.md) | Port の粒度、Code 原子的消費・Rotation・Grant 失効の Adapter 側保証 |
| [ADR-0006 トークン形式と Token Operations](adr/0006-tokens-and-token-operations.md) | Opaque AT + JWT ID Token、Mint / Reissue の却下 |
| [ADR-0007 パッケージ・モジュール構成](adr/0007-package-layout.md) | 文脈ごとのパッケージ分割、Adapter の別モジュール化 |
| [ADR-0008 MCP 連携](adr/0008-mcp-integration.md) | Resource Indicators と Audience、MCP Client Profile、CIMD Resolver、JWT Access Token、Resource Server ミドルウェア、DCR の不採用 |
| [ロードマップ](roadmap.md) | M1〜M4 とタスク順序、M1〜M3 の実施結果と計画からの差分 |
| [組み込みガイド](embedding.md) | エンジンを組み込む人向け。責務の分担、Store の選択、Client 登録、HTTP への公開、鍵、監査ログ、本番前の確認 |
| [Interaction API 仕様](interaction-api.md) | Interaction App 実装者向け。エンドポイント、JSON、エラー、守ってほしいこと |
| [Conformance Suite](conformance.md) | OpenID Conformance Suite（Basic OP）をローカルで回す構成・手順・想定結果 |
| [MCP 相互運用](mcp-interop.md) | MCP Inspector（公式 MCP クライアント）で CIMD + PKCE + `resource` のフローを回す構成・手順・結果 |

## 技術スタック案に対する判断の要約

| 論点 | 判断 | 参照 |
| --- | --- | --- |
| Go 1.26+ / net/http / 独自 OAuth 実装 / go-jose v4 / 標準 crypto / slog | 採用 | ADR-0002 |
| SQLite（modernc）→ PostgreSQL（pgx） | 採用。PostgreSQL は M2 | ADR-0002 |
| goose | 修正。ライブラリとして Adapter 内から呼ぶ | ADR-0002 |
| OpenTelemetry | 保留。コアに依存を入れない | ADR-0002 |
| ヘッドレス契約（案に欠落） | 新規に定義。二段階（バックチャネル Complete → ブラウザ Resume）、ブラウザ結合 Cookie、Bearer 認証の Interaction API、Txn 10 分 / Code 60 秒 | ADR-0003 |
| Client Profile 3 種 | 採用。grant_types / PKCE / 認証方式 / 照合規則は固定、Custom Profile は置かない | ADR-0004 |
| Storage Port | 修正。トランザクション抽象を Port に置かず、操作単位の原子性を契約にする。契約テストを全 Adapter に課す | ADR-0005 |
| Opaque AT + JWT ID Token | 採用。帰結として Introspection / Revocation を M2 必須に | ADR-0006 |
| Token Operations の Mint / Reissue | 却下。Client Credentials / Token Exchange に写像する | ADR-0006 |
| Inspect / Revoke / RevokeGrant | 採用（M2、Go API） | ADR-0006 |
| domain / protocol / usecase の 3 層構成 | 修正。文脈ごと（client / authorization / grant / token / oidc / keys / storage / httpapi）に統合 | ADR-0007 |
| Adapter を別 Go Module | 採用 | ADR-0007 |
| 最初のマイルストーン（SQLite で Code + PKCE 完走） | 採用。10 タスクに分解 | roadmap |

## 合意済みの点（2026-10-24）

実装着手前に次の判断をユーザーと確認し、合意した。

1. ADR-0003 の二段階方式（Interaction App は Code を見ない）と、ブラウザ結合 Cookie を既定で有効にすること
2. ADR-0004 の「Custom Profile を置かない」こと（PKCE 非対応クライアントを切る）
3. ADR-0005 の「Port にトランザクション抽象を置かない」こと。全 Port メソッドの第一引数は `context.Context`
4. ADR-0006 の `Mint` / `Reissue` 却下
5. ADR-0007 のパッケージ構成（3 層を文脈ごとに統合、Store インターフェースは使う側で定義、合成 Store はルート、永続化は公開フィールド + 規約）
6. モジュールパスは `github.com/u-masato/auth-engine`、リポジトリ名は `auth-engine`
7. ADR-0008 の MCP 連携の 8 点（Resource Server は静的設定、Access Token の形式は resource ごと、MCP Client Profile で `http://localhost` を許可、CIMD はコアの `cimd` パッケージ、Resource Server ミドルウェアはコアの `resourceserver` パッケージ、DCR は実装しない）。M3 着手前に合意
