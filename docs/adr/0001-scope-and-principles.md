# ADR-0001: スコープと設計原則

- 状態: 採用（2026-10-24 合意）
- 日付: 2026-10-24

## 文脈

ヘッドレスな OAuth 2.0 / OpenID Connect 認可サーバー「Protocol Engine」を Go で OSS として作る。
ログイン・同意 UI、ユーザー管理、業務固有の権限判断は外部アプリケーション（以下「Interaction App」）の責務とし、本体はプロトコル処理と Grant・トークンの状態管理に専念する。
品質目標は「ロジックがわかりやすく、他者の参考実装になること」である。性能や機能網羅性より、仕様との対応関係が読み取れることを優先する。

準拠対象の仕様は [rfcs.md](../../rfcs.md) の P0〜P3 の段階分けに従う。

## 決定

### 1. 本体が持つもの・持たないもの

| 本体（Protocol Engine）が持つ | 外部（Interaction App / 利用者）が持つ |
| --- | --- |
| `/authorize` `/token` `/userinfo` `/jwks` Discovery の各エンドポイント | ログイン画面、同意画面、エラー画面の描写 |
| Authorization Transaction / Code / Grant / Token の状態遷移と不変条件 | ユーザー DB、パスワード・MFA・パスキーなどの認証手段 |
| Client の登録情報と Client Profile による方針の固定 | 「誰が」「何に同意したか」を決める判断 |
| 署名鍵の管理と ID Token の発行 | ID Token / UserInfo に載せる Claims の中身 |
| Interaction App との契約（ADR-0003） | Interaction App 自身のセッション管理 |

本体はユーザーの存在を知らない。本体にとって `subject` は Interaction App が主張してきた不透明な文字列である。

### 2. 設計原則

1. **仕様との対応が読めること。** パッケージ・型・関数名は RFC / OIDC の用語をそのまま使う。実装の各判断には対応する仕様の節番号をコメントで示す。
2. **「選ばせない」こと。** 利用者に RFC の個別設定を選ばせず、Client Profile（ADR-0004）で安全側に固定する。RFC 9700（OAuth 2.0 Security BCP）が禁止・非推奨とする選択肢は設定項目として存在させない。
3. **不変条件は保存層が保証すること。** Authorization Code の単回使用、Refresh Token Rotation、Grant 失効とトークン発行の整合性は、Storage Port の操作単位で原子性を保証する（ADR-0005）。In-Memory Store だけで安全性を確認したと見なさない。
4. **コアの依存を最小にすること。** コアモジュールの外部依存は JOSE ライブラリのみとし、DB ドライバーや Web フレームワークはコアから参照しない（ADR-0002, ADR-0007）。
5. **拡張はコアに混ぜないこと。** MCP 向け拡張（Resource Indicators、CIMD、DPoP 等）は、コアの状態遷移を変更せずに追加できる形で設計する。P0 の実装中であっても、P1 以降で必要になる拡張点は「存在だけ」確保する。

### 3. 初期リリース（P0）で提供しないもの

- Implicit Grant、Resource Owner Password Credentials Grant、Hybrid Flow（RFC 9700 §2.1.2, §2.4）
- PKCE を使わない Authorization Code Grant（RFC 9700 §2.1.1）
- `plain` の `code_challenge_method`
- Dynamic Client Registration（P1 で CIMD と併せて検討）
- 管理 GUI、マルチテナント、独自プラグイン実行環境
- 任意トークンの Mint / Reissue（ADR-0006 で却下理由を記述）

## 影響

- 「参考実装」であることを優先するため、スループット最適化（キャッシュ層、非同期書き込み等）は原則として行わない。
- 「選ばせない」方針の結果、PKCE 非対応のレガシークライアントは接続できない。これは意図した制約として README に明記する。
