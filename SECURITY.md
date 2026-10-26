# セキュリティ方針

auth-engine は認可サーバーなので、脆弱性はそのまま利用者のサービスの認可の破れになります。見つけたら、公開の issue や Pull Request ではなく、以下の非公開の経路で知らせてください。

## 報告のしかた

GitHub の **Private vulnerability reporting** を使います。

1. リポジトリの **Security** タブを開く
2. **Report a vulnerability** から報告を作る

報告には、わかる範囲で次を書いてください。

- 影響を受けるパッケージ・エンドポイント・Adapter と、コミット（またはタグ）
- 関係する仕様と節番号（例: RFC 6749 §4.1.2.1、RFC 9700 §4.1.3、CIMD §3）
- 再現手順。最小のテストコードや HTTP のやり取りがあると早く直せます
- 想定される影響（Code・トークンの漏洩、Client のなりすまし、オープンリダイレクトなど）

## 対応の流れ

| 段階 | 目安 |
| --- | --- |
| 受け取りの連絡 | 3 営業日以内 |
| 再現と深刻度の評価（CVSS v4） | 7 日以内 |
| 修正の公開 | 深刻度に応じて。報告から 90 日以内を上限に、公開日を報告者と調整する |

修正は GitHub Security Advisory として公開し、必要なら CVE を採番します。報告者の希望に応じて Advisory にクレジットを載せます。

## 対象

| 対象 | 扱い |
| --- | --- |
| コアモジュール（`github.com/u-masato/auth-engine` の全パッケージ） | 対象 |
| `adapters/sqlite`、`adapters/postgres` | 対象 |
| `examples/standalone`（デモサーバー、デモのログイン画面、開発者コンソール） | 対象外。本番用ではない。ただし、デモの設定や文書が本番で危険な使い方へ誘導している場合は報告を歓迎する |
| `tests`、`conformance` | 対象外 |

## サポートするバージョン

1.0 より前は、`main` の最新コミットだけを修正します。過去のコミットへのバックポートはしません。リリースタグを打ち始めたら、この表を更新します。

| バージョン | 修正の対象 |
| --- | --- |
| `main` の最新 | ○ |
| それ以前 | × |

## 脆弱性として扱わないもの

次は [README の「意図した制約」](README.md#意図した制約) に書いた設計上の判断で、脆弱性ではありません。変えたい場合は issue で設計の議論として提案してください。

- PKCE（S256）を使わない Authorization Code Grant、Implicit Grant、Password Grant、Dynamic Client Registration を受け付けないこと
- JWT Access Token の失効が `exp` まで Resource Server に伝わらないこと（Opaque を既定にし、JWT は resource ごとに選ぶ設計。[ADR-0008](docs/adr/0008-mcp-integration.md) §3）
- レート制限を持たないこと。前段のリバースプロキシで行う前提（[組み込みガイド](docs/embedding.md) §9）
- 組み込みガイドの「本番に出す前の確認」に反する設定（`AllowInsecureIssuer`、`InsecureCookies`、`storage/memory` など）で起きる問題

## 組み込む人へ

本番に出す前に [組み込みガイド](docs/embedding.md) の §9「本番に出す前の確認」を通してください。Interaction App を実装する場合は、[Interaction API 仕様](docs/interaction-api.md) の「守ってほしいこと」も満たしてください。
