# コントリビューションガイド

auth-engine に関心を持ってくれてありがとうございます。このプロジェクトは「他者の参考実装になるわかりやすさ」を品質目標にしています。性能や機能の網羅より、コードから仕様との対応が読めることを優先します。変更もこの目標に沿って判断します。

脆弱性は issue に書かず、[SECURITY.md](SECURITY.md) の非公開の経路で報告してください。参加者には [行動規範](CODE_OF_CONDUCT.md) を守ってもらいます。

## 歓迎するもの

- **仕様との食い違いの指摘。** どの仕様のどの節に反するかを書いてください（例: RFC 6749 §4.1.2.1、OIDC Core §3.1.2.1）。
- **相互運用の報告。** 実在するクライアント・Resource Server・MCP クライアントと組み合わせて、通った・通らなかったという報告。通らなかった場合はやり取り（機密値は伏せる）を添えてください。
- **バグ報告と再現テスト。** 失敗するテストだけの Pull Request も歓迎します。
- **文書の改善。** 文書はすべて日本語です。識別子と RFC の用語は原文のまま書きます。
- **Store Adapter。** `storage/storagetest` の契約テストを通すことが条件です。新しい Adapter は別モジュールにします（[ADR-0007](docs/adr/0007-package-layout.md)）。

## 受け付けないもの

次は設計上の判断です（[ADR-0001](docs/adr/0001-scope-and-principles.md)、[README の「意図した制約」](README.md#意図した制約)）。変えたい場合は、実装より先に issue で設計の議論を始めてください。

- PKCE なしの Authorization Code Grant、`plain`、Implicit Grant、Password Grant、Dynamic Client Registration
- Client Profile を迂回する個別設定や Custom Profile
- コアモジュールへの go-jose/v4 以外の外部依存（DB ドライバー、Web フレームワーク、OpenTelemetry など）
- 管理 GUI、マルチテナント

## 設計を変えるときは ADR から

設計判断は [docs/adr/](docs/adr/) に ADR（Architecture Decision Record）として残しています。索引は [docs/README.md](docs/README.md) です。

- 次の不変条件を変える変更は、ADR の追加か修正を伴います。Pull Request より先に issue で合意を取ってください。
  - コアの外部依存は go-jose/v4 だけ
  - Store の各メソッドは単体で原子的。Port にトランザクション抽象を置かない
  - 秘密値（Code、トークン、Resume Token、Client Secret）は 256 bit 乱数で、保存は SHA-256 ハッシュだけ。比較は定数時間
  - 状態遷移は fail-closed（Resume は CAS で消費してから Code を作る、Code 交換は先に消費して失敗しても戻さない）
- 作業の順序は [ロードマップ](docs/roadmap.md) に沿います。大きな機能は、ロードマップのタスクに対応させてから着手してください。
- HTTP の形を変えたら [Interaction API 仕様](docs/interaction-api.md) を、`Config` や公開 API を変えたら [組み込みガイド](docs/embedding.md) と各パッケージの `example_test.go` を直します。

## 開発環境

- Go 1.26 以上。モジュールはリポジトリ直下の `go.work` で束ねています。
- PostgreSQL Adapter のテストには Docker が要ります（Testcontainers）。Docker がなければ Skip されます。`AUTH_ENGINE_POSTGRES_DSN` で既存の DB を指すこともできます。

```bash
make vet test        # 全モジュールで go vet + go test -race（Fuzz の seed も回る）
make lint            # gofmt、go 指示子、staticcheck、govulncheck、コアの依存検査
make fuzz FUZZTIME=30s   # コアの Fuzz テストを 1 ターゲットずつ
(cd examples/standalone && go run ./cmd/server -db ./auth.db)   # デモを起動して手で確かめる
```

`go mod tidy` は `go.mod` の `go` 指示子を手元の Go に合わせて上げることがあります。最低バージョンは Go 1.26 のままにしてください（`make lint` の `go-directive-check` が検出します）。

## コードの書き方

- パッケージはレイヤーではなく文脈（`client` `authorization` `grant` `token` など）で切ります。ファイルは概念ごと、1 ユースケース 1 ファイルです。
- コメントは日本語で書き、判断には対応する仕様の節番号を添えます（`// RFC 6749 §4.1.2.1`）。各パッケージの `doc.go` に対応仕様を列挙します。
- エラーは各パッケージのセンチネルを `errors.Is` で判別します。プロトコルエラーは `authorization.Error` / `token.Error`、内部障害は通常の `error` で返します。
- HTTP 層（`httpapi`）は薄く保ちます。プロトコルの判断は Service に書きます。
- `storage/memory` を使うテストは外部テストパッケージ（`package xxx_test`）に置きます。

## テスト

- 変更には、仕様の節に対応する正常系と異常系のテストを付けてください。
- Store の振る舞いを変えたら `storage/storagetest` の契約テストを足し、memory / SQLite / PostgreSQL のすべてで通します。
- 外部入力を解析・照合する関数を足したら、そのパッケージの `fuzz_test.go` に Fuzz テストを足します。「パニックしない」だけでなく、受理した値が仕様の条件を満たすことを確かめてください。
- 並行性のテスト（Code の同時交換など）は、不安定さを疑ったら `-count=3` で回してください。

## コミットと Pull Request

- 1 つの Pull Request には 1 つの目的だけを入れます。
- コミットメッセージは `type(scope): 要約` の形にします。ロードマップのタスクなら番号を入れます（例: `feat(token): M2タスク4 ...`、`fix(client): ...`、`docs: ...`）。本文には何を・なぜを箇条書きで書きます。
- Pull Request のテンプレートのチェックリストを埋めてください。CI（vet、test、lint）が通っていることが前提です。

## ライセンス

このリポジトリは [Apache License 2.0](LICENSE) です。Pull Request として送った貢献は、同ライセンスの第 5 条に従い Apache License 2.0 の下で提供されたものとして扱います。
