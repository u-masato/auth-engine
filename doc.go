// Package authengine は、ヘッドレスな OAuth 2.0 / OpenID Connect 認可サーバー
// 「Protocol Engine」のルートパッケージである。
//
// エンジンはプロトコル処理（/authorize, /token, /userinfo, /jwks, Discovery）と
// Authorization Transaction・Grant・トークンの状態管理だけを担う。
// ログイン・同意 UI とユーザー管理は外部の Interaction App の責務である
// （docs/adr/0003-interaction-contract.md）。
//
// パッケージ構成と依存方向は docs/adr/0007-package-layout.md に従う。
// このルートパッケージは各文脈パッケージの Store インターフェースを合成した
// Store と、全 Service を配線する Engine を提供する。
//
// # 使い方
//
// 組み込む側が用意するものは 4 つある。
//
//   - Store: 永続化 Adapter。adapters/sqlite か adapters/postgres（別モジュール）。
//     storage/memory はテスト専用。
//   - Keys: 署名鍵セット（keys パッケージ）。RS256 の署名鍵を含め、再起動後も同じ鍵を使えるよう保存する。
//   - Client の登録: client.NewWeb / NewNative / NewMachine で作り、Store.CreateClient で登録する。
//   - Interaction App: ログイン・同意画面。docs/interaction-api.md の契約に従って実装する。
//
// MCP 連携（docs/adr/0008-mcp-integration.md）を使うときは、さらに Config.Resources に
// Resource Server（resource パッケージ）を列挙し、事前登録なしの MCP クライアントを受け入れるなら
// Config.CIMD（cimd パッケージ）を与える。Resource Server 側には resourceserver パッケージを組み込む。
//
// New で Engine を組み立て、httpapi.New に渡すと、公開エンドポイント（PublicHandler）と
// Interaction App 向けのバックチャネル（InteractionHandler）の 2 つの http.Handler が得られる。
// 期限切れデータの削除（Store.Purge）は利用者のスケジューラから呼ぶ。
//
// 各パッケージの Example と、組み込みの手順・本番の注意点をまとめた
// docs/embedding.md も参照すること。フロー全体を 1 プロセス内で通す例は
// httpapi パッケージの Example (AuthorizationCodeFlow) にある。
package authengine
