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
package authengine
