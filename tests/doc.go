// Package e2e は、SQLite Adapter・HTTP 層・デモ Interaction App・サンプルクライアントを
// 実際の HTTP サーバー（httptest）で結合し、Authorization Code + PKCE のフローを端から端まで
// 検証する。コアモジュールからは Adapter を import できない（依存の向きが逆になる）ため、
// 別モジュールにしている。
package e2e
