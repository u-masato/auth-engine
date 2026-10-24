// Package e2e は、SQLite Adapter・HTTP 層・デモ Interaction App・サンプルクライアントを
// 実際の HTTP サーバー（httptest）で結合し、Authorization Code + PKCE のフローを端から端まで
// 検証する。コアモジュールからは Adapter を import できない（依存の向きが逆になる）ため、
// 別モジュールにしている。
//
// e2e_test.go は M1 のフロー（Web / Native、拒否、別ブラウザからの Resume、期限切れ）、
// lifecycle_test.go は M2 のトークンライフサイクル（公開 JWKS での ID Token 検証、UserInfo、
// Refresh Rotation、Revocation、Introspection、client_credentials、prompt=none のセッション判定）を扱う。
package e2e
