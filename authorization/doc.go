// Package authorization は認可エンドポイント（/authorize）の処理を担う。
//
// 認可要求の解析・検証、Authorization Transaction の状態機械、Interaction App との
// 契約（Begin / Complete / Reject / Resume）、PKCE の検証、Authorization Code の発行を
// 1 つの文脈として扱う（docs/adr/0003-interaction-contract.md、docs/adr/0007-package-layout.md）。
//
// 対応する仕様:
//   - RFC 6749 §3.1 Authorization Endpoint、§4.1.1 Authorization Request、
//     §4.1.2 Authorization Response、§4.1.2.1 Error Response
//   - RFC 7636 §4.3 code_challenge の送信、§4.4 サーバー側の保持
//   - RFC 9207 認可レスポンスの iss パラメータ
//   - RFC 9700 §4.1 redirect_uri、§4.7 CSRF 対策（PKCE / state）
//   - OIDC Core §3.1.2.1 Authentication Request（nonce, prompt, max_age, login_hint, ...）、
//     §3.1.2.6 Authentication Error Response
//
// 永続化の規約: Transaction と AuthorizationCode は公開フィールドの構造体だが、
// 構築はこのパッケージの Service が行い、状態遷移は Store.TransitionTransaction の
// CAS で原子的に行う。Status フィールドへの直接代入は Adapter の復元に限る。
package authorization
