// Package httpapi は Engine を net/http に載せる。
//
// 2 つの http.Handler を提供する（docs/adr/0003-interaction-contract.md §4）。
//
//   - PublicHandler: Client とブラウザが使う公開エンドポイント。
//     GET|POST /authorize、GET /authorize/resume、POST /token、POST /revoke、POST /introspect、
//     GET|POST /userinfo、GET /jwks、GET /.well-known/oauth-authorization-server、
//     GET /.well-known/openid-configuration
//   - InteractionHandler: Interaction App だけが使うバックチャネル API。
//     GET /transactions/{id}、POST /transactions/{id}/complete、POST /transactions/{id}/reject、
//     GET /grants。利用者は内部ネットワーク専用のリスナーに bind することを推奨する。
//
// HTTP 層は薄く保つ。パラメータの取り出し、Cookie、ステータスコードへの写像、JSON の
// 直列化だけを行い、プロトコルの判断はすべて authorization / token の Service に委ねる。
//
// 対応する仕様:
//   - RFC 6749 §2.3.1 Basic 認証、§3.1 GET 必須 / POST 任意、§4.1.2 リダイレクト、
//     §5.1 Cache-Control: no-store、§5.2 エラー応答と WWW-Authenticate
//   - RFC 6750 §3 Bearer の WWW-Authenticate（/userinfo）
//   - RFC 7009 Token Revocation、RFC 7662 Token Introspection
//   - RFC 8414 Authorization Server Metadata、OIDC Discovery 1.0
//   - RFC 9207 iss パラメータ（authorization_response_iss_parameter_supported）
package httpapi
