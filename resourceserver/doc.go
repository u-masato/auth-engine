// Package resourceserver は、MCP サーバーなどの Resource Server に組み込む net/http ミドルウェアである
// （docs/adr/0008-mcp-integration.md §7）。認可サーバー側のコード（Engine、httpapi）には依存せず、
// 別プロセスの Resource Server から単独で使う。依存は標準ライブラリと keys（JWT 検証）、resource（URI の正規化）だけ。
//
// 提供するもの:
//   - RFC 9728 の Protected Resource Metadata（Protector.MetadataHandler を MetadataPath に mount する）
//   - Bearer トークンの検証ミドルウェア（Protector.Require）。未提示・無効は 401、scope 不足は 403 で、
//     WWW-Authenticate に resource_metadata と必要な scope を載せる
//   - TokenVerifier の 2 実装: IntrospectionVerifier（RFC 7662）と JWTVerifier（RFC 9068 のローカル検証）
//   - 検証済みの主体（Principal）を context から取り出す FromContext
//
// どちらの TokenVerifier でも、Protector は Access Token の aud に自分の resource URI が含まれることを
// 必ず確認する（MCP 仕様「Token Handling」「Access Token Privilege Restriction」）。これを無効にする設定はない。
//
// 対応する仕様:
//   - RFC 9728 §2 メタデータの項目、§3 well-known URI（path を持つ resource は /.well-known/oauth-protected-resource/{path}）、
//     §5.1 WWW-Authenticate の resource_metadata パラメータ
//   - RFC 6750 §2.1 Authorization ヘッダの Bearer、§3 WWW-Authenticate（realm、scope、error、error_description）、
//     §3.1 invalid_token（401）と insufficient_scope（403）
//   - RFC 7662 §2 Introspection の要求と応答（IntrospectionVerifier）
//   - RFC 9068 §4 JWT Access Token の検証（typ=at+jwt、iss、aud、exp、alg の許可リスト）、RFC 8725 §3.1 アルゴリズムの固定
//   - RFC 8414 §3 認可サーバーメタデータの取得（jwks_uri、introspection_endpoint）
//   - RFC 8707 §2 resource indicator（aud の比較は正規形）
//   - MCP Authorization Specification（2026-07-28）「Authorization Server Location」「Scope Selection Strategy」
//     「Runtime Insufficient Scope Errors」「Token Handling」
//
// scope 階層（広い scope が狭い scope を含む）の解釈は Resource Server の方針であり、ミドルウェアは
// Require に与えられた scope がすべてトークンに含まれることだけを見る。
package resourceserver
