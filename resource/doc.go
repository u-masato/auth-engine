// Package resource は Resource Server（RFC 8707 の resource indicator で識別される保護リソース）の
// 静的設定と、認可要求・トークン要求の resource パラメータの正規化を担う
// （docs/adr/0008-mcp-integration.md §1〜§3）。
//
// Resource Server はデプロイ単位で決まり Client のように実行時に増えないため、Store には置かず
// Engine の設定（authengine.Config.Resources）で与える。要求された resource が設定にないものは
// 認可エンドポイントで invalid_target になる（RFC 8707 §2）。
//
// 対応する仕様:
//   - RFC 8707 §2 Resource Parameter（絶対 URI、fragment なし、query は持たないことを推奨）、
//     §2.1 認可要求での resource、§2.2 トークン要求での resource
//   - RFC 3986 §6.2.2.1 Case Normalization（scheme と host の小文字化）
//   - MCP Authorization Specification「Canonical Server URI」（大文字の受理、末尾スラッシュは区別）
//   - RFC 9068 JWT Profile for OAuth 2.0 Access Tokens（AccessTokenFormat が FormatJWT のとき。M3 タスク 3）
//
// このパッケージは他のコアパッケージを import しない葉パッケージである。client と authorization が
// 参照する。
package resource
