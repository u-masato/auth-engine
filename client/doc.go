// Package client は OAuth 2.0 クライアントの登録情報と、用途別に方針を固定する
// Client Profile を提供する（docs/adr/0004-client-profiles.md）。
//
// 対応する仕様:
//   - RFC 6749 §2 Client Registration、§2.1 Client Types、§3.1.2 Redirection Endpoint、
//     §3.3 Access Token Scope
//   - RFC 7636 PKCE（Profile が S256 を必須にする）
//   - RFC 8252 §7.3 Loopback Interface Redirection（Native の port 無視照合）、
//     §8.3 Loopback Redirect Considerations（localhost ではなく loopback IP リテラルを使う）
//   - RFC 8707 §2 resource indicator（Client が要求できる resource の上限 Resources。MCP では必須）
//   - RFC 9700 §2.1.1 PKCE 必須、§4.1 redirect_uri の完全一致
//   - RFC 7591 §2 クライアントメタデータ（MetadataDocument のフィールド名）
//   - CIMD（draft-ietf-oauth-client-id-metadata-document-02）§3 Client Identifier URL（ParseClientIDURL）、
//     §4 文書の検証と client_id の一致、§4.1 共有シークレットの禁止、§4.2 redirect URI の完全一致（NewMCP）
//   - MCP Authorization Specification（2026-07-28）「Communication Security」（MCP の redirect URI は
//     localhost か https）、「Client Registration」（CIMD の client_name は必須）
//
// 利用者が選べるのは Profile（Web / Native / Machine / MCP）と、Profile が開放する項目だけである。
// grant_types、PKCE の有無、クライアント認証方式、redirect URI の照合規則は Profile が決める。
// MCP Profile（docs/adr/0008-mcp-integration.md §4）は CIMD 文書から NewMCP で組み立て、
// 事前登録なしの Client を cimd.Resolver が解決する。
//
// 永続化の規約（docs/adr/0007-package-layout.md §2）: Client はフィールドを公開した
// 構造体だが、構築は NewWeb / NewNative / NewMachine / NewMCP のみで行い、登録後の変更は Update で行う。
// Adapter から復元した値は Validate で再検証する。
package client
