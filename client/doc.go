// Package client は OAuth 2.0 クライアントの登録情報と、用途別に方針を固定する
// Client Profile を提供する（docs/adr/0004-client-profiles.md）。
//
// 対応する仕様:
//   - RFC 6749 §2 Client Registration、§2.1 Client Types、§3.1.2 Redirection Endpoint、
//     §3.3 Access Token Scope
//   - RFC 7636 PKCE（Profile が S256 を必須にする）
//   - RFC 8252 §7.3 Loopback Interface Redirection（Native の port 無視照合）、
//     §8.3 Loopback Redirect Considerations（localhost ではなく loopback IP リテラルを使う）
//   - RFC 8707 §2 resource indicator（Client が要求できる resource の上限 Resources）
//   - RFC 9700 §2.1.1 PKCE 必須、§4.1 redirect_uri の完全一致
//
// 利用者が選べるのは Profile（Web / Native / Machine）と、Profile が開放する項目だけである。
// grant_types、PKCE の有無、クライアント認証方式、redirect URI の照合規則は Profile が決める。
//
// 永続化の規約（docs/adr/0007-package-layout.md §2）: Client はフィールドを公開した
// 構造体だが、構築は NewWeb / NewNative / NewMachine のみで行い、Adapter から復元した値は
// Validate で再検証する。
package client
