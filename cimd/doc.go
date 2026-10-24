// Package cimd は、CIMD（Client ID Metadata Document）の URL を client_id とする MCP クライアントを
// 事前登録なしに解決する client.Resolver 実装である（docs/adr/0008-mcp-integration.md §5）。
//
// 対応する仕様（CIMD は draft-ietf-oauth-client-id-metadata-document-02 の節番号）:
//   - CIMD §3 Client Identifier URL（判定は client.ParseClientIDURL。満たさない client_id は storage.ErrNotFound）
//   - CIMD §4 文書の検証（client.NewMCP に委ねる）、§4.1 共有シークレットの禁止
//   - CIMD §5 文書の取得（GET、Accept: application/json、リダイレクト非追従、200 以外はエラー）、
//     §5.1 取得エラー時は認可要求を中断、§5.2 キャッシュ（Cache-Control を尊重、上下限、エラーと不正な文書はキャッシュしない）
//   - CIMD §6 Authorization Server Metadata の client_id_metadata_document_supported（httpapi が Resolver の有無で載せる）
//   - CIMD §8.6 SSRF 対策（RFC 6890 の特殊用途アドレスへ接続しない。loopback は開発用 AllowLoopback のみ）、
//     §8.7 応答サイズの上限（既定 5 KB）、§8.9 client_id のドメインに対する信頼ポリシー（TrustPolicy）
//   - RFC 6890 Special-Purpose IP Address Registries（拒否するアドレス範囲の根拠）
//   - RFC 9111 §5.2.2.1 Cache-Control: max-age
//   - MCP Authorization Specification（2026-07-28）「Client Registration」「Trust Policies」
//
// 設計上の要点:
//   - 外部へ接続するコアのコードはこのパッケージだけである。既定の http.Transport は名前解決後の
//     接続先アドレスを net.Dialer.Control で検査し、特殊用途アドレスへの接続を拒む（TOCTOU がない）。
//   - 解決できない失敗は client.ErrUnresolvable で返し、呼び出し側（authorization / token）が
//     理由付きのプロトコルエラーに写す。client_id の形式が CIMD でないときだけ storage.ErrNotFound。
//   - キャッシュはプロセス内メモリ。複数インスタンスでの共有は M3 の範囲外（roadmap「M3 で明示的に先送りするもの」）。
package cimd
