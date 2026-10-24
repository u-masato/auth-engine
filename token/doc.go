// Package token は Access Token / Refresh Token の発行・交換・Rotation と、
// それらをまとめる Token Family を扱う。
//
// Token Family は Code 交換 1 回ごとに作られ、Refresh Token の Rotation はその中で連鎖する。
// Rotation 済みの Refresh Token が再提示されたら Family 全体を失効させる
// （RFC 9700 §4.14.2）。Code が再利用されたら、その Code から作られた Family を失効させる
// （RFC 6749 §4.1.2）。
//
// Access Token は Opaque（ADR-0006 §1）。平文は発行時にのみ返し、保存は SHA-256 の Hash のみ。
//
// Refresh Token は Family 作成からの絶対期限（既定 30 日）と最終使用からのスライド期限
// （既定 14 日）を持つ。Rotation のたびに後継のスライド期限は延びるが絶対期限は超えない。
//
// ファイル構成: service.go（Exchange の入口と authorization_code）、refresh.go（refresh_token）、
// clientcredentials.go（client_credentials）、clientauth.go（クライアント認証）。
//
// 対応する仕様:
//   - RFC 6749 §2.3 Client Authentication、§4.1.3 Access Token Request、
//     §4.1.4 Access Token Response、§4.4 Client Credentials Grant、§5.1 Successful Response、
//     §5.2 Error Response、§6 Refreshing an Access Token
//   - RFC 6750 §4 Bearer Token の返却形式
//   - RFC 7636 §4.5 code_verifier の送信、§4.6 サーバー側の検証
//   - RFC 9700 §4.14 Refresh Token Protection（Rotation と再利用検知）
//   - OIDC Core §12 Using Refresh Tokens（Refresh 応答の ID Token）
package token
