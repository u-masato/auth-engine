// Package grant は Grant（ある Client に対してある subject が与えた認可の記録）を扱う。
//
// Grant は client_id × subject につき 1 つで、付与済み scope の和集合と Claims の
// スナップショットを持つ。トークンはすべて Grant に属し、Grant の失効は配下の
// Token Family と全トークンの失効を意味する（docs/adr/0006-tokens-and-token-operations.md）。
//
// Service は Grant の管理操作（同意スキップ判断のための Find、連携済みアプリ一覧の List、
// 連携解除の Revoke）を提供する。プロトコル上の対応物はなく、Go API と Interaction API の
// GET /grants から使う（docs/adr/0006-tokens-and-token-operations.md §5）。
//
// RFC 6749 §1.3 の "authorization grant" は Code などの資格情報を指す用語であり、
// ここでの Grant は OAuth 2.0 Grant Management（FAPI）と同じ「永続的な認可の記録」の意味で使う。
package grant
