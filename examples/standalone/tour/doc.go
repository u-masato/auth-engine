// Package tour は「境界ツアー」である。Client、auth-engine、Interaction App、Resource Server を
// 1 プロセスで起動し、1 回のログインと業務 API の呼び出しで、どのコンポーネントの間を何が通ったかを
// 図とタイムラインで見せる。cmd/tour が起動する。
//
// 登場するコンポーネント（それぞれ別のポートで待ち受け、HTTP で話す）:
//   - Client（app.go）: Web Profile の confidential クライアント「Notes Web」。トークンはサーバー側の
//     セッションに置き、ブラウザには渡さない。ツアーの画面もここが出す
//   - auth-engine（tour.go）: Engine と httpapi。Store は storage/memory
//   - Interaction App（interaction.go）: ログインと同意の画面。Interaction API をバックチャネルで呼ぶ
//   - Resource Server（notes.go）: 業務 API「Notes API」。resourceserver で Bearer トークンを検証する
//
// やり取りの記録（trace.go）は、各リスナーの入口に置いたミドルウェアと、Store の一部のメソッドを包んだ
// 記録用の Store（store.go）で行う。サーバー間の要求は Tour-From ヘッダで送信元を名乗る。これは図に出す
// ための目印で、プロトコルの一部ではない。
//
// 対応する仕様（各コンポーネントが従うもの。判断の実装は auth-engine と resourceserver にある）:
//   - RFC 6749 §4.1 Authorization Code Grant、§6 Refresh、RFC 7636 PKCE（S256）、RFC 9207 iss の検証
//   - RFC 8707 resource indicator（Access Token の aud を Notes API に絞る）
//   - RFC 6750 Bearer トークン、RFC 9728 Protected Resource Metadata、RFC 9068 JWT Access Token、
//     RFC 7662 Introspection、RFC 7009 Revocation
//   - docs/adr/0003-interaction-contract.md、docs/interaction-api.md（Interaction App との契約）
//
// デモとして省いているもの:
//   - 実際の認証。Interaction App はユーザー名を入力するだけで認証済みとみなし、ログインセッションも
//     持たない（毎回画面を出す）。フォームの CSRF 対策と Txn のセッションへの紐づけもない（loginapp と同じ）
//   - OpenID Connect。ID Token の検証は開発者コンソール（console）が見せているので、ここでは `openid` を
//     要求しない。Client はユーザーが誰かを知らず、Notes API の応答に出る owner で初めて分かる
//   - 永続化。Store もセッションもメモリにあり、再起動で消える
//   - 記録の保護。タイムラインは誰でも見られ、秘密値は読みやすさのために先頭だけを出している
package tour
