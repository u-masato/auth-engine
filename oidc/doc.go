// Package oidc は OpenID Connect Core 1.0 のうち、エンジンが担う部分を実装する。
//
//   - ID Token の組立と署名（§2、§3.1.3.6、at_hash は §3.1.3.6 の定義）
//   - scope と Claims の対応（§5.4）と UserInfo の応答（§5.3）
//
// Discovery（OIDC Discovery 1.0）のメタデータは、エンドポイント URL を知っている
// httpapi が組み立てる。
//
// Claims の値はエンジンが生成しない。Interaction App が Complete で渡したスナップショット
// （Grant に保存）を、付与された scope で絞って返すだけである（docs/adr/0006 §3）。
package oidc
