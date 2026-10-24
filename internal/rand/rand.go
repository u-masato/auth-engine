// Package rand は、トークン・識別子として使う暗号学的乱数の生成と、
// 保存用ハッシュの計算を提供する。
//
// エンジンが発行する秘密値（Authorization Code、Access Token、Refresh Token、
// Resume Token、Client Secret）はすべてここで生成し、保存時は SHA-256 ハッシュのみを
// 残す（docs/adr/0005-storage-port.md §5）。元値が 256 bit の乱数なのでソルトは不要である。
package rand

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// TokenBytes は Token が生成する乱数のバイト長（256 bit）。
const TokenBytes = 32

// Token は 256 bit の乱数を base64url（パディングなし、43 文字）で返す。
// prefix は "at_" のような識別用接頭辞で、ログやシークレットスキャナでの
// 種別判定に使う。空でもよい。
func Token(prefix string) (string, error) {
	b, err := Bytes(TokenBytes)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Bytes は n バイトの暗号学的乱数を返す。
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return b, nil
}

// Hash は保存用のハッシュ（SHA-256 の 16 進表現、64 文字）を返す。
// Adapter はこの値をキーに検索する。
func Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// HashEqual は、提示された秘密値のハッシュが保存済みハッシュと一致するかを
// 定数時間で比較する。
func HashEqual(storedHash, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(Hash(presented))) == 1
}
