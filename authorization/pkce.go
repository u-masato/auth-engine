package authorization

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// CodeChallengeMethodS256 は唯一サポートする code_challenge_method（RFC 7636 §4.2、RFC 9700 §2.1.1）。
// "plain" は受け付けない。
const CodeChallengeMethodS256 = "S256"

// ValidCodeVerifier は code_verifier が RFC 7636 §4.1 の構文
// （43〜128 文字の unreserved 文字 [A-Za-z0-9-._~]）に従うかを返す。
func ValidCodeVerifier(s string) bool { return validPKCEString(s) }

// ValidCodeChallenge は code_challenge が RFC 7636 §4.2 の構文に従うかを返す。
// S256 の値は base64url（パディングなし）の 43 文字で、unreserved 文字の部分集合である。
func ValidCodeChallenge(s string) bool { return validPKCEString(s) }

func validPKCEString(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9',
			ch == '-', ch == '.', ch == '_', ch == '~':
		default:
			return false
		}
	}
	return true
}

// VerifyS256 は BASE64URL(SHA256(code_verifier)) == code_challenge を定数時間で検証する
// （RFC 7636 §4.6）。
func VerifyS256(challenge, verifier string) bool {
	if !ValidCodeVerifier(verifier) || !ValidCodeChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
