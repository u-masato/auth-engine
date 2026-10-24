package authorization_test

import (
	"fmt"

	"github.com/muno/auth-engine/authorization"
)

// ExampleVerifyS256 は PKCE の S256 検証（RFC 7636 §4.6）を、RFC 7636 Appendix B の値で確かめる。
// エンジンは plain を受け付けないので、Client は常に BASE64URL(SHA256(code_verifier)) を送る。
func ExampleVerifyS256() {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	fmt.Println(authorization.VerifyS256(challenge, verifier))
	fmt.Println(authorization.VerifyS256(challenge, "wrong-verifier-wrong-verifier-wrong-verifier"))

	// Output:
	// true
	// false
}
