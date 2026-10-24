package authorization

import "testing"

// RFC 7636 Appendix B のテストベクタ。
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestVerifyS256(t *testing.T) {
	if !VerifyS256(rfcChallenge, rfcVerifier) {
		t.Fatal("RFC 7636 appendix B vector must verify")
	}
	if VerifyS256(rfcChallenge, rfcVerifier[:len(rfcVerifier)-1]+"X") {
		t.Fatal("altered verifier must fail")
	}
	if VerifyS256(rfcChallenge+"=", rfcVerifier) {
		t.Fatal("padded challenge must fail")
	}
	if VerifyS256(rfcChallenge, "") || VerifyS256("", rfcVerifier) {
		t.Fatal("empty values must fail")
	}
	// plain 方式（verifier == challenge）は受け付けない
	if VerifyS256(rfcVerifier, rfcVerifier) {
		t.Fatal("plain method must not verify")
	}
}

func TestValidPKCEStrings(t *testing.T) {
	ok := []string{rfcVerifier, rfcChallenge, string(make43('a')), string(make43('~')) + "-._"}
	for _, s := range ok {
		if !ValidCodeVerifier(s) || !ValidCodeChallenge(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	bad := []string{"", "short", string(make43('a')) + "+", string(make43('a')) + "=", string(make43('a')) + " ", string(make([]byte, 129))}
	for _, s := range bad {
		if ValidCodeVerifier(s) || ValidCodeChallenge(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func make43(ch byte) []byte {
	b := make([]byte, 43)
	for i := range b {
		b[i] = ch
	}
	return b
}
