package rand

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestToken(t *testing.T) {
	tok, err := Token("at_")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "at_") {
		t.Fatalf("prefix missing: %q", tok)
	}
	raw := strings.TrimPrefix(tok, "at_")
	if len(raw) != 43 {
		t.Fatalf("want 43 chars of base64url, got %d", len(raw))
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != TokenBytes {
		t.Fatalf("want %d bytes, got %d", TokenBytes, len(b))
	}

	other, _ := Token("at_")
	if other == tok {
		t.Fatal("two tokens must differ")
	}
}

func TestHash(t *testing.T) {
	h := Hash("secret")
	if len(h) != 64 {
		t.Fatalf("want 64 hex chars, got %d", len(h))
	}
	if h != Hash("secret") {
		t.Fatal("hash must be deterministic")
	}
	if !HashEqual(h, "secret") {
		t.Fatal("HashEqual must accept the original secret")
	}
	if HashEqual(h, "Secret") {
		t.Fatal("HashEqual must reject a different secret")
	}
	if HashEqual("", "secret") {
		t.Fatal("HashEqual must reject an empty stored hash")
	}
}
