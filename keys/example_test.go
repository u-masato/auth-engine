package keys_test

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/u-masato/auth-engine/keys"
)

// jwksSize は JWKS（RFC 7517 §5）に載っている鍵の本数を返す。
func jwksSize(s *keys.Set) int {
	data, err := s.JWKS()
	if err != nil {
		log.Fatal(err)
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwks); err != nil {
		log.Fatal(err)
	}
	return len(jwks.Keys)
}

// ExampleSet_AddSigning は署名鍵のローテーションを示す。
//
//  1. 新しい鍵を AddSigning する。以後の署名は新しい鍵で行い、旧鍵は検証鍵として JWKS に残る。
//     ExportPrivate で保存し直し、全インスタンスに配る。
//  2. 旧鍵で署名したトークンがすべて期限切れになるまで待つ（ID Token の既定は 1 時間）。
//     Client は JWKS をキャッシュするので、新しい鍵での署名も JWKS への掲載より遅らせたいなら、
//     先に AddVerification で公開だけしておき、キャッシュの更新を待ってから AddSigning する。
//  3. 旧鍵を Remove する。
func ExampleSet_AddSigning() {
	set := keys.NewSet()
	old, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := set.AddSigning(old); err != nil {
		log.Fatal(err)
	}
	signedByOld, err := set.Sign(keys.AlgRS256, map[string]any{"sub": "alice"})
	if err != nil {
		log.Fatal(err)
	}

	// 1. 差し替え
	next, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := set.AddSigning(next); err != nil {
		log.Fatal(err)
	}
	current, _ := set.SigningKey(keys.AlgRS256)
	_, verifyErr := set.Verify(signedByOld, &map[string]any{})
	fmt.Println("signs with new key:", current.ID == next.ID, "jwks:", jwksSize(set), "old token verifies:", verifyErr == nil)

	// 差し替えたら書き出し直して保存する。旧鍵も検証鍵として保存され、再起動後も JWKS に残る。
	saved, err := set.ExportPrivate()
	if err != nil {
		log.Fatal(err)
	}
	set, err = keys.ImportPrivate(saved)
	if err != nil {
		log.Fatal(err)
	}
	current, _ = set.SigningKey(keys.AlgRS256)
	fmt.Println("after restart: signs with new key:", current.ID == next.ID, "jwks:", jwksSize(set))

	// 3. 旧鍵を外す
	set.Remove(old.ID)
	_, verifyErr = set.Verify(signedByOld, &map[string]any{})
	fmt.Println("jwks:", jwksSize(set), "old token verifies:", verifyErr == nil)

	// Output:
	// signs with new key: true jwks: 2 old token verifies: true
	// after restart: signs with new key: true jwks: 2
	// jwks: 1 old token verifies: false
}

// ExampleImportPrivate は鍵セットを保存し、再起動後に復元する。
// 鍵がプロセスごとに変わると、発行済みの ID Token を Client が検証できなくなる。
// ExportPrivate の出力は秘密鍵そのものなので、Secret Manager や権限 0600 のファイルなど、
// 利用者の責任で保護した場所に置く。
func ExampleImportPrivate() {
	set := keys.NewSet()
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		k, err := keys.Generate(alg, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		if err := set.AddSigning(k); err != nil {
			log.Fatal(err)
		}
	}
	saved, err := set.ExportPrivate()
	if err != nil {
		log.Fatal(err)
	}

	restored, err := keys.ImportPrivate(saved)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(restored.SigningAlgorithms())

	// Output:
	// [RS256 ES256]
}
