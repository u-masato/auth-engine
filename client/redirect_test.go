package client

import (
	"errors"
	"testing"
)

func TestWebRedirectRegistration(t *testing.T) {
	tests := []struct {
		uri      string
		insecure bool
		ok       bool
	}{
		{"https://app.example.com/cb", false, true},
		{"https://app.example.com/cb?x=1", false, true},
		{"http://app.example.com/cb", false, false},       // https 必須
		{"https://app.example.com/cb#frag", false, false}, // フラグメント禁止（RFC 6749 §3.1.2）
		{"app.example.com/cb", false, false},              // 相対 URI
		{"http://localhost:3000/cb", false, false},        // 既定では http localhost も拒否
		{"http://localhost:3000/cb", true, true},          // 開発用緩和
		{"http://127.0.0.1:3000/cb", true, true},          // 開発用緩和（loopback）
		{"http://192.168.1.10/cb", true, false},           // 緩和しても loopback 以外は拒否
		{"com.example.app:/cb", false, false},             // カスタムスキームは Web では不可
		{"javascript:alert(1)", false, false},
	}
	for _, tt := range tests {
		_, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"}, RedirectURIs: []string{tt.uri}, AllowInsecureLocalhost: tt.insecure}, now)
		if (err == nil) != tt.ok {
			t.Errorf("web %q (insecure=%v): ok=%v, err=%v", tt.uri, tt.insecure, tt.ok, err)
		}
	}
}

func TestNativeRedirectRegistration(t *testing.T) {
	tests := []struct {
		uri      string
		insecure bool
		ok       bool
	}{
		{"http://127.0.0.1/cb", false, true},
		{"http://127.0.0.1:8080/cb", false, true},
		{"http://[::1]/cb", false, true},
		{"http://localhost/cb", false, false}, // RFC 8252 §8.3: 既定で拒否
		{"http://localhost/cb", true, true},
		{"http://192.168.1.10/cb", false, false},
		{"https://app.example.com/cb", false, true}, // クレーム https URL（RFC 8252 §7.2）
		{"com.example.app:/cb", false, true},        // カスタムスキーム（RFC 8252 §7.1）
		{"com.example.app://cb", false, true},
		{"com.example.app:", false, false}, // スキームのみ
		{"https://app.example.com/cb#x", false, false},
		{"data:text/html,x", false, false},
	}
	for _, tt := range tests {
		_, err := NewNative(NativeParams{Name: "n", Scopes: []string{"openid"}, RedirectURIs: []string{tt.uri}, AllowInsecureLocalhost: tt.insecure}, now)
		if (err == nil) != tt.ok {
			t.Errorf("native %q (insecure=%v): ok=%v, err=%v", tt.uri, tt.insecure, tt.ok, err)
		}
	}
}

func TestDuplicateRedirectURIs(t *testing.T) {
	_, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"}, RedirectURIs: []string{"https://a.example/cb", "https://a.example/cb"}}, now)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestResolveRedirectURIWeb(t *testing.T) {
	c, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"}, RedirectURIs: []string{"https://a.example/cb", "https://a.example/cb2"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.ResolveRedirectURI("https://a.example/cb2"); err != nil || got != "https://a.example/cb2" {
		t.Errorf("exact match: %q, %v", got, err)
	}
	// 完全一致のみ。末尾スラッシュ、大文字小文字、クエリの差は不一致。
	for _, bad := range []string{"https://a.example/cb/", "https://A.example/cb", "https://a.example/cb?x=1", "http://a.example/cb", "https://a.example/cb#f", ""} {
		_, err := c.ResolveRedirectURI(bad)
		if bad == "" {
			if !errors.Is(err, ErrRedirectURIRequired) {
				t.Errorf("empty with 2 registered: want ErrRedirectURIRequired, got %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrRedirectURIMismatch) {
			t.Errorf("%q: want ErrRedirectURIMismatch, got %v", bad, err)
		}
	}
}

func TestResolveRedirectURIDefault(t *testing.T) {
	c, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"}, RedirectURIs: []string{"https://a.example/cb"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 6749 §3.1.2.3: 登録が 1 つなら省略可
	if got, err := c.ResolveRedirectURI(""); err != nil || got != "https://a.example/cb" {
		t.Errorf("default: %q, %v", got, err)
	}
}

func TestResolveRedirectURINativeLoopback(t *testing.T) {
	c, err := NewNative(NativeParams{Name: "n", Scopes: []string{"openid"}, RedirectURIs: []string{"http://127.0.0.1/cb", "http://[::1]:9000/cb", "com.example.app:/cb"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{
		"http://127.0.0.1/cb",
		"http://127.0.0.1:51004/cb", // RFC 8252 §7.3: ポート番号は任意
		"http://[::1]:12345/cb",
		"http://[::1]/cb",
		"com.example.app:/cb",
	}
	for _, u := range ok {
		if got, err := c.ResolveRedirectURI(u); err != nil || got != u {
			t.Errorf("%q: got %q, %v", u, got, err)
		}
	}
	bad := []string{
		"http://127.0.0.1/other",        // パス違い
		"http://127.0.0.1:51004/cb?x=1", // クエリ違い
		"https://127.0.0.1/cb",          // スキーム違い
		"http://localhost/cb",           // localhost は loopback IP と同一視しない
		"http://127.0.0.2/cb",           // 別の loopback アドレス（登録と異なるホスト）
		"com.example.app:/cb2",
		"http://user@127.0.0.1/cb",
		"http://127.0.0.1:51004/cb#x", // fragment（RFC 6749 §3.1.2）
		"http://127.0.0.1:51004/cb#",  // 空の fragment も登録時と同じく拒否する
	}
	for _, u := range bad {
		if _, err := c.ResolveRedirectURI(u); !errors.Is(err, ErrRedirectURIMismatch) {
			t.Errorf("%q: want mismatch, got %v", u, err)
		}
	}
}

func TestWebDoesNotIgnoreLoopbackPort(t *testing.T) {
	c, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"}, RedirectURIs: []string{"http://127.0.0.1:3000/cb"}, AllowInsecureLocalhost: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveRedirectURI("http://127.0.0.1:3001/cb"); !errors.Is(err, ErrRedirectURIMismatch) {
		t.Errorf("web profile must require exact port, got %v", err)
	}
}
