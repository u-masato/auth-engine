package tour

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMaskURL(t *testing.T) {
	long := strings.Repeat("a", 40)
	got := maskURL("http://localhost:8100/callback?code=" + long + "&iss=http%3A%2F%2Flocalhost%3A8101&state=xyz")
	want := "http://localhost:8100/callback?code=aaaaaaaaaa…（全 40 文字）&iss=http://localhost:8101&state=xyz"
	if got != want {
		t.Errorf("maskURL:\n got %s\nwant %s", got, want)
	}
	if got := maskURL("http://localhost:8103/login"); got != "http://localhost:8103/login" {
		t.Errorf("a URL without a query must be left as is, got %s", got)
	}
}

func TestShortPath(t *testing.T) {
	for in, want := range map[string]string{
		"/transactions/abcdefghijkl":          "/transactions/abcdef…",
		"/transactions/abcdefghijkl/complete": "/transactions/abcdef…/complete",
		"/transactions/abc":                   "/transactions/abc",
		"/authorize/resume":                   "/authorize/resume",
	} {
		if got := shortPath(in); got != want {
			t.Errorf("shortPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Observe は送信元を Tour-From で見分け、本文を読んだ後も next が同じ本文を読めるようにする。
func TestObserveKeepsBodyAndRecordsBothSides(t *testing.T) {
	rec := &Recorder{}
	rec.StartStep("テスト")
	secret := strings.Repeat("s", 43)
	h := rec.Observe(Engine, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("code_verifier") != secret {
			t.Errorf("the handler must still see the form: %v %v", err, r.PostForm)
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": secret, "scope": "notes:read"})
	}))
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code_verifier": {secret}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(fromHeader, string(ClientApp))
	h.ServeHTTP(httptest.NewRecorder(), req)

	steps := rec.Steps()
	if len(steps) != 1 || len(steps[0].Events) != 1 {
		t.Fatalf("one event must be recorded: %+v", steps)
	}
	e := steps[0].Events[0]
	if e.From != ClientApp || e.To != Engine || e.Status != http.StatusOK || e.Index != 1 || e.Note == "" {
		t.Errorf("event: %+v", e)
	}
	if v := param(e.Request, "code_verifier"); v == secret || !strings.HasPrefix(v, "ssssssssss…") {
		t.Errorf("code_verifier must be abbreviated, got %q", v)
	}
	if body := param(e.Response, "body"); strings.Contains(body, secret) || !strings.Contains(body, `"scope": "notes:read"`) {
		t.Errorf("the response body must be recorded with the token abbreviated, got %s", body)
	}

	// 名乗らない要求はブラウザから、知らない名前も信用せずブラウザからとみなす
	req = httptest.NewRequest(http.MethodGet, "/jwks", nil)
	req.Header.Set(fromHeader, "store")
	rec.Observe(Engine, http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), req)
	if e := rec.Steps()[0].Events[1]; e.From != Browser || !e.Failed {
		t.Errorf("event: %+v", e)
	}
}
