package httpapi

import (
	"net/http"

	"github.com/muno/auth-engine/internal/rand"
)

// ブラウザ結合 Cookie（ADR-0003 §3）。
//
// /authorize でブラウザに発行し、Resume で同じブラウザからの要求であることを確認する。
// 1 ブラウザに 1 つで、複数の Transaction を並行して進めてもよい。
const (
	bindingCookieSecure   = "__Host-ae_bind"
	bindingCookieInsecure = "ae_bind"
	bindingCookieMaxAge   = 24 * 60 * 60 // 1 日。Transaction の上限（1 時間）より十分長い
)

func (s *Server) bindingCookieName() string {
	if s.cfg.InsecureCookies {
		return bindingCookieInsecure
	}
	return bindingCookieSecure
}

// browserBinding は既存の結合 Cookie を返し、なければ新規に発行して応答にセットする。
func (s *Server) browserBinding(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(s.bindingCookieName()); err == nil && c.Value != "" {
		return c.Value, nil
	}
	v, err := rand.Token("")
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.bindingCookieName(),
		Value:    v,
		Path:     "/",
		MaxAge:   bindingCookieMaxAge,
		HttpOnly: true,
		Secure:   !s.cfg.InsecureCookies,
		SameSite: http.SameSiteLaxMode, // Resume は top-level GET なので Lax で送られる
	})
	return v, nil
}
