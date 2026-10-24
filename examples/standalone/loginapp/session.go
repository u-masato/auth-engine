package loginapp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"time"
)

// sessionCookie はこの App のログインセッション。デモなので署名せず、subject と認証時刻を
// base64url の JSON で持つ。本番の Interaction App は自前のセッション機構に置き換えること。
const sessionCookie = "loginapp_session"

type session struct {
	Subject         string    `json:"sub"`
	AuthenticatedAt time.Time `json:"auth_time"`
}

func readSession(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var s session
	if err := json.Unmarshal(raw, &s); err != nil || s.Subject == "" || s.AuthenticatedAt.IsZero() {
		return nil
	}
	return &s
}

func writeSession(w http.ResponseWriter, s session) {
	raw, _ := json.Marshal(s)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: base64.RawURLEncoding.EncodeToString(raw),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 24 * 60 * 60,
	})
}

// decision は prompt / max_age と既存セッションから決めた認証の扱い。
type decision struct {
	// Reject が空でなければ、この error コードで Reject する（prompt=none でログインが必要な場合）。
	Reject string
	// Fresh は新しく認証し直すか（prompt=login、max_age 超過、セッションなし）。
	Fresh bool
	// Session は再利用する既存セッション。Fresh なら nil。
	Session *session
}

// decide は OIDC Core §3.1.2.1 の prompt と max_age を解釈する。エンジンはこれらを解釈せず
// Interaction App に委ねる（docs/interaction-api.md）ので、ここが唯一の判断点になる。
func decide(r *http.Request, txn *Transaction, now time.Time) decision {
	sess := readSession(r)
	fresh := sess == nil || slices.Contains(txn.Request.Prompt, "login")
	if sess != nil && txn.Request.MaxAge != nil && now.Sub(sess.AuthenticatedAt) > time.Duration(*txn.Request.MaxAge)*time.Second {
		fresh = true
	}
	if slices.Contains(txn.Request.Prompt, "none") && fresh {
		return decision{Reject: "login_required"}
	}
	if fresh {
		return decision{Fresh: true}
	}
	return decision{Session: sess}
}
