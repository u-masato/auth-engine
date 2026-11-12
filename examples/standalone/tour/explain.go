package tour

import (
	"net/http"
	"strings"
)

// explain は HTTP のやり取りに、何が起きたかの説明と対応する仕様の節を付ける。
// 表示のための文言で、判断はしていない（判断は auth-engine と resourceserver が行う）。
func explain(e *Event) (note, ref string) {
	p := e.Target
	switch e.To {
	case Engine:
		return explainEngine(e, p)
	case Interaction:
		if e.Method == http.MethodPost {
			return "ユーザーが入力したユーザー名と、許可する scope を受け取る。本人確認を行うのはここで、auth-engine は結果だけを受け取る",
				"docs/adr/0003-interaction-contract.md"
		}
		return "txn を受け取り、ログインと同意の画面を出す。この画面は auth-engine の外にある", "docs/adr/0003-interaction-contract.md"
	case ClientApp:
		switch p {
		case "/start":
			return "ボタンが押された。Client は state と PKCE の code_verifier を作り、ブラウザを認可エンドポイントへ送る", "RFC 6749 §4.1.1、RFC 7636 §4.1 / §4.2"
		case "/callback":
			return "認可応答を受け取る。state と iss を確かめてから、Code をトークンに交換する", "RFC 6749 §4.1.2 / §10.12、RFC 9207 §2.4"
		}
		return "ボタンが押された。トークンは Client のサーバー側にあり、ブラウザには渡っていない", ""
	case Resource:
		return explainResource(e, p)
	}
	return "", ""
}

func explainEngine(e *Event, p string) (note, ref string) {
	switch {
	case p == "/authorize":
		return "認可要求（client_id・redirect_uri・scope・PKCE・resource）を検証して Transaction を保存し、ブラウザを Interaction App へ送る",
			"RFC 6749 §4.1.1、RFC 7636 §4.3、RFC 8707 §2"
	case p == "/authorize/resume":
		return "Resume Token と結合 Cookie を確かめ、Authorization Code を付けて Client の redirect_uri へ戻す", "RFC 6749 §4.1.2、RFC 9207 §2"
	case p == "/token":
		if param(e.Request, "grant_type") == "refresh_token" {
			return "Refresh Token を Rotation し、新しい Access Token と Refresh Token を返す。古い Refresh Token はもう使えない", "RFC 6749 §6、RFC 9700 §4.14.2"
		}
		return "Code を 1 回だけ消費し、code_verifier と Client 認証を確かめてトークンを発行する", "RFC 6749 §4.1.3 / §4.1.4、RFC 7636 §4.5 / §4.6"
	case p == "/revoke":
		return "トークンを失効させる。無効なトークンを渡されても 200 を返す", "RFC 7009 §2.1 / §2.2"
	case p == "/introspect":
		return "トークンの状態（active・scope・sub・aud）を返す。失効していれば active=false", "RFC 7662 §2.1 / §2.2"
	case p == "/jwks":
		return "JWT Access Token の署名を確かめるための公開鍵を返す。Resource Server は受け取った鍵を覚えておき、以後は問い合わせない", "RFC 7517 §5、RFC 9068 §4"
	case p == "/.well-known/oauth-authorization-server":
		return "認可サーバーのメタデータ（各エンドポイントの URL）を返す", "RFC 8414 §3"
	case strings.HasSuffix(p, "/complete"):
		return "認証と同意の結果（subject・認証時刻・許可した scope）を受け取り、ブラウザを戻す先の resume_url を返す。Code やトークンは返さない",
			"docs/interaction-api.md、docs/adr/0003-interaction-contract.md §3"
	case strings.HasSuffix(p, "/reject"):
		return "拒否の結果を受け取り、resume_url を返す。Client には OAuth のエラーとして伝わる", "docs/interaction-api.md、RFC 6749 §4.1.2.1"
	case strings.HasPrefix(p, "/transactions/"):
		return "検証済みの認可要求（Client の表示名・scope・resource）を返す。state や code_challenge は渡さない", "docs/interaction-api.md"
	}
	return "", ""
}

func explainResource(e *Event, p string) (note, ref string) {
	if strings.HasPrefix(p, "/.well-known/") {
		return "Protected Resource Metadata（この API を守る認可サーバーと、対応する scope）を返す", "RFC 9728 §3"
	}
	switch {
	case e.Status == http.StatusUnauthorized && param(e.Request, "Authorization") == "":
		return "トークンがないので 401。WWW-Authenticate の resource_metadata で、どこでトークンを得るかを案内する", "RFC 6750 §3、RFC 9728 §5.1"
	case e.Status == http.StatusUnauthorized:
		return "トークンが無効（失効・期限切れ・宛先違いなど）なので 401 invalid_token", "RFC 6750 §3.1"
	case e.Status == http.StatusForbidden:
		return "トークンは有効だが、この操作に必要な scope がないので 403 insufficient_scope", "RFC 6750 §3.1"
	case e.Status >= 200 && e.Status < 300:
		return "Bearer トークンを検証し（iss・exp・aud・scope）、トークンの sub が持つノートだけを扱う。業務データは auth-engine を通らない", "RFC 6750 §2.1、RFC 9068 §4"
	}
	return "業務 API の呼び出し。auth-engine を経由しない", "RFC 6750 §2.1"
}

// param は KV の一覧から名前で値を引く。
func param(kvs []KV, name string) string {
	for _, kv := range kvs {
		if kv.K == name {
			return kv.V
		}
	}
	return ""
}
