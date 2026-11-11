package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
)

// clientRow は一覧の 1 行。
type clientRow struct {
	Client *client.Client
	// Usable は、コンソールからこの Client のフローを実行できるか（Machine は常に実行できる。
	// それ以外はコンソールの redirect URI が登録されていること）。
	Usable bool
}

type clientsPage struct {
	Layout layout
	Rows   []clientRow
	// After はこのページの開始位置（空なら先頭）、Next は次のページの開始位置（なければ空）。
	After, Next string
	Notice      string
	Flows       []flowSummary // 直近のフロー
}

// recentFlows は一覧画面に出す直近のフローの件数。
const recentFlows = 5

// handleClients は Client の一覧（ダッシュボードのトップ）。Store.ListClients のキーセットページングを
// そのまま使い、次のページは最後の client_id を after に渡して読む。
func (a *App) handleClients(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// 「client_id を指定して開く」。一覧をたどらずに詳細へ行く
	if id := strings.TrimSpace(q.Get("open")); id != "" {
		http.Redirect(w, r, clientPath(id), http.StatusSeeOther)
		return
	}
	after := q.Get("after")
	// 次のページがあるかを知るために 1 件多く読む
	cs, err := a.cfg.Store.ListClients(r.Context(), after, a.cfg.PageSize+1)
	if err != nil {
		a.logger.Error("console: list clients", "error", err)
		a.renderError(w, http.StatusInternalServerError, "一覧を取得できない: "+err.Error())
		return
	}
	p := clientsPage{Layout: a.layout("クライアント", "clients"), After: after}
	if len(cs) > a.cfg.PageSize {
		cs = cs[:a.cfg.PageSize]
		p.Next = cs[len(cs)-1].ID
	}
	for _, c := range cs {
		p.Rows = append(p.Rows, clientRow{Client: c, Usable: a.usable(c)})
	}
	if id := q.Get("deleted"); id != "" {
		p.Notice = "client_id " + id + " を削除した。この Client の Grant とトークンはすべて失効している。"
	}
	p.Flows = a.flowSummaries(recentFlows)
	a.render(w, "clients", p, http.StatusOK)
}

// usable は、コンソールからこの Client のフローを実行できるかを返す。
// redirect URI の照合はエンジンと同じ規則（client.Client.ResolveRedirectURI。loopback のポート無視を含む）で行う。
func (a *App) usable(c *client.Client) bool {
	if c.Profile == client.ProfileMachine {
		return true
	}
	_, err := c.ResolveRedirectURI(a.RedirectURI())
	return err == nil
}

// ruleRow は Profile が固定する項目の 1 行（docs/adr/0004-client-profiles.md §1）。
type ruleRow struct{ Name, Value, Ref string }

// profileRules は Client の Profile が固定する項目を、公開メソッドから読み取って並べる。
// 利用者が変えられるのは Profile が開放する項目だけで、ここに出るものは登録後も変えられない。
func profileRules(c *client.Client) []ruleRow {
	kind := "confidential（シークレットを保持できる）"
	if c.IsPublic() {
		kind = "public（シークレットを保持できない）"
	}
	var grants, auth []string
	for _, gt := range []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken, client.GrantClientCredentials} {
		if c.Allows(gt) {
			grants = append(grants, string(gt))
		}
	}
	for _, m := range []client.AuthMethod{client.AuthClientSecretBasic, client.AuthClientSecretPost, client.AuthNone} {
		if c.AcceptsAuthMethod(m) {
			auth = append(auth, string(m))
		}
	}
	yesNo := func(b bool, yes, no string) string {
		if b {
			return yes
		}
		return no
	}
	rows := []ruleRow{
		{"クライアント種別", kind, "RFC 6749 §2.1"},
		{"grant_type", strings.Join(grants, "、"), "RFC 6749 §4 / §6"},
		{"クライアント認証", strings.Join(auth, "、"), "RFC 6749 §2.3"},
	}
	if c.Allows(client.GrantAuthorizationCode) {
		rows = append(rows, ruleRow{"PKCE", yesNo(c.RequiresPKCE(), "必須（S256）", "任意"), "RFC 7636、RFC 9700 §2.1.1"})
	}
	return append(rows,
		ruleRow{"Refresh Token", yesNo(c.IssuesRefreshToken(), "発行する（使うたびに Rotation）", "発行しない"), "RFC 9700 §4.14"},
		ruleRow{"ID Token", yesNo(c.IssuesIDToken(), "openid を付与したときに発行する", "発行しない"), "OIDC Core §3.1.3.3"},
		ruleRow{"resource", yesNo(c.RequiresResource(), "認可要求に必須", "任意"), "RFC 8707 §2"},
	)
}

type clientPage struct {
	Layout layout
	Client *client.Client
	Rules  []ruleRow
	// Secret はコンソールが知っている Client Secret の平文。知らなければ空。
	Secret string
	Notice string
	Usable bool
	// CodeFlow は認可エンドポイントを経由するフローを使う Client か（Machine 以外）。
	CodeFlow bool
	Scope    string // 開始フォームの初期値

	// Grants はこの Client に対する Grant の 1 ページ分（Subject の昇順、失効済みも含む）。
	Grants []*grant.Grant
	// GrantsAfter はこのページの開始位置（空なら先頭）、GrantsNext は次のページの開始位置（なければ空）。
	GrantsAfter, GrantsNext string
}

// handleClient は Client の詳細。Profile が固定する項目と開放項目を分けて見せ、ここからフローを開始する。
func (a *App) handleClient(w http.ResponseWriter, r *http.Request) {
	c, ok := a.findClient(w, r)
	if !ok {
		return
	}
	// コンソールの外（管理 API など）で再発行されていたら、覚えている平文はもう使えない。
	// 古い値を表示して開始フォームに入れないよう、Store のハッシュと合わなければ捨てる。
	if s := a.knownSecret(c.ID); s != "" && !c.VerifySecret(s) {
		a.forgetSecret(c.ID)
	}
	q := r.URL.Query()
	p := clientPage{Layout: a.layout(c.Name, "clients"), Client: c, Rules: profileRules(c),
		Secret: a.knownSecret(c.ID), Usable: a.usable(c), CodeFlow: c.Allows(client.GrantAuthorizationCode),
		Scope: strings.Join(c.Scopes, " "), GrantsAfter: q.Get("grants_after")}
	// 次のページがあるかを知るために 1 件多く読む（一覧画面と同じ）
	gs, err := a.cfg.Grants.ListByClient(r.Context(), c.ID, p.GrantsAfter, a.cfg.PageSize+1)
	if err != nil {
		a.logger.Error("console: list grants", "client_id", c.ID, "error", err)
		a.renderError(w, http.StatusInternalServerError, "Grant の一覧を取得できない: "+err.Error())
		return
	}
	if len(gs) > a.cfg.PageSize {
		gs = gs[:a.cfg.PageSize]
		p.GrantsNext = gs[len(gs)-1].Subject
	}
	p.Grants = gs
	switch q.Get("notice") {
	case "registered":
		p.Notice = "登録した。"
		if p.Secret != "" {
			p.Notice += "Client Secret は生成時にしか平文で得られない（Store はハッシュだけを持つ）ので、必要なら控えておく。"
		}
	case "updated":
		p.Notice = "変更を保存した。発行済みのトークンはそのまま有効で、次の要求から新しい設定が使われる。"
	case "rotated":
		p.Notice = "Client Secret を再発行した。旧シークレットはもう使えない。新しい平文が得られるのは今だけなので、控えてから Client 側の設定を差し替える。発行済みのトークンと Grant はそのまま残っている。"
	case "grant-revoked":
		p.Notice = "subject " + q.Get("subject") + " との連携を解除した。この Grant から発行したトークンはすべて失効している。"
	}
	a.render(w, "client", p, http.StatusOK)
}

// findClient はパスの client_id で Client を引く。見つからなければエラー画面を描いて false を返す。
func (a *App) findClient(w http.ResponseWriter, r *http.Request) (*client.Client, bool) {
	id := r.PathValue("id")
	c, err := a.cfg.Store.GetClient(r.Context(), id)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		a.renderError(w, http.StatusNotFound, "client_id "+id+" は Store に登録されていない")
		return nil, false
	case err != nil:
		a.logger.Error("console: get client", "client_id", id, "error", err)
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	return c, true
}
