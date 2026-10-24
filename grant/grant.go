package grant

import (
	"maps"
	"slices"
	"time"
)

// Status は Grant の状態。
type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// Grant は client_id × subject に対する認可の記録。
type Grant struct {
	ID       string
	ClientID string
	Subject  string

	// Scopes は付与済み scope の和集合。
	Scopes []string
	// Claims は最新の同意時点の Claims スナップショット。UserInfo と ID Token に使う。
	Claims map[string]any

	Status    Status
	CreatedAt time.Time
	UpdatedAt time.Time
	RevokedAt time.Time // ゼロ値なら未失効
}

// Active は失効していないかを返す。
func (g *Grant) Active() bool { return g.Status == StatusActive }

// Merge は UpsertGrant で既存 Grant に候補を適用した結果を返す。Adapter が共通で使う。
//
//   - 既存が active: scope は和集合、Claims と UpdatedAt は候補の値で置き換える。
//   - 既存が revoked: 失効前の scope は引き継がず、候補の内容で active に戻す
//     （失効済みトークンは既に無効なので、行を再利用して一意制約を保つ）。
//
// ID と ClientID、Subject、CreatedAt は既存の値を保つ。
func Merge(existing, candidate *Grant) *Grant {
	out := &Grant{
		ID:        existing.ID,
		ClientID:  existing.ClientID,
		Subject:   existing.Subject,
		Claims:    maps.Clone(candidate.Claims),
		Status:    StatusActive,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: candidate.UpdatedAt,
	}
	if existing.Active() {
		out.Scopes = unionScopes(existing.Scopes, candidate.Scopes)
	} else {
		out.Scopes = slices.Clone(candidate.Scopes)
	}
	return out
}

// unionScopes は順序を保った和集合を返す（a の順、次に a にない b の順）。
func unionScopes(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
