package token

import (
	"context"
	"time"

	"github.com/muno/auth-engine/client"
)

// IDTokenInput は ID Token の発行に必要な、トークンエンドポイントが持つ情報。
type IDTokenInput struct {
	Subject         string
	AuthenticatedAt time.Time
	Nonce           string
	AMR             []string
	ACR             string
	// AccessToken は同時に発行した Access Token の平文（at_hash 用）。
	AccessToken string
	Scopes      []string
}

// IDTokenIssuer は ID Token を発行する Port。oidc パッケージが実装し、Engine が配線する。
// nil のままなら openid scope が付与されても id_token は返さない（OAuth 2.0 のみの構成）。
type IDTokenIssuer interface {
	IssueIDToken(ctx context.Context, c *client.Client, in IDTokenInput) (string, error)
}
