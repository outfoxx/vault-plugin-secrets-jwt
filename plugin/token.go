package jwtsecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	jwtSecretsTokenType = "jwt_token"
)

func (b *backend) token() *framework.Secret {
	return &framework.Secret{
		Type: jwtSecretsTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Signed JWT",
			},
		},
		Revoke: tokenRevoke,
	}
}

func tokenRevoke(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Nothing to do!
	return nil, nil
}
