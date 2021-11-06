package jwtsecrets

import "github.com/hashicorp/vault/sdk/framework"

const (
	jwtSecretsTokenType = "jwt_token"
)

type jwtSecretsToken struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func (b *backend) token() *framework.Secret {
	return &framework.Secret{
		Type: jwtSecretsTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Signed JWT",
			},
		},
	}
}
