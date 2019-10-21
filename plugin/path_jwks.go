package jwtsecrets

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathJwks(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "jwks",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathJwksRead,
			},
		},

		HelpSynopsis:    pathJwksHelpSyn,
		HelpDescription: pathJwksHelpDesc,
	}
}

func (b *backend) pathJwksRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := json.Marshal(b.GetPublicKeys().Keys)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": keys,
		},
	}, nil
}

const pathJwksHelpSyn = `
Get a JSON Web Key Set.
`

const pathJwksHelpDesc = `
Get a JSON Web Key Set.
`
