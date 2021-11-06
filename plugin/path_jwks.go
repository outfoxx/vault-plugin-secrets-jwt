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

func (b *backend) pathJwksRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {

	jwkSet, err := b.getPublicKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	jwkSetJson, err := json.Marshal(map[string]interface{}{"keys": jwkSet.Keys})
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPStatusCode:  200,
			logical.HTTPContentType: "application/jwk-set+json",
			logical.HTTPRawBody:     jwkSetJson,
		},
	}, nil
}

const pathJwksHelpSyn = `
Get a JSON Web Key Set.
`

const pathJwksHelpDesc = `
Get a JSON Web Key Set.
`
