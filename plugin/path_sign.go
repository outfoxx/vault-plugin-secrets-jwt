package jwtsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign",
		Fields: map[string]*framework.FieldSchema{
			"claims": {
				Type:        framework.TypeMap,
				Description: `JSON claim set to sign.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSignWrite,
			},
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func (b *backend) pathSignWrite(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rawClaims, ok := d.GetOk("claims")
	if !ok {
		return logical.ErrorResponse("no claims provided"), logical.ErrInvalidRequest
	}

	claims, ok := rawClaims.(map[string]interface{})
	if !ok {
		return logical.ErrorResponse("claims not a map"), logical.ErrInvalidRequest
	}

	key, err := b.GetKey()
	if err != nil {
		return nil, err
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key.Key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.ID))
	if err != nil {
		return nil, err
	}

	token, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token": token,
		},
	}, nil
}

const pathSignHelpSyn = `
Sign a set of claims.
`

const pathSignHelpDesc = `
Sign a set of claims.
`
