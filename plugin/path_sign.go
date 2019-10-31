package jwtsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ReservedClaims are claims which can be set by the backend. Attempting to set them manually causes an error.
var ReservedClaims = []string{"exp"}

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

	if err := checkReservedFields(claims); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	// Get a local copy of config, to minimize time with the lock
	b.configLock.RLock()
	config := *b.config
	b.configLock.RUnlock()

	expiry := b.clock.now().Add(config.TokenTTL)
	claims["exp"] = jwt.NumericDate(expiry.Unix())

	key, err := b.getKey(expiry)
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

func checkReservedFields(claims map[string]interface{}) error {
	for _, reservedClaim := range ReservedClaims {
		if _, ok := claims[reservedClaim]; ok {
			return fmt.Errorf("claim `%s` is reserved", reservedClaim)
		}
	}

	return nil
}

const pathSignHelpSyn = `
Sign a set of claims.
`

const pathSignHelpDesc = `
Sign a set of claims.
`
