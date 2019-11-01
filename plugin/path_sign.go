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

	// Get a local copy of config, to minimize time with the lock
	b.configLock.RLock()
	config := *b.config
	b.configLock.RUnlock()

	for claim := range claims {
		if allowedClaim, ok := config.allowedClaimsMap[claim]; !ok || !allowedClaim {
			return logical.ErrorResponse("claim %s not permitted", claim), logical.ErrInvalidRequest
		}
	}

	now := b.clock.now()

	expiry := now.Add(config.TokenTTL)
	claims["exp"] = jwt.NumericDate(expiry.Unix())

	if config.SetIAT {
		claims["iat"] = jwt.NumericDate(now.Unix())
	}

	if config.SetNBF {
		claims["nbf"] = jwt.NumericDate(now.Unix())
	}

	if config.SetJTI {
		jti, err := b.uuidGen.uuid()
		if err != nil {
			return logical.ErrorResponse("could not generate 'jti' claim: %v", err), err
		}
		claims["jti"] = jti
	}

	if config.Issuer != "" {
		claims["iss"] = config.Issuer
	}

	if rawSub, ok := claims["sub"]; ok {
		if sub, ok := rawSub.(string); ok {
			if !config.SubjectPattern.MatchString(sub) {
				return logical.ErrorResponse("validation of 'sub' claim failed"), logical.ErrInvalidRequest
			}
		} else {
			return logical.ErrorResponse("'sub' claim was %T, not string", rawSub), logical.ErrInvalidRequest
		}
	}

	if rawAud, ok := claims["aud"]; ok {
		switch aud := rawAud.(type) {
		case string:
			if !config.AudiencePattern.MatchString(aud) {
				return logical.ErrorResponse("validation of 'aud' claim failed"), logical.ErrInvalidRequest
			}
		case []string:
			if config.MaxAudiences > -1 && len(aud) > config.MaxAudiences {
				return logical.ErrorResponse("too many audience claims: %d", len(aud)), logical.ErrInvalidRequest
			}
			for _, audEntry := range aud {
				if !config.AudiencePattern.MatchString(audEntry) {
					return logical.ErrorResponse("validation of 'aud' claim failed"), logical.ErrInvalidRequest
				}
			}
		default:
			return logical.ErrorResponse("'aud' claim was %T, not string or []string", rawAud), logical.ErrInvalidRequest
		}
	}

	key, err := b.getKey(expiry)
	if err != nil {
		return logical.ErrorResponse("error getting key: %v", err), err
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key.Key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.ID))
	if err != nil {
		return logical.ErrorResponse("error signing claims: %v", err), err
	}

	token, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return logical.ErrorResponse("error serializing jwt: %v", err), err
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
