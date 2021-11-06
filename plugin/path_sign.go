package jwtsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	keyClaims = "claims"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex(keyRoleName),
		Fields: map[string]*framework.FieldSchema{
			keyRoleName: {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
			keyClaims: {
				Type:        framework.TypeMap,
				Description: `JSON claims set to sign.`,
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

func (b *backend) pathSignWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		return logical.ErrorResponse("unknown role"), logical.ErrInvalidRequest
	}

	rawClaims, ok := d.GetOk(keyClaims)
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
		if _, ok := roleEntry.OtherClaims[claim]; ok {
			return logical.ErrorResponse("claim %s not permitted, already provided via role configuration", claim), logical.ErrInvalidRequest
		}
	}

	for otherClaim := range roleEntry.OtherClaims {
		claims[otherClaim] = roleEntry.OtherClaims[otherClaim]
	}

	claims["sub"] = roleEntry.Subject
	responseData := map[string]interface{}{}

	now := b.clock.now()

	expiry := now.Add(config.TokenTTL)
	claims["exp"] = jwt.NumericDate(expiry.Unix())
	responseData["expires_at"] = expiry.Unix()

	if config.SetIAT {
		claims["iat"] = jwt.NumericDate(now.Unix())
	}

	if config.SetNBF {
		claims["nbf"] = jwt.NumericDate(now.Unix())
	}

	if config.SetJTI {
		jti, err := b.idGen.id()
		if err != nil {
			return logical.ErrorResponse("could not generate 'jti' claim: %v", err), err
		}
		claims["jti"] = jti
		responseData["id"] = jti
	}

	if config.Issuer != "" {
		claims["iss"] = config.Issuer
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

	key, err := b.getKey()
	if err != nil {
		return logical.ErrorResponse("error getting key: %v", err), err
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: config.SignatureAlgorithm, Key: key.PrivateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.ID))
	if err != nil {
		return logical.ErrorResponse("error signing claims: %v", err), err
	}

	token, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return logical.ErrorResponse("error serializing jwt: %v", err), err
	}

	responseData["token"] = token

	return &logical.Response{
		Data: responseData,
	}, nil
}

const pathSignHelpSyn = `
Sign a set of claims.
`

const pathSignHelpDesc = `
Sign a set of claims.
`
