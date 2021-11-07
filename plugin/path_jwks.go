package jwtsecrets

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"strconv"
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

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys(ctx context.Context, stg logical.Storage) (*jose.JSONWebKeySet, error) {

	config, err := b.getConfig(ctx, stg)
	if err != nil {
		return nil, err
	}

	policy, err := b.getPolicy(ctx, stg, config)
	if err != nil {
		return nil, err
	}

	policy.Lock(false)
	defer policy.Unlock()

	keyCount := (policy.LatestVersion - policy.MinDecryptionVersion) + 1

	jwkSet := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, keyCount),
	}

	keyIdx := 0
	for version := policy.MinDecryptionVersion; version <= policy.LatestVersion; version++ {

		key, ok := policy.Keys[strconv.Itoa(version)]
		if !ok {
			continue
		}

		if key.FormattedPublicKey != "" {
			block, _ := pem.Decode([]byte(key.FormattedPublicKey))
			if block == nil {
				continue
			}

			jwkSet.Keys[keyIdx].Key, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				continue
			}
		} else if key.RSAKey != nil {
			jwkSet.Keys[keyIdx].Key = &key.RSAKey.PublicKey
		}

		jwkSet.Keys[keyIdx].KeyID = createKeyId(b.id, policy.Name, version)
		jwkSet.Keys[keyIdx].Algorithm = string(config.SignatureAlgorithm)
		jwkSet.Keys[keyIdx].Use = "sig"
		keyIdx += 1
	}

	return &jwkSet, nil
}

const pathJwksHelpSyn = `
Get a JSON Web Key Set.
`

const pathJwksHelpDesc = `
Get a JSON Web Key Set.
`
