package jwtsecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	keyRotationDurationLabel = "key_ttl"
	keyTokenTTL              = "jwt_ttl"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			keyRotationDurationLabel: {
				Type:        framework.TypeString,
				Description: `Duration before a key stops being used to sign new tokens.`,
			},
			keyTokenTTL: {
				Type:        framework.TypeString,
				Description: `Duration a token is valid for.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *backend) pathConfigWrite(c context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	if newRotationPeriod, ok := d.GetOk(keyRotationDurationLabel); ok {
		duration, err := time.ParseDuration(newRotationPeriod.(string))
		if err != nil {
			return nil, err
		}
		b.config.KeyRotationPeriod = duration
	}

	if newTTL, ok := d.GetOk(keyTokenTTL); ok {
		duration, err := time.ParseDuration(newTTL.(string))
		if err != nil {
			return nil, err
		}
		b.config.TokenTTL = duration
	}

	return nonLockingRead(b)
}

func (b *backend) pathConfigRead(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.RLock()
	defer b.configLock.RUnlock()

	return nonLockingRead(b)
}

func nonLockingRead(b *backend) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			keyRotationDurationLabel: b.config.KeyRotationPeriod.String(),
			keyTokenTTL:              b.config.TokenTTL.String(),
		},
	}, nil
}

const pathConfigHelpSyn = `
Configure the backend.
`

const pathConfigHelpDesc = `
Configure the backend.

key_ttl: Duration before a key stops signing new tokens and a new one is generated.
		 After this period the public key will still be available to verify JWTs.
jwt_ttl: Duration before a token expires.
`
