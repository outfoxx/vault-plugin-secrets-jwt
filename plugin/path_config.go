package jwtsecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	keyRotationDurationLabel = "key_rotate"
	keyExpiryDurationLabel   = "key_expire"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			keyRotationDurationLabel: {
				Type:        framework.TypeString,
				Description: `Duration before a key stops being used to sign new tokens.`,
			},
			keyExpiryDurationLabel: {
				Type:        framework.TypeString,
				Description: `Duration before a key is discarded and can no longer be used to verify tokens.`,
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

func (b *backend) pathConfigWrite(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	if newRotationPeriod, ok := d.GetOk(keyRotationDurationLabel); ok {
		duration, err := time.ParseDuration(newRotationPeriod.(string))
		if err != nil {
			return nil, err
		}
		b.config.KeyRotationPeriod = duration
	}

	if newExpiryPeriod, ok := d.GetOk(keyExpiryDurationLabel); ok {
		duration, err := time.ParseDuration(newExpiryPeriod.(string))
		if err != nil {
			return nil, err
		}
		b.config.KeyExpiryPeriod = duration
	}

	return &logical.Response{
		Data: map[string]interface{}{
			keyRotationDurationLabel: b.config.KeyRotationPeriod.String(),
			keyExpiryDurationLabel:   b.config.KeyExpiryPeriod.String(),
		},
	}, nil
}

func (b *backend) pathConfigRead(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.RLock()
	defer b.configLock.RUnlock()

	return &logical.Response{
		Data: map[string]interface{}{
			keyRotationDurationLabel: b.config.KeyRotationPeriod.String(),
			keyExpiryDurationLabel:   b.config.KeyExpiryPeriod.String(),
		},
	}, nil
}

const pathConfigHelpSyn = `
Configure the backend.
`

const pathConfigHelpDesc = `
Configure the backend.

max_ttl: Duration before a signing key is rotated.
`
