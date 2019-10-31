// Package jwtsecrets implements the vault-plugin-jwt-secrets backend.
package jwtsecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	clock      clock
	config     *Config
	configLock *sync.RWMutex
	keys       []*signingKey
	keysLock   *sync.RWMutex
	uuidGen    uuidGenerator
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := makeBackend(conf.BackendUUID)
	if err != nil {
		return nil, err
	}
	if err = b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func makeBackend(backendUUID string) (*backend, error) {
	var b = &backend{}

	b.keysLock = new(sync.RWMutex)
	b.keys = make([]*signingKey, 0)

	b.configLock = new(sync.RWMutex)
	b.config = DefaultConfig(backendUUID)

	b.clock = realClock{}
	b.uuidGen = realUUIDGenerator{}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"jwks"},
		},
		Paths: []*framework.Path{
			pathConfig(b),
			pathJwks(b),
			pathSign(b),
		},
	}

	return b, nil
}

const backendHelp = `
The JWT secrets engine signs JWTs.
`
