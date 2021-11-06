// Package jwtsecrets implements the vault-plugin-jwt-secrets backend.
package jwtsecrets

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
)

const (
	configPath = "config"
)

type backend struct {
	*framework.Backend
	clock                  clock
	storagePrefix          string
	cachedConfig           *Config
	cachedConfigLock       *sync.RWMutex
	signingKey             *signingKey
	cachedVerificationKeys []*verificationKey
	cachedKeysLock         *sync.RWMutex
	idGen                  uniqueIdGenerator
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

	if backendUUID == "" {
		backendUUID = uuid.New().String()
	}
	b.storagePrefix = backendUUID

	b.cachedKeysLock = new(sync.RWMutex)
	b.cachedConfigLock = new(sync.RWMutex)

	b.clock = realClock{}
	b.idGen = friendlyIdGenerator{}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"jwks"},
		},
		Paths: framework.PathAppend(
			pathRole(b),
			[]*framework.Path{
				pathConfig(b),
				pathJwks(b),
				pathSign(b),
			},
		),
	}

	return b, nil
}

const backendHelp = `
The JWT secrets engine signs JWTs.
`
