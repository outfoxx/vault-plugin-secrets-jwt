package jwtsecrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
)

type backend struct {
	*framework.Backend
	config     *Config
	configLock *sync.RWMutex
	keys       []*SigningKey
	keysLock   *sync.RWMutex
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := makeBackend()
	if err != nil {
		return nil, err
	}
	if err = b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func makeBackend() (*backend, error) {
	var b = &backend{}

	b.keysLock = new(sync.RWMutex)
	b.keys = make([]*SigningKey, 0)

	b.configLock = new(sync.RWMutex)
	b.config = DefaultConfig()

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

// SigningKey holds a RSA key with a specified TTL.
type SigningKey struct {
	Created time.Time
	Key     *rsa.PrivateKey
	ID      string
}

func (b *backend) GetKey() (*SigningKey, error) {
	key, err := b.getExistingKey()
	if err == nil {
		return key, nil
	}

	return b.getNewKey()
}

func (b *backend) getExistingKey() (*SigningKey, error) {
	b.configLock.RLock()
	maxAge := b.config.KeyRotationPeriod
	b.configLock.RUnlock()

	now := time.Now()

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	for _, k := range b.keys {
		if k.Created.Add(maxAge).After(now) {
			return k, nil
		}
	}

	return nil, errors.New("no valid key found")
}

func (b *backend) getNewKey() (*SigningKey, error) {
	b.keysLock.Lock()
	defer b.keysLock.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	newKey := &SigningKey{
		Created: time.Now(),
		ID:      kid.String(),
		Key:     privateKey,
	}

	b.keys = append(b.keys, newKey)
	return newKey, nil
}

func (b *backend) pruneOldKeys() {
	b.configLock.RLock()
	maxAge := b.config.KeyExpiryPeriod
	b.configLock.RUnlock()

	now := time.Now()

	b.keysLock.Lock()
	defer b.keysLock.Unlock()

	n := 0
	for _, k := range b.keys {
		if k.Created.Add(maxAge).After(now) {
			b.keys[n] = k
			n++
		}
	}
	b.keys = b.keys[:n]
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) GetPublicKeys() *jose.JSONWebKeySet {
	b.pruneOldKeys()

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(b.keys)),
	}

	for i, k := range b.keys {
		jwks.Keys[i].Key = &k.Key.PublicKey
		jwks.Keys[i].KeyID = k.ID
		jwks.Keys[i].Algorithm = "RS256"
		jwks.Keys[i].Use = "sig"
	}

	return &jwks
}
