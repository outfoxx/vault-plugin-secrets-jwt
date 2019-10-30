package jwtsecrets

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
)

// SigningKey holds a RSA key with a specified TTL.
type SigningKey struct {
	UseUntil  time.Time
	KeepUntil time.Time
	Key       *rsa.PrivateKey
	ID        string
}

func (b *backend) GetKey(validUntil time.Time) (*SigningKey, error) {
	key, err := b.getExistingKey(validUntil)
	if err == nil {
		return key, nil
	}

	return b.getNewKey()
}

func (b *backend) getExistingKey(validUntil time.Time) (*SigningKey, error) {
	now := b.clock.Now()

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	for _, k := range b.keys {
		if k.UseUntil.After(now) && k.KeepUntil.After(validUntil) {
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

	b.configLock.RLock()

	rotationTime := b.clock.Now().Add(b.config.KeyRotationPeriod)

	newKey := &SigningKey{
		ID:        kid.String(),
		Key:       privateKey,
		UseUntil:  rotationTime,
		KeepUntil: rotationTime.Add(b.config.TokenTTL),
	}

	b.configLock.RUnlock()

	b.keys = append(b.keys, newKey)
	return newKey, nil
}

func (b *backend) pruneOldKeys() {
	now := b.clock.Now()

	b.keysLock.Lock()
	defer b.keysLock.Unlock()

	n := 0
	for _, k := range b.keys {
		if k.KeepUntil.After(now) {
			b.keys[n] = k
			n++
		}
	}
	b.keys = b.keys[:n]
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys() *jose.JSONWebKeySet {
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
