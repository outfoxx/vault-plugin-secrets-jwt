package jwtsecrets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type AnyPrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// signingKey holds an RSA/EC key with a specified TTL.
type signingKey struct {
	Inception  time.Time
	UseUntil   time.Time
	KeepUntil  time.Time
	PrivateKey AnyPrivateKey
	ID         string
}

// getKey will return a valid key is one is available, or otherwise generate a new one.
func (b *backend) getKey(validUntil time.Time) (*signingKey, error) {
	key, err := b.getExistingKey(validUntil)
	if err == nil {
		return key, nil
	}

	return b.getNewKey()
}

func (b *backend) getExistingKey(validUntil time.Time) (*signingKey, error) {
	now := b.clock.now()

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	for _, k := range b.keys {
		if k.UseUntil.After(now) && k.KeepUntil.After(validUntil) {
			return k, nil
		}
	}

	return nil, errors.New("no valid key found")
}

func (b *backend) getNewKey() (*signingKey, error) {
	b.keysLock.Lock()
	defer b.keysLock.Unlock()

	b.configLock.RLock()
	config := b.config
	b.configLock.RUnlock()

	var err error
	var privateKey AnyPrivateKey

	switch config.SignatureAlgorithm {
	case jose.RS256, jose.RS384, jose.RS512:
		privateKey, err = rsa.GenerateKey(rand.Reader, config.RSAKeyBits)
	case jose.ES256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.ES512:
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = errors.New("unknown/unsupported signature algorithm")
	}

	if err != nil {
		return nil, err
	}

	kid, err := b.idGen.id()
	if err != nil {
		return nil, err
	}

	now := b.clock.now()
	rotationTime := now.Add(b.config.KeyRotationPeriod)

	newKey := &signingKey{
		ID:         kid,
		PrivateKey: privateKey,
		Inception:  now,
		UseUntil:   rotationTime,
		KeepUntil:  rotationTime.Add(b.config.TokenTTL),
	}

	b.keys = append(b.keys, newKey)
	return newKey, nil
}

func (b *backend) pruneOldKeys() {
	now := b.clock.now()

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

	jwkSet := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(b.keys)),
	}

	for i, k := range b.keys {
		jwkSet.Keys[i].Key = k.PrivateKey.Public()
		jwkSet.Keys[i].KeyID = k.ID
		jwkSet.Keys[i].Algorithm = "RS256"
		jwkSet.Keys[i].Use = "sig"
	}

	return &jwkSet
}

func (b *backend) updateConfigOfKeys(keyRotationPeriod time.Duration, tokenTTL time.Duration) {

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	for _, key := range b.keys {
		key.UseUntil = key.Inception.Add(keyRotationPeriod)

		// Only update the keep until if the new keep until is after
		// the current one. This ensures shortening a ttl doesn't
		// prune keys too early.
		newKeepUntil := key.UseUntil.Add(tokenTTL)
		if newKeepUntil.After(key.KeepUntil) {
			key.KeepUntil = newKeepUntil
		}
	}
}
