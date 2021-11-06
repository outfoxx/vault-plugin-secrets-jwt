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

var keyPruneExtra, _ = time.ParseDuration("3s")

type AnyPrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// signingKey holds an RSA/EC key with a specified TTL.
type signingKey struct {
	ID                 string
	PrivateKey         AnyPrivateKey
	SignatureAlgorithm jose.SignatureAlgorithm
	Inception          time.Time
	UseUntil           time.Time
}

type verificationKey struct {
	ID                 string
	PublicKey          crypto.PublicKey
	SignatureAlgorithm jose.SignatureAlgorithm
	KeepUntil          time.Time
}

// getKey will return a valid key is one is available, or otherwise generate a new one.
func (b *backend) getKey() (*signingKey, error) {
	key, err := b.getExistingKey()
	if err == nil {
		return key, nil
	}

	return b.getNewKey()
}

func (b *backend) getExistingKey() (*signingKey, error) {
	now := b.clock.now()

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	if b.signingKey != nil && b.signingKey.UseUntil.After(now) {
		return b.signingKey, nil
	}

	return nil, errors.New("no valid key found")
}

func (b *backend) getNewKey() (*signingKey, error) {
	b.keysLock.Lock()
	defer b.keysLock.Unlock()

	b.configLock.RLock()
	config := b.config
	b.configLock.RUnlock()

	// Save signing key as verification key

	if b.signingKey != nil {
		newVerificationKey := &verificationKey{
			ID:                 b.signingKey.ID,
			PublicKey:          b.signingKey.PrivateKey.Public(),
			SignatureAlgorithm: b.signingKey.SignatureAlgorithm,
			KeepUntil:          b.signingKey.UseUntil.Add(config.TokenTTL).Add(keyPruneExtra),
		}
		b.verificationKeys = append(b.verificationKeys, newVerificationKey)
	}

	// Generate new signing key

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

	newSigningKey := &signingKey{
		ID:                 kid,
		PrivateKey:         privateKey,
		SignatureAlgorithm: config.SignatureAlgorithm,
		Inception:          now,
		UseUntil:           now.Add(config.KeyRotationPeriod),
	}

	b.signingKey = newSigningKey

	return b.signingKey, nil
}

func (b *backend) pruneOldKeys() {
	now := b.clock.now()

	_, _ = b.getKey()

	b.keysLock.Lock()
	defer b.keysLock.Unlock()

	n := 0
	for _, k := range b.verificationKeys {
		if k.KeepUntil.After(now) {
			b.verificationKeys[n] = k
			n++
		}
	}
	b.verificationKeys = b.verificationKeys[:n]
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys() *jose.JSONWebKeySet {
	b.pruneOldKeys()

	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	keyCount := len(b.verificationKeys)
	if b.signingKey != nil {
		keyCount += 1
	}

	jwkSet := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, keyCount),
	}

	kIdx := 0

	// Add verification keys
	for _, k := range b.verificationKeys {
		jwkSet.Keys[kIdx].Key = k.PublicKey
		jwkSet.Keys[kIdx].KeyID = k.ID
		jwkSet.Keys[kIdx].Algorithm = string(k.SignatureAlgorithm)
		jwkSet.Keys[kIdx].Use = "sig"
		kIdx += 1
	}

	// Add current signing key
	if b.signingKey != nil {
		jwkSet.Keys[kIdx].Key = b.signingKey.PrivateKey.Public()
		jwkSet.Keys[kIdx].KeyID = b.signingKey.ID
		jwkSet.Keys[kIdx].Algorithm = string(b.signingKey.SignatureAlgorithm)
		jwkSet.Keys[kIdx].Use = "sig"
	}

	return &jwkSet
}
