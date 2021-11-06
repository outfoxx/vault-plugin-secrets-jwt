package jwtsecrets

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/hashicorp/vault/sdk/logical"
	"path"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const (
	keysPath = "verificationKeys"
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
func (b *backend) getKey(ctx context.Context, stg logical.Storage) (*signingKey, error) {
	key, err := b.getExistingKey()
	if err == nil {
		return key, nil
	}

	return b.getNewKey(ctx, stg)
}

func (b *backend) getExistingKey() (*signingKey, error) {
	now := b.clock.now()

	b.cachedKeysLock.RLock()
	defer b.cachedKeysLock.RUnlock()

	if b.signingKey != nil && b.signingKey.UseUntil.After(now) {
		return b.signingKey, nil
	}

	return nil, errors.New("no valid key found")
}

func (b *backend) getNewKey(ctx context.Context, stg logical.Storage) (*signingKey, error) {
	config, err := b.getConfig(ctx, stg)
	if err != nil {
		return nil, err
	}

	b.cachedKeysLock.Lock()
	defer b.cachedKeysLock.Unlock()

	if err := b.saveSigningKeyAsVerificationKeyUnlocked(ctx, stg, config); err != nil {
		return nil, err
	}

	// Generate new signing key

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

func (b *backend) getVerificationKeys(ctx context.Context, stg logical.Storage) ([]*verificationKey, error) {
	b.cachedKeysLock.RLock()
	if b.cachedVerificationKeys != nil {
		defer b.cachedKeysLock.RUnlock()
		return b.cachedVerificationKeys, nil
	}

	b.cachedKeysLock.RUnlock()
	b.cachedKeysLock.Lock()
	defer b.cachedKeysLock.Unlock()

	// Double check somebody else didn't already cache it
	if b.cachedVerificationKeys != nil {
		return b.cachedVerificationKeys, nil
	}

	// Attempt to load keys from storage & cache

	rawKeys, err := stg.Get(ctx, path.Join(b.storagePrefix, keysPath))
	if err != nil {
		return nil, err
	}

	if rawKeys != nil {
		// Found them, finish load from storage
		var keys []*verificationKey
		if err := json.Unmarshal(rawKeys.Value, &keys); err != nil {
			return nil, err
		}
		b.cachedVerificationKeys = keys
	} else {
		b.cachedVerificationKeys = []*verificationKey{}
	}

	return b.cachedVerificationKeys, nil
}

func (b *backend) saveVerificationKeysUnlocked(ctx context.Context, stg logical.Storage, keys []*verificationKey) error {
	entry, err := logical.StorageEntryJSON(path.Join(b.storagePrefix, configPath), keys)
	if err != nil {
		return err
	}
	if err := stg.Put(ctx, entry); err != nil {
		return err
	}

	b.cachedVerificationKeys = keys

	return nil
}

func (b *backend) saveSigningKeyAsVerificationKey(ctx context.Context, stg logical.Storage, config *Config) error {
	b.cachedKeysLock.Lock()
	defer b.cachedKeysLock.Unlock()

	return b.saveSigningKeyAsVerificationKeyUnlocked(ctx, stg, config)
}

func (b *backend) saveSigningKeyAsVerificationKeyUnlocked(ctx context.Context, stg logical.Storage, config *Config) error {
	if b.signingKey == nil {
		return nil
	}

	newVerificationKey := &verificationKey{
		ID:                 b.signingKey.ID,
		PublicKey:          b.signingKey.PrivateKey.Public(),
		SignatureAlgorithm: b.signingKey.SignatureAlgorithm,
		KeepUntil:          b.signingKey.UseUntil.Add(config.TokenTTL).Add(keyPruneExtra),
	}

	newVerificationKeys := append(b.cachedVerificationKeys, newVerificationKey)

	if err := b.saveVerificationKeysUnlocked(ctx, stg, newVerificationKeys); err != nil {
		return err
	}

	b.cachedVerificationKeys = newVerificationKeys
	b.signingKey = nil

	return nil
}

func (b *backend) pruneOldKeys(ctx context.Context, stg logical.Storage) ([]*verificationKey, error) {
	now := b.clock.now()

	if b.signingKey != nil && b.signingKey.UseUntil.After(now) {
		config, err := b.getConfig(ctx, stg)
		if err != nil {
			return nil, err
		}
		if err := b.saveSigningKeyAsVerificationKey(ctx, stg, config); err != nil {
			return nil, err
		}
	}

	verificationKeys, err := b.getVerificationKeys(ctx, stg)
	if err != nil {
		return nil, err
	}

	b.cachedKeysLock.Lock()
	defer b.cachedKeysLock.Unlock()

	n := 0
	for _, k := range verificationKeys {
		if k.KeepUntil.After(now) {
			verificationKeys[n] = k
			n++
		}
	}

	if n != len(verificationKeys) {
		verificationKeys = verificationKeys[:n]
		if err = b.saveVerificationKeysUnlocked(ctx, stg, verificationKeys); err != nil {
			return nil, err
		}
	}

	return verificationKeys, nil
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys(ctx context.Context, stg logical.Storage) (*jose.JSONWebKeySet, error) {

	verificationKeys, err := b.pruneOldKeys(ctx, stg)
	if err != nil {
		return nil, err
	}

	b.cachedKeysLock.RLock()
	defer b.cachedKeysLock.RUnlock()

	keyCount := len(verificationKeys)
	if b.signingKey != nil {
		keyCount += 1
	}

	jwkSet := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, keyCount),
	}

	kIdx := 0

	// Add verification keys
	for _, k := range verificationKeys {
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

	return &jwkSet, nil
}
