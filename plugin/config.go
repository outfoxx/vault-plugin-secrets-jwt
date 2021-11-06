package jwtsecrets

import (
	"context"
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"path"
	"regexp"
	"time"
)

// Default values for configuration options.
const (
	DefaultSignatureAlgorithm = jose.ES256
	DefaultRSAKeyBits         = 2048
	DefaultKeyRotationPeriod  = "15m0s"
	DefaultTokenTTL           = "5m0s"
	DefaultSetIAT             = true
	DefaultSetJTI             = true
	DefaultSetNBF             = true
	DefaultIssuer             = "vault-plugin-secrets-jwt"
	DefaultAudiencePattern    = ".*"
	DefaultSubjectPattern     = ".*"
	DefaultMaxAudiences       = -1
)

// DefaultAllowedClaims is the default value for the AllowedClaims config option.
// By default, only the 'aud' claim can be set by the caller.
var DefaultAllowedClaims = []string{"aud"}

var ReservedClaims = []string{"sub", "iss", "exp", "nbf", "iat", "jti"}

var AllowedSignatureAlgorithmNames = []string{string(jose.ES256), string(jose.ES384), string(jose.ES512), string(jose.RS256), string(jose.RS384), string(jose.RS512)}
var AllowedRSAKeyBits = []int{2048, 3072, 4096}

// Config holds all configuration for the backend.
type Config struct {
	proto.Message

	// SignatureAlgorithm is the signing algorithm to use.
	SignatureAlgorithm jose.SignatureAlgorithm

	// RSAKeyBits is size of generated RSA keys; only used when SignatureAlgorithm is one of the supported RSA algorithms.
	RSAKeyBits int

	// KeyRotationPeriod is how frequently a new key is created.
	KeyRotationPeriod time.Duration

	// TokenTTL defines how long a token is valid for after being signed.
	TokenTTL time.Duration

	// SetIat defines if the backend sets the 'iat' claim or not.
	SetIAT bool

	// SetJTI defines if the backend generates and sets the 'jti' claim or not.
	SetJTI bool

	// SetNBF defines if the backend sets the 'nbf' claim. If true, the claim will be set to the same as the 'iat' claim.
	SetNBF bool

	// Issuer defines the 'iss' claim for the jwt. If blank, it is omitted.
	Issuer string

	// AudiencePattern defines a regular expression (https://golang.org/pkg/regexp/) which must be matched by any incoming 'aud' claims.
	// If the audience claim is an array, each element in the array must match the pattern.
	AudiencePattern *regexp.Regexp

	// SubjectPattern defines a regular expression (https://golang.org/pkg/regexp/) which must be matched by any incoming 'sub' claims.
	SubjectPattern *regexp.Regexp

	// MaxAudiences defines the maximum number of strings in the 'aud' claim.
	MaxAudiences int

	// AllowedClaims defines which claims can be set on the JWT.
	AllowedClaims []string

	// allowedClaimsMap is used to easily check if a claim is in the allowed claim set.
	allowedClaimsMap map[string]bool
}

func (b *backend) getConfig(ctx context.Context, stg logical.Storage) (*Config, error) {
	b.cachedConfigLock.RLock()
	if b.cachedConfig != nil {
		defer b.cachedConfigLock.RUnlock()
		return &*b.cachedConfig, nil
	}

	b.cachedConfigLock.RUnlock()
	b.cachedConfigLock.Lock()
	defer b.cachedConfigLock.Unlock()

	// Double check somebody else didn't already cache it
	if b.cachedConfig != nil {
		return &*b.cachedConfig, nil
	}

	// Attempt to load config from storage & cache

	rawConfig, err := stg.Get(ctx, path.Join(b.storagePrefix, configPath))
	if err != nil {
		return nil, err
	}

	if rawConfig != nil {
		// Found it, finish load from storage
		conf := &Config{}
		if err := json.Unmarshal(rawConfig.Value, conf); err != nil {
			return nil, err
		}
		b.cachedConfig = conf
	} else {
		// Nothing found, initialize configuration to default and save
		b.cachedConfig = DefaultConfig()
		if err := b.saveConfigUnlocked(ctx, stg, b.cachedConfig); err != nil {
			return nil, err
		}
	}

	return &*b.cachedConfig, nil
}

func (b *backend) saveConfig(ctx context.Context, stg logical.Storage, config *Config) error {
	b.cachedConfigLock.Lock()
	defer b.cachedConfigLock.Unlock()

	return b.saveConfigUnlocked(ctx, stg, config)
}

func (b *backend) saveConfigUnlocked(ctx context.Context, stg logical.Storage, config *Config) error {

	entry, err := logical.StorageEntryJSON(path.Join(b.storagePrefix, configPath), config)
	if err != nil {
		return err
	}
	if err := stg.Put(ctx, entry); err != nil {
		return err
	}

	b.cachedConfig = config

	return nil
}

func (b *backend) clearConfig(ctx context.Context, stg logical.Storage) error {
	return stg.Delete(ctx, path.Join(b.storagePrefix, configPath))
}

// DefaultConfig updates a configuration to the default.
func DefaultConfig() *Config {
	c := &Config{}
	c.SignatureAlgorithm = DefaultSignatureAlgorithm
	c.RSAKeyBits = DefaultRSAKeyBits
	c.KeyRotationPeriod, _ = time.ParseDuration(DefaultKeyRotationPeriod)
	c.TokenTTL, _ = time.ParseDuration(DefaultTokenTTL)
	c.SetIAT = DefaultSetIAT
	c.SetJTI = DefaultSetJTI
	c.SetNBF = DefaultSetNBF
	c.Issuer = DefaultIssuer
	c.AudiencePattern = regexp.MustCompile(DefaultAudiencePattern)
	c.SubjectPattern = regexp.MustCompile(DefaultSubjectPattern)
	c.MaxAudiences = DefaultMaxAudiences
	c.AllowedClaims = DefaultAllowedClaims
	c.allowedClaimsMap = makeAllowedClaimsMap(DefaultAllowedClaims)
	return c
}

// turn the slice of allowed claims into a map to easily check if a given claim is in the set
func makeAllowedClaimsMap(allowedClaims []string) map[string]bool {
	newClaims := make(map[string]bool)
	for _, claim := range allowedClaims {
		newClaims[claim] = true
	}
	for _, claim := range ReservedClaims {
		newClaims[claim] = false
	}
	return newClaims
}
