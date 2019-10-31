package jwtsecrets

import (
	"strings"
	"time"
)

// Default values for configuration options.
const (
	DefaultKeyRotationPeriod = "15m0s"
	DefaultTokenTTL          = "5m0s"
	DefaultSetIat            = true
	DefaultSetJTI            = true
	DefaultIssuer            = "vault-plugin-secrets-jwt:UUID"
)

// Config holds all configuration for the backend.
type Config struct {
	// KeyRotationPeriod is how frequently a new key is created.
	KeyRotationPeriod time.Duration

	// TokenTTL defines how long a token is valid for after being signed.
	TokenTTL time.Duration

	// SetIat defines if the backend sets the 'iat' claim or not.
	SetIat bool

	// SetJTI defines if the backend generates and sets the 'jti' claim or not.
	SetJTI bool

	// Issuer defines the 'iss' claim for the jwt. If blank, it is omitted.
	Issuer string
}

// DefaultConfig creates a new default configuration.
func DefaultConfig(backendUUID string) *Config {
	c := new(Config)
	c.KeyRotationPeriod, _ = time.ParseDuration(DefaultKeyRotationPeriod)
	c.TokenTTL, _ = time.ParseDuration(DefaultTokenTTL)
	c.SetIat = DefaultSetIat
	c.SetJTI = DefaultSetJTI
	c.Issuer = strings.Replace(DefaultIssuer, "UUID", backendUUID, 1)
	return c
}
