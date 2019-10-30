package jwtsecrets

import "time"

// Default values for configuration options.
const (
	DefaultKeyRotationPeriod = "15m0s"
	DefaultTokenTTL          = "5m0s"
)

// Config holds all configuration for the backend.
type Config struct {
	// KeyRotationPeriod is how frequently a new key is created.
	KeyRotationPeriod time.Duration

	// TokenTTL defines how long a token is valid for after being signed.
	TokenTTL time.Duration
}

// DefaultConfig creates a new default configuration.
func DefaultConfig() *Config {
	c := new(Config)
	c.KeyRotationPeriod, _ = time.ParseDuration(DefaultKeyRotationPeriod)
	c.TokenTTL, _ = time.ParseDuration(DefaultTokenTTL)
	return c
}
