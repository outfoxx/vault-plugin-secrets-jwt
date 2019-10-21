package jwtsecrets

import "time"

// Default values for configuration options.
const (
	DefaultKeyRotationPeriod = "15m0s"
	DefaultKeyExpiryPeriod   = "20m0s"
)

// Config holds all configuration for the backend.
type Config struct {
	KeyRotationPeriod time.Duration
	KeyExpiryPeriod   time.Duration
}

// DefaultConfig creates a new default configuration.
func DefaultConfig() *Config {
	c := new(Config)
	c.KeyRotationPeriod, _ = time.ParseDuration(DefaultKeyRotationPeriod)
	c.KeyExpiryPeriod, _ = time.ParseDuration(DefaultKeyExpiryPeriod)
	return c
}
