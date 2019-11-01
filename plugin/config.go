package jwtsecrets

import (
	"regexp"
	"strings"
	"time"
)

// Default values for configuration options.
const (
	DefaultKeyRotationPeriod = "15m0s"
	DefaultTokenTTL          = "5m0s"
	DefaultSetIAT            = true
	DefaultSetJTI            = true
	DefaultSetNBF            = true
	DefaultIssuer            = "vault-plugin-secrets-jwt:UUID"
	DefaultAudiencePattern   = ".*"
	DefaultSubjectPattern    = ".*"
	DefaultMaxAudiences      = -1
)

// DefaultAllowedClaims is the default value for the AllowedClaims config option.
// By default only the 'aud' and 'sub' claims can be set by the caller.
var DefaultAllowedClaims = []string{"aud", "sub"}

var ReservedClaims = []string{"iss", "exp", "nbf", "iat", "jti"}

// Config holds all configuration for the backend.
type Config struct {
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

// DefaultConfig creates a new default configuration.
func DefaultConfig(backendUUID string) *Config {
	c := new(Config)
	c.KeyRotationPeriod, _ = time.ParseDuration(DefaultKeyRotationPeriod)
	c.TokenTTL, _ = time.ParseDuration(DefaultTokenTTL)
	c.SetIAT = DefaultSetIAT
	c.SetJTI = DefaultSetJTI
	c.SetNBF = DefaultSetNBF
	c.Issuer = strings.Replace(DefaultIssuer, "UUID", backendUUID, 1)
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
