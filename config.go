package authenticator

import (
	"crypto"
	"errors"
	"time"
)

const (
	Sha1   = crypto.SHA1
	Sha256 = crypto.SHA256
	Sha512 = crypto.SHA512
)

var (
	ErrIssuerRequired = errors.New("issuer is required")
	ErrUserRequired   = errors.New("user is required")
	ErrSecretRequired = errors.New("secret is required")
	ErrSecretInvalid  = errors.New("secret is invalid with algorithm")
	ErrAlgorithm      = errors.New("algorithm is invalid")
	ErrDigitsInvalid  = errors.New("digits is invalid")
	ErrPeriodInvalid  = errors.New("period is invalid")
)

type Config struct {
	Issuer    string        // issuer with company name
	User      string        // user with account name
	Secret    string        // secret key with stardard string
	algorithm crypto.Hash   // algorithm with crypto.Hash default SHA1
	digits    int           // digits default 6
	period    time.Duration // period default 30 seconds
}

func (c *Config) SetDefaults() {

	c.algorithm = Sha1

	c.digits = 6

	c.period = 30 * time.Second
}

func (c *Config) Validate() error {

	if c.Issuer == "" {
		return ErrIssuerRequired
	}

	if c.User == "" {
		return ErrUserRequired
	}

	if c.Secret == "" {
		return ErrSecretRequired
	}

	switch c.algorithm {
	case Sha1:
		if len(c.Secret) != 16 {
			return ErrSecretInvalid
		}

	case Sha256:
		if len(c.Secret) != 32 {
			return ErrSecretInvalid
		}

	case Sha512:
		if len(c.Secret) != 64 {
			return ErrSecretInvalid
		}

	default:
		return ErrAlgorithm
	}

	if !(c.digits == 6 || c.digits == 8) {
		return ErrDigitsInvalid
	}

	if c.period < 30*time.Second || c.period > 60*time.Second {
		return ErrPeriodInvalid
	}

	return nil
}

type Option func(*Config)

func WithAlgorithm(algorithm crypto.Hash) Option {
	return func(c *Config) {
		c.algorithm = algorithm
	}
}

func WithDigits(digits int) Option {
	return func(c *Config) {
		c.digits = digits
	}
}

func WithPeriod(period time.Duration) Option {
	return func(c *Config) {
		c.period = period
	}
}
