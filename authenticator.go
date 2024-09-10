package authenticator

func NewAuthenticator(config Config, options ...Option) (*Authenticator, error) {

	config.SetDefaults()

	for _, option := range options {
		option(&config)
	}

	err := config.Validate()
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		issuer:    config.Issuer,
		user:      config.User,
		secret:    config.Secret,
		algorithm: config.algorithm,
		digits:    config.digits,
		period:    config.period,
	}, nil
}
