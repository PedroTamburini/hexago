package port

// TokenIssuer mints access tokens for a given subject. It is the capability
// required by the authentication flow.
type TokenIssuer interface {
	GenerateToken(userID uint64) (string, error)
	ExpireSeconds() int64
}

// TokenValidator validates access tokens presented by clients. It is the
// capability required by the HTTP authentication middleware.
type TokenValidator interface {
	ValidateToken(token string) (uint64, error)
}

// TokenService is the composite capability implemented by the token adapter.
// It exists for composition only: consumers should depend on the narrow
// interface they actually need (TokenIssuer or TokenValidator).
type TokenService interface {
	TokenIssuer
	TokenValidator
}
