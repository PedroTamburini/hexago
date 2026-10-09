package port

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
)

// AuthenticationUseCase is the capability exposed to the HTTP layer to
// authenticate a user.
type AuthenticationUseCase interface {
	Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error)
}

// AuthenticationRepository is a narrow read port dedicated to the authentication
// flow.
//
// It exists so the auth use case depends on a single, well defined operation
// instead of the whole user management use case, and so the password hash is
// only ever returned to the caller that legitimately needs it.
//
// Implementations must return domainerr.ErrUserNotFound when the username does
// not exist.
type AuthenticationRepository interface {
	FindCredentialsByUsername(ctx context.Context, username string) (*dto.UserCredentials, error)
}

// PasswordHasher hashes and verifies passwords. The hashing algorithm is an
// implementation detail of the adapter that satisfies this port.
type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hashed string, plain string) error
}

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
