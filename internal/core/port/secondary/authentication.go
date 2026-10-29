package secondary

import (
	"context"
	"time"
)

// Credentials carries the minimum data required to authenticate a user: the
// user ID, the stored password hash and the temporary password expiration, when
// one is active. Keeping this data in the port (instead of a generic user output
// DTO) confines the hash to the authentication flow and prevents it from leaking
// through a read model that could be serialized or logged by mistake.
type Credentials struct {
	ID                    uint64
	PasswordHash          string
	TempPasswordExpiresAt *time.Time
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
	FindCredentialsByUsername(ctx context.Context, username string) (*Credentials, error)
}

// PasswordHasher hashes and verifies passwords. The hashing algorithm is an
// implementation detail of the adapter that satisfies this port.
type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hashed string, plain string) error
}

// TokenIssuer mints access tokens for a given subject. It is the capability
// required by the authentication flow. The token version is embedded in the
// token so a later increment invalidates every token issued before it, and the
// purpose limits where the token can be used.
type TokenIssuer interface {
	GenerateToken(userID uint64, tokenVersion int) (string, error)
	GenerateTokenWithPurpose(userID uint64, tokenVersion int, purpose string) (string, error)
	ExpireSeconds() int64
}

// TokenValidator validates access tokens presented by clients. It is the
// capability required by the HTTP authentication middleware.
type TokenValidator interface {
	ValidateToken(token string) (uint64, error)
}

// TokenService is the composite capability implemented by the token adapter.
// It exists for composition only: consumers should depend on the narrow
// interface they actually need (TokenIssuer, TokenValidator or TokenParser).
type TokenService interface {
	TokenIssuer
	TokenValidator
	TokenParser
}
