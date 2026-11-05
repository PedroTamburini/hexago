package secondary

import (
	"context"
	"time"
)

const (
	// TokenPurposeAccess is the purpose of a token that can access the regular
	// API. It is also the purpose assumed for tokens issued before purposes were
	// introduced.
	TokenPurposeAccess = "access"
	// TokenPurposeChangePassword is the purpose of a token issued after a login
	// with a temporary password. It only grants access to the change-password
	// endpoint.
	TokenPurposeChangePassword = "change_password"
)

// TokenClaims represents claims extracted for token management.
type TokenClaims struct {
	JTI       string
	Subject   string // userID
	TokenVer  int
	Purpose   string // token purpose; empty means access for legacy tokens
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TokenParser extracts full claims from a token.
type TokenParser interface {
	ParseClaims(token string) (*TokenClaims, error)
}

// TokenIssuer mints access tokens for a given subject. The token version is
// embedded in the token so a later increment invalidates every token issued
// before it, and the purpose limits where the token can be used.
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

// TokenDenylist manages revoked tokens individually.
type TokenDenylist interface {
	Revoke(ctx context.Context, jti string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// Session represents metadata of an active session.
type Session struct {
	JTI       string    `json:"jti"`
	UserID    uint64    `json:"user_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// SessionRegistry manages active sessions for inspection and revocation.
type SessionRegistry interface {
	Register(ctx context.Context, session Session) error
	GetByJTI(ctx context.Context, jti string) (*Session, error)
	ListByUserID(ctx context.Context, userID uint64) ([]*Session, error)
	Remove(ctx context.Context, jti string) error
	RemoveAllByUserID(ctx context.Context, userID uint64) error
}

// TokenVersionManager controls token versioning per user (tv claim).
// Does not alter database models; uses Redis.
type TokenVersionManager interface {
	GetVersion(ctx context.Context, userID uint64) (int, error)
	IncrementVersion(ctx context.Context, userID uint64) (int, error)
}
