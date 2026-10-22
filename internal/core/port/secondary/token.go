package secondary

import (
	"context"
	"time"
)

// TokenClaims represents claims extracted for token management.
type TokenClaims struct {
	JTI       string
	Subject   string // userID
	TokenVer  int
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TokenParser extracts full claims from a token.
type TokenParser interface {
	ParseClaims(token string) (*TokenClaims, error)
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
