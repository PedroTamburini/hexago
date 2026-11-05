package secondary

import (
	"context"
	"time"
)

// Credentials carries the minimum data required to authenticate a user or to
// change a password: the user ID, the stored password hash and the temporary
// password expiration, when one is active. Keeping this data in the port
// (instead of a generic user output DTO) confines the hash to the flows that
// legitimately need it and prevents it from leaking through a read model that
// could be serialized or logged by mistake.
type Credentials struct {
	ID                    uint64
	PasswordHash          string
	TempPasswordExpiresAt *time.Time
}

// CredentialsRepository owns every read and write of password credentials. Both
// the login flow and the password flows depend on this single capability, so the
// password hash never enters the regular user read model.
//
// Implementations must return domainerr.ErrUserNotFound when the username or the
// user ID does not exist.
type CredentialsRepository interface {
	FindCredentialsByUsername(ctx context.Context, username string) (*Credentials, error)
	FindCredentialsByID(ctx context.Context, id uint64) (*Credentials, error)
	UpdatePasswordAndClearTemp(ctx context.Context, id uint64, passwordHash string) error
	SetTempPassword(ctx context.Context, id uint64, passwordHash string, expiresAt time.Time) error
}

// PasswordHasher hashes and verifies passwords. The hashing algorithm is an
// implementation detail of the adapter that satisfies this port.
type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hashed string, plain string) error
}
