package port

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
)

// UserCredentialsFinder is a narrow read port dedicated to the authentication
// flow.
//
// It exists so the auth use case depends on a single, well defined operation
// instead of the whole user management use case, and so the password hash is
// only ever returned to the caller that legitimately needs it.
//
// Implementations must return domainerr.ErrUserNotFound when the username does
// not exist.
type UserCredentialsFinder interface {
	FindCredentialsByUsername(ctx context.Context, username string) (*dto.UserCredentials, error)
}
