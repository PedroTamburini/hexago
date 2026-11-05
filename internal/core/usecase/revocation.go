package usecase

import (
	"context"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

// revokeAllUserTokens invalidates every token of a user by bumping the token
// version and clears the session records. Password changes, password resets,
// account deactivation and administrative session revocation all rely on the
// same operation, so it lives in one place instead of being duplicated by each
// use case.
func revokeAllUserTokens(
	ctx context.Context,
	versions portout.TokenVersionManager,
	sessions portout.SessionRegistry,
	userID uint64,
) error {
	if _, err := versions.IncrementVersion(ctx, userID); err != nil {
		return err
	}

	return sessions.RemoveAllByUserID(ctx, userID)
}
