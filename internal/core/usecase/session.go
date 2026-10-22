package usecase

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

type sessionManagementUseCase struct {
	sessions      portout.SessionRegistry
	denylist      portout.TokenDenylist
	tokenVersions portout.TokenVersionManager
}

func NewSessionManagementUseCase(
	sessions portout.SessionRegistry,
	denylist portout.TokenDenylist,
	tokenVersions portout.TokenVersionManager,
) portin.SessionManagementUseCase {
	return &sessionManagementUseCase{
		sessions:      sessions,
		denylist:      denylist,
		tokenVersions: tokenVersions,
	}
}

func (u *sessionManagementUseCase) ListUserSessions(ctx context.Context, userID uint64) ([]*dto.SessionDTO, error) {
	sessions, err := u.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]*dto.SessionDTO, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, &dto.SessionDTO{
			JTI:       session.JTI,
			UserID:    session.UserID,
			IssuedAt:  session.IssuedAt,
			ExpiresAt: session.ExpiresAt,
			IP:        session.IP,
			UserAgent: session.UserAgent,
		})
	}

	return result, nil
}

// RevokeSession denies one specific token. It is the operation an administrator
// uses when a token leaks: the access token is still cryptographically valid,
// but the denylist makes the middleware reject it until it expires.
func (u *sessionManagementUseCase) RevokeSession(ctx context.Context, jti string) error {
	session, err := u.sessions.GetByJTI(ctx, jti)
	if err != nil {
		return err
	}

	if err := u.denylist.Revoke(ctx, session.JTI, session.ExpiresAt); err != nil {
		return err
	}

	return u.sessions.Remove(ctx, session.JTI)
}

// RevokeAllUserSessions invalidates every token of a user: the version bump
// rejects tokens that no longer have the stored version and the registry is
// cleared so the panel reflects the revocation immediately.
func (u *sessionManagementUseCase) RevokeAllUserSessions(ctx context.Context, userID uint64) error {
	if _, err := u.tokenVersions.IncrementVersion(ctx, userID); err != nil {
		return err
	}

	return u.sessions.RemoveAllByUserID(ctx, userID)
}
