package primary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// SessionManagementUseCase exposes administrative session management operations.
type SessionManagementUseCase interface {
	ListUserSessions(ctx context.Context, userID uint64) ([]*dto.SessionDTO, error)
	RevokeSession(ctx context.Context, jti string) error
	RevokeAllUserSessions(ctx context.Context, userID uint64) error
}
