package primary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// AuthenticationUseCase is the capability exposed to the HTTP layer to
// authenticate a user.
type AuthenticationUseCase interface {
	Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error)
	Logout(ctx context.Context, token string) error
	RevokeToken(ctx context.Context, token string) error
	RevokeAllUserTokens(ctx context.Context, userID uint64) error
}
