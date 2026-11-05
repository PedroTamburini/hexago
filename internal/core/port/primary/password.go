package primary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// PasswordUseCase is the capability exposed to the HTTP layer to manage the
// password lifecycle: a self-service change and an administrative reset that
// issues a temporary password.
type PasswordUseCase interface {
	ChangePassword(ctx context.Context, input dto.ChangePasswordInput) error
	ResetPassword(ctx context.Context, input dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error)
}
