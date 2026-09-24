package port

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
)

type AuthUseCase interface {
	Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error)
}
