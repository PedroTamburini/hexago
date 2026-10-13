package primary

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/core/dto"
)

// AuthenticationUseCase is the capability exposed to the HTTP layer to
// authenticate a user.
type AuthenticationUseCase interface {
	Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error)
}
