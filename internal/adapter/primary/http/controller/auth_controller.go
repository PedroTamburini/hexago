package controller

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	"github.com/PedroTamburini/hexago/internal/domain/port"
)

type AuthController struct {
	usecase port.AuthUseCase
}

func NewAuthController(usecase port.AuthUseCase) *AuthController {
	return &AuthController{usecase: usecase}
}

func (c *AuthController) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	output, err := c.usecase.Authenticate(ctx, input)
	if err != nil {
		return nil, err
	}

	return &dto.AuthenticateOutput{
		Token:    output.Token,
		ExpireIn: output.ExpireIn,
	}, nil
}
