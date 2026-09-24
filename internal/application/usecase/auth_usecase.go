package usecase

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/PedroTamburini/hexago/internal/domain/port"
)

const dummyPasswordHash = "$2a$12$r7RUu7gyJNGiGzipY0OFcukSIiaTOhMLqxTJJsaJGD5zLS05U1TIy"

type AuthUseCase struct {
	userUseCase   port.UserUseCase
	bcryptService port.PasswordHasherService
	jwtService    port.JWTService
}

func NewAuthUseCase(userUseCase port.UserUseCase, bcryptService port.PasswordHasherService, jwtService port.JWTService) port.AuthUseCase {
	return &AuthUseCase{
		userUseCase:   userUseCase,
		bcryptService: bcryptService,
		jwtService:    jwtService,
	}
}

func (u *AuthUseCase) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	username := dto.FindUserByUsernameInput{
		Username: input.Username,
	}

	user, err := u.userUseCase.FindByUsername(ctx, username)
	if err != nil {
		if !errors.Is(err, domainerr.ErrUserNotFound) {
			return nil, err
		}

		// Equalizes response time to prevent user enumeration.
		_ = u.bcryptService.Compare(dummyPasswordHash, input.Password)
		return nil, domainerr.ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, domainerr.ErrInvalidCredentials
	}

	if err := u.bcryptService.Compare(user.PasswordHash, input.Password); err != nil {
		return nil, domainerr.ErrInvalidCredentials
	}

	token, err := u.jwtService.GenerateToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &dto.AuthenticateOutput{
		Token:    token,
		ExpireIn: u.jwtService.ExpireSeconds(),
	}, nil
}
