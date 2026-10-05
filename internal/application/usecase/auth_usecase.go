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
	userCredentialsFinder port.UserCredentialsFinder
	bcryptService         port.PasswordHasherService
	jwtService            port.JWTService
}

func NewAuthUseCase(
	userCredentialsFinder port.UserCredentialsFinder,
	bcryptService port.PasswordHasherService,
	jwtService port.JWTService,
) port.AuthUseCase {
	return &AuthUseCase{
		userCredentialsFinder: userCredentialsFinder,
		bcryptService:         bcryptService,
		jwtService:            jwtService,
	}
}

func (u *AuthUseCase) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	credentials, err := u.userCredentialsFinder.FindCredentialsByUsername(ctx, input.Username)
	if err != nil {
		if !errors.Is(err, domainerr.ErrUserNotFound) {
			return nil, err
		}

		// Equalizes response time to prevent user enumeration.
		_ = u.bcryptService.Compare(dummyPasswordHash, input.Password)
		return nil, domainerr.ErrInvalidCredentials
	}

	if !credentials.IsActive {
		return nil, domainerr.ErrInvalidCredentials
	}

	if err := u.bcryptService.Compare(credentials.PasswordHash, input.Password); err != nil {
		return nil, domainerr.ErrInvalidCredentials
	}

	token, err := u.jwtService.GenerateToken(credentials.ID)
	if err != nil {
		return nil, err
	}

	return &dto.AuthenticateOutput{
		Token:    token,
		ExpireIn: u.jwtService.ExpireSeconds(),
	}, nil
}
