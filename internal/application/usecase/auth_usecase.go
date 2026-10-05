package usecase

import (
	"context"
	"errors"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/PedroTamburini/hexago/internal/domain/port"
)

const dummyPasswordHash = "$2a$12$r7RUu7gyJNGiGzipY0OFcukSIiaTOhMLqxTJJsaJGD5zLS05U1TIy"

type authUseCase struct {
	userCredentialsFinder port.UserCredentialsFinder
	hasher                port.PasswordHasher
	tokens                port.TokenIssuer
}

func NewAuthUseCase(
	userCredentialsFinder port.UserCredentialsFinder,
	hasher port.PasswordHasher,
	tokens port.TokenIssuer,
) port.AuthUseCase {
	return &authUseCase{
		userCredentialsFinder: userCredentialsFinder,
		hasher:                hasher,
		tokens:                tokens,
	}
}

func (u *authUseCase) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	credentials, err := u.userCredentialsFinder.FindCredentialsByUsername(ctx, input.Username)
	if err != nil {
		if !errors.Is(err, domainerr.ErrUserNotFound) {
			return nil, err
		}

		// Equalizes response time to prevent user enumeration.
		_ = u.hasher.Compare(dummyPasswordHash, input.Password)
		return nil, domainerr.ErrInvalidCredentials
	}

	if !credentials.IsActive {
		return nil, domainerr.ErrInvalidCredentials
	}

	if err := u.hasher.Compare(credentials.PasswordHash, input.Password); err != nil {
		return nil, domainerr.ErrInvalidCredentials
	}

	token, err := u.tokens.GenerateToken(credentials.ID)
	if err != nil {
		return nil, err
	}

	return &dto.AuthenticateOutput{
		Token:    token,
		ExpireIn: u.tokens.ExpireSeconds(),
	}, nil
}
