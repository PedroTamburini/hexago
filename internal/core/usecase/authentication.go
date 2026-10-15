package usecase

import (
	"context"
	"errors"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

const (
	// dummyPassword is hashed at construction time with the configured hasher so
	// the "user not found" path performs the same work (and takes the same time)
	// as a real password comparison, which prevents user enumeration by timing.
	dummyPassword = "hexago-dummy-password"
	// dummyPasswordHash is only used if generating the dummy hash fails, which
	// should not happen with a working hasher.
	dummyPasswordHash = "$2a$12$r7RUu7gyJNGiGzipY0OFcukSIiaTOhMLqxTJJsaJGD5zLS05U1TIy"
)

type authenticationUseCase struct {
	userCredentialsFinder portout.AuthenticationRepository
	hasher                portout.PasswordHasher
	tokens                portout.TokenIssuer
	dummyHash             string
}

func NewAuthenticationUseCase(
	userCredentialsFinder portout.AuthenticationRepository,
	hasher portout.PasswordHasher,
	tokens portout.TokenIssuer,
) portin.AuthenticationUseCase {
	dummyHash := dummyPasswordHash

	if hash, err := hasher.Hash(dummyPassword); err == nil {
		dummyHash = hash
	}

	return &authenticationUseCase{
		userCredentialsFinder: userCredentialsFinder,
		hasher:                hasher,
		tokens:                tokens,
		dummyHash:             dummyHash,
	}
}

func (u *authenticationUseCase) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	credentials, err := u.userCredentialsFinder.FindCredentialsByUsername(ctx, input.Username)
	if err != nil {
		if !errors.Is(err, domainerr.ErrUserNotFound) {
			return nil, err
		}

		// Equalizes response time to prevent user enumeration.
		_ = u.hasher.Compare(u.dummyHash, input.Password)
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
