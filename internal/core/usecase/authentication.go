package usecase

import (
	"context"
	"errors"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/domain/validator"
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
	tokens                portout.TokenService
	denylist              portout.TokenDenylist
	sessions              portout.SessionRegistry
	tokenVersions         portout.TokenVersionManager
	dummyHash             string
}

func NewAuthenticationUseCase(
	userCredentialsFinder portout.AuthenticationRepository,
	hasher portout.PasswordHasher,
	tokens portout.TokenService,
	denylist portout.TokenDenylist,
	sessions portout.SessionRegistry,
	tokenVersions portout.TokenVersionManager,
) portin.AuthenticationUseCase {
	dummyHash := dummyPasswordHash

	if hash, err := hasher.Hash(dummyPassword); err == nil {
		dummyHash = hash
	}

	return &authenticationUseCase{
		userCredentialsFinder: userCredentialsFinder,
		hasher:                hasher,
		tokens:                tokens,
		denylist:              denylist,
		sessions:              sessions,
		tokenVersions:         tokenVersions,
		dummyHash:             dummyHash,
	}
}

func (u *authenticationUseCase) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	// Validated before touching the repository: a malformed password can never
	// match any account, and rejecting it here keeps the finder (and therefore
	// the database) out of the loop.
	if !validator.IsValidPassword(input.Password) {
		return nil, domainerr.ErrInvalidCredentials
	}

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

	tokenVersion, err := u.tokenVersions.GetVersion(ctx, credentials.ID)
	if err != nil {
		return nil, err
	}

	token, err := u.tokens.GenerateToken(credentials.ID, tokenVersion)
	if err != nil {
		return nil, err
	}

	// The session record powers the administrative panel and the per-session
	// revocation. Failing to record it must not fail the login: the token is
	// already valid, and the record is an observability aid.
	if claims, err := u.tokens.ParseClaims(token); err == nil {
		_ = u.sessions.Register(ctx, portout.Session{
			JTI:       claims.JTI,
			UserID:    credentials.ID,
			IssuedAt:  claims.IssuedAt,
			ExpiresAt: claims.ExpiresAt,
			IP:        input.IP,
			UserAgent: input.UserAgent,
		})
	}

	return &dto.AuthenticateOutput{
		Token:    token,
		ExpireIn: u.tokens.ExpireSeconds(),
	}, nil
}

// Logout revokes the token presented by the client. It is an alias of
// RevokeToken so callers can express intent without depending on the naming.
func (u *authenticationUseCase) Logout(ctx context.Context, token string) error {
	return u.RevokeToken(ctx, token)
}

// RevokeToken denies a single token until it would have expired and removes its
// session record. An already invalid token produces no error: revocation is
// idempotent, so a second logout does not surface as a server failure.
func (u *authenticationUseCase) RevokeToken(ctx context.Context, token string) error {
	claims, err := u.tokens.ParseClaims(token)
	if err != nil {
		return domainerr.ErrInvalidToken
	}

	if err := u.denylist.Revoke(ctx, claims.JTI, claims.ExpiresAt); err != nil {
		return err
	}

	if err := u.sessions.Remove(ctx, claims.JTI); err != nil {
		return err
	}

	return nil
}

// RevokeAllUserTokens invalidates every token of a user at once by bumping the
// token version, and clears the session records. It is the operation meant for
// flows such as a password reset or a compromised account.
func (u *authenticationUseCase) RevokeAllUserTokens(ctx context.Context, userID uint64) error {
	if _, err := u.tokenVersions.IncrementVersion(ctx, userID); err != nil {
		return err
	}

	return u.sessions.RemoveAllByUserID(ctx, userID)
}
