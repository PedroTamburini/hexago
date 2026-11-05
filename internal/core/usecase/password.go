package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/domain/validator"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

const (
	// tempPasswordTTL bounds how long an administrative password reset can be
	// used to log in and choose a new password.
	tempPasswordTTL = 24 * time.Hour
)

type passwordUseCase struct {
	credentials   portout.CredentialsRepository
	hasher        portout.PasswordHasher
	tokenVersions portout.TokenVersionManager
	sessions      portout.SessionRegistry
}

func NewPasswordUseCase(
	credentials portout.CredentialsRepository,
	hasher portout.PasswordHasher,
	tokenVersions portout.TokenVersionManager,
	sessions portout.SessionRegistry,
) portin.PasswordUseCase {
	return &passwordUseCase{
		credentials:   credentials,
		hasher:        hasher,
		tokenVersions: tokenVersions,
		sessions:      sessions,
	}
}

// ChangePassword updates the password after validating the current one. The two
// allowed purposes represent the two entry points: an access token for a normal
// password change, and a change_password token for the flow started by an
// administrative reset, which requires a live temporary password. Every
// successful change revokes all tokens because the previous credentials must
// stop working immediately.
func (u *passwordUseCase) ChangePassword(ctx context.Context, input dto.ChangePasswordInput) error {
	if !validator.IsValidPassword(input.NewPassword) {
		return domainerr.ErrInvalidPassword
	}

	credentials, err := u.credentials.FindCredentialsByID(ctx, input.UserID)
	if err != nil {
		return err
	}

	switch input.TokenPurpose {
	case portout.TokenPurposeChangePassword:
		if credentials.TempPasswordExpiresAt == nil {
			return domainerr.ErrChangePasswordNotAllowed
		}

		if time.Now().After(*credentials.TempPasswordExpiresAt) {
			return domainerr.ErrTempPasswordExpired
		}

	case portout.TokenPurposeAccess:
	default:
		return domainerr.ErrChangePasswordNotAllowed
	}

	if err := u.hasher.Compare(credentials.PasswordHash, input.CurrentPassword); err != nil {
		return domainerr.ErrInvalidCredentials
	}

	newHash, err := u.hasher.Hash(input.NewPassword)
	if err != nil {
		return err
	}

	if err := u.credentials.UpdatePasswordAndClearTemp(ctx, input.UserID, newHash); err != nil {
		return err
	}

	return revokeAllUserTokens(ctx, u.tokenVersions, u.sessions, input.UserID)
}

// generateTempPassword produces a URL-safe temporary password from 12 random
// bytes. The entropy comes from crypto/rand, so the result cannot be predicted
// from previous resets.
func generateTempPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ResetPassword replaces the password with a temporary one and returns the
// plaintext exactly once, so an administrator can hand it to the user. Only the
// hash is stored, and a successful reset revokes every existing token because
// the previous password can no longer be trusted.
func (u *passwordUseCase) ResetPassword(ctx context.Context, input dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
	tempPass, err := generateTempPassword()
	if err != nil {
		return nil, err
	}

	hash, err := u.hasher.Hash(tempPass)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(tempPasswordTTL)
	if err := u.credentials.SetTempPassword(ctx, input.TargetID, hash, expiresAt); err != nil {
		return nil, err
	}

	if err := revokeAllUserTokens(ctx, u.tokenVersions, u.sessions, input.TargetID); err != nil {
		return nil, err
	}

	return &dto.ResetPasswordOutput{
		TemporaryPassword: tempPass,
	}, nil
}
