package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

func TestChangePasswordRejectsExpiredTemporaryPassword(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "current-password"
	)

	expiresAt := time.Now().Add(-time.Minute)
	repo := &stubCredentialsRepository{
		credentialsByID: &portout.Credentials{
			ID:                    42,
			PasswordHash:          validHash,
			TempPasswordExpiresAt: &expiresAt,
		},
	}
	versions := &stubTokenVersionManager{}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: plain}, versions, &stubSessionRegistry{})

	err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeChangePassword,
		CurrentPassword: plain,
		NewPassword:     "new-password",
	})
	if !errors.Is(err, domainerr.ErrTempPasswordExpired) {
		t.Fatalf("error = %v, want ErrTempPasswordExpired", err)
	}

	if repo.updatePasswordCalls != 0 || versions.increase != 0 {
		t.Fatalf("expected no update or revocation, got %d updates and %d increments", repo.updatePasswordCalls, versions.increase)
	}
}

func TestChangePasswordWithTemporaryPasswordUpdatesAndRevokes(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "current-password"
	)

	expiresAt := time.Now().Add(time.Hour)
	repo := &stubCredentialsRepository{
		credentialsByID: &portout.Credentials{
			ID:                    42,
			PasswordHash:          validHash,
			TempPasswordExpiresAt: &expiresAt,
		},
	}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: plain}, versions, sessions)

	if err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeChangePassword,
		CurrentPassword: plain,
		NewPassword:     "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if repo.updatePasswordCalls != 1 || repo.updatedPasswordID != 42 || repo.updatedPasswordHash != validHash {
		t.Fatalf("unexpected password update: calls=%d id=%d hash=%q", repo.updatePasswordCalls, repo.updatedPasswordID, repo.updatedPasswordHash)
	}

	if versions.increase != 1 || len(sessions.removedAll) != 1 || sessions.removedAll[0] != 42 {
		t.Fatalf("expected tokens to be revoked, got %d increments and %v removals", versions.increase, sessions.removedAll)
	}
}

func TestChangePasswordWithAccessTokenRequiresCurrentPassword(t *testing.T) {
	const validHash = "$2a$12$validhash"

	repo := &stubCredentialsRepository{
		credentialsByID: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: "correct-password"}, &stubTokenVersionManager{}, &stubSessionRegistry{})

	err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeAccess,
		CurrentPassword: "wrong-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, domainerr.ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}

	if repo.updatePasswordCalls != 0 {
		t.Fatalf("expected no password update, got %d", repo.updatePasswordCalls)
	}
}

func TestChangePasswordRejectsUnknownPurpose(t *testing.T) {
	repo := &stubCredentialsRepository{
		credentialsByID: &portout.Credentials{ID: 42, PasswordHash: "$2a$12$validhash"},
	}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{}, &stubTokenVersionManager{}, &stubSessionRegistry{})

	err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    "unknown",
		CurrentPassword: "current-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, domainerr.ErrChangePasswordNotAllowed) {
		t.Fatalf("error = %v, want ErrChangePasswordNotAllowed", err)
	}
}

func TestResetPasswordStoresTemporaryPasswordAndRevokesTokens(t *testing.T) {
	const hash = "$2a$12$temporaryhash"

	repo := &stubCredentialsRepository{}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: hash}, versions, sessions)

	output, err := uc.ResetPassword(context.Background(), dto.ResetPasswordInput{TargetID: 7})
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if output.TemporaryPassword == "" {
		t.Fatal("expected a temporary password to be returned")
	}

	if repo.tempPasswordCalls != 1 || repo.tempPasswordID != 7 || repo.tempPasswordHash != hash {
		t.Fatalf("unexpected temp password update: calls=%d id=%d hash=%q", repo.tempPasswordCalls, repo.tempPasswordID, repo.tempPasswordHash)
	}

	remaining := time.Until(repo.tempPasswordExpiresAt)
	if remaining <= 23*time.Hour || remaining > 25*time.Hour {
		t.Fatalf("expected a 24h expiration, got %v", remaining)
	}

	if versions.increase != 1 || len(sessions.removedAll) != 1 {
		t.Fatalf("expected tokens to be revoked, got %d increments and %v removals", versions.increase, sessions.removedAll)
	}
}
