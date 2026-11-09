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

func TestChangePasswordRejectsInvalidNewPasswordBeforeLookup(t *testing.T) {
	repo := &stubCredentialsRepository{}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{}, &stubTokenVersionManager{}, &stubSessionRegistry{})

	err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeAccess,
		CurrentPassword: "current-password",
		NewPassword:     "short",
	})
	if !errors.Is(err, domainerr.ErrInvalidPassword) {
		t.Fatalf("error = %v, want ErrInvalidPassword", err)
	}

	if repo.updatePasswordCalls != 0 {
		t.Fatalf("expected no password update, got %d", repo.updatePasswordCalls)
	}
}

func TestChangePasswordPropagatesCredentialLookupError(t *testing.T) {
	findErr := errors.New("database unavailable")
	repo := &stubCredentialsRepository{credentialsByIDErr: findErr}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{}, &stubTokenVersionManager{}, &stubSessionRegistry{})

	err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeAccess,
		CurrentPassword: "current-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, findErr) {
		t.Fatalf("error = %v, want %v", err, findErr)
	}
}

func TestChangePasswordWithChangePasswordTokenRequiresTemporaryPassword(t *testing.T) {
	// A change_password token is only valid while a temporary password reset is
	// outstanding; without one the flow must be refused.
	repo := &stubCredentialsRepository{
		credentialsByID: &portout.Credentials{ID: 42, PasswordHash: "$2a$12$validhash"},
	}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{}, &stubTokenVersionManager{}, &stubSessionRegistry{})

	err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeChangePassword,
		CurrentPassword: "current-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, domainerr.ErrChangePasswordNotAllowed) {
		t.Fatalf("error = %v, want ErrChangePasswordNotAllowed", err)
	}

	if repo.updatePasswordCalls != 0 {
		t.Fatalf("expected no password update, got %d", repo.updatePasswordCalls)
	}
}

func TestChangePasswordWithAccessTokenUpdatesAndRevokes(t *testing.T) {
	const validHash = "$2a$12$validhash"

	repo := &stubCredentialsRepository{
		credentialsByID: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: "current-password"}, versions, sessions)

	if err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
		UserID:          42,
		TokenPurpose:    portout.TokenPurposeAccess,
		CurrentPassword: "current-password",
		NewPassword:     "new-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if repo.updatePasswordCalls != 1 || repo.updatedPasswordHash != validHash {
		t.Fatalf("unexpected password update: calls=%d hash=%q", repo.updatePasswordCalls, repo.updatedPasswordHash)
	}

	if versions.increase != 1 || len(sessions.removedAll) != 1 || sessions.removedAll[0] != 42 {
		t.Fatalf("expected tokens to be revoked, got %d increments and %v removals", versions.increase, sessions.removedAll)
	}
}

func TestChangePasswordPropagatesUpdateErrors(t *testing.T) {
	const validHash = "$2a$12$validhash"

	hashErr := errors.New("hashing failed")
	updateErr := errors.New("write failed")
	versionErr := errors.New("version failed")
	removeErr := errors.New("registry failed")

	t.Run("hash fails", func(t *testing.T) {
		repo := &stubCredentialsRepository{credentialsByID: &portout.Credentials{ID: 42, PasswordHash: validHash}}

		uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, hashErr: hashErr, expectedPlain: "current-password"}, &stubTokenVersionManager{}, &stubSessionRegistry{})

		err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
			UserID: 42, TokenPurpose: portout.TokenPurposeAccess,
			CurrentPassword: "current-password", NewPassword: "new-password",
		})
		if !errors.Is(err, hashErr) {
			t.Fatalf("error = %v, want %v", err, hashErr)
		}

		if repo.updatePasswordCalls != 0 {
			t.Fatalf("expected no update, got %d", repo.updatePasswordCalls)
		}
	})

	t.Run("update fails", func(t *testing.T) {
		repo := &stubCredentialsRepository{
			credentialsByID:   &portout.Credentials{ID: 42, PasswordHash: validHash},
			updatePasswordErr: updateErr,
		}

		uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: "current-password"}, &stubTokenVersionManager{}, &stubSessionRegistry{})

		err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
			UserID: 42, TokenPurpose: portout.TokenPurposeAccess,
			CurrentPassword: "current-password", NewPassword: "new-password",
		})
		if !errors.Is(err, updateErr) {
			t.Fatalf("error = %v, want %v", err, updateErr)
		}
	})

	t.Run("version increment fails", func(t *testing.T) {
		repo := &stubCredentialsRepository{credentialsByID: &portout.Credentials{ID: 42, PasswordHash: validHash}}

		uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: "current-password"}, &stubTokenVersionManager{incrementErr: versionErr}, &stubSessionRegistry{})

		err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
			UserID: 42, TokenPurpose: portout.TokenPurposeAccess,
			CurrentPassword: "current-password", NewPassword: "new-password",
		})
		if !errors.Is(err, versionErr) {
			t.Fatalf("error = %v, want %v", err, versionErr)
		}
	})

	t.Run("session removal fails", func(t *testing.T) {
		repo := &stubCredentialsRepository{credentialsByID: &portout.Credentials{ID: 42, PasswordHash: validHash}}

		uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: validHash, expectedPlain: "current-password"}, &stubTokenVersionManager{}, &stubSessionRegistry{removeAllErr: removeErr})

		err := uc.ChangePassword(context.Background(), dto.ChangePasswordInput{
			UserID: 42, TokenPurpose: portout.TokenPurposeAccess,
			CurrentPassword: "current-password", NewPassword: "new-password",
		})
		if !errors.Is(err, removeErr) {
			t.Fatalf("error = %v, want %v", err, removeErr)
		}
	})
}

func TestResetPasswordPropagatesErrors(t *testing.T) {
	hashErr := errors.New("hashing failed")
	setErr := errors.New("write failed")
	versionErr := errors.New("version failed")
	removeErr := errors.New("registry failed")

	t.Run("hash fails", func(t *testing.T) {
		uc := NewPasswordUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{hashErr: hashErr}, &stubTokenVersionManager{}, &stubSessionRegistry{})

		if _, err := uc.ResetPassword(context.Background(), dto.ResetPasswordInput{TargetID: 7}); !errors.Is(err, hashErr) {
			t.Fatalf("error = %v, want %v", err, hashErr)
		}
	})

	t.Run("set temp password fails", func(t *testing.T) {
		repo := &stubCredentialsRepository{tempPasswordErr: setErr}
		versions := &stubTokenVersionManager{}

		uc := NewPasswordUseCase(repo, &stubPasswordHasher{hash: "hash"}, versions, &stubSessionRegistry{})

		if _, err := uc.ResetPassword(context.Background(), dto.ResetPasswordInput{TargetID: 7}); !errors.Is(err, setErr) {
			t.Fatalf("error = %v, want %v", err, setErr)
		}

		if versions.increase != 0 {
			t.Fatalf("expected no revocation, got %d increments", versions.increase)
		}
	})

	t.Run("version increment fails", func(t *testing.T) {
		uc := NewPasswordUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{hash: "hash"}, &stubTokenVersionManager{incrementErr: versionErr}, &stubSessionRegistry{})

		if _, err := uc.ResetPassword(context.Background(), dto.ResetPasswordInput{TargetID: 7}); !errors.Is(err, versionErr) {
			t.Fatalf("error = %v, want %v", err, versionErr)
		}
	})

	t.Run("session removal fails", func(t *testing.T) {
		uc := NewPasswordUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{hash: "hash"}, &stubTokenVersionManager{}, &stubSessionRegistry{removeAllErr: removeErr})

		if _, err := uc.ResetPassword(context.Background(), dto.ResetPasswordInput{TargetID: 7}); !errors.Is(err, removeErr) {
			t.Fatalf("error = %v, want %v", err, removeErr)
		}
	})
}
