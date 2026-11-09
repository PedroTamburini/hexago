package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

func newAuthUseCase(finder *stubCredentialsRepository, hasher *stubPasswordHasher, jwt *stubJWTService) portin.AuthenticationUseCase {
	denylist := &stubDenylist{}
	sessions := &stubSessionRegistry{}
	tokenVer := &stubTokenVersionManager{}

	return NewAuthenticationUseCase(finder, hasher, jwt, denylist, sessions, tokenVer)
}

func TestAuthenticationUseCaseRejectsInvalidCredentials(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
	)

	testCases := []struct {
		name         string
		finder       *stubCredentialsRepository
		expectFinder bool
		expectComp   bool
	}{
		{
			name:         "unknown user",
			finder:       &stubCredentialsRepository{err: domainerr.ErrUserNotFound},
			expectFinder: true,
			expectComp:   true,
		},
		{
			name:         "wrong password",
			finder:       &stubCredentialsRepository{credentials: &portout.Credentials{ID: 7, PasswordHash: validHash}},
			expectFinder: true,
			expectComp:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
			jwt := &stubJWTService{}

			uc := newAuthUseCase(tc.finder, hasher, jwt)

			output, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
				Username: "john.doe",
				Password: "wrong-password",
			})

			if !errors.Is(err, domainerr.ErrInvalidCredentials) {
				t.Fatalf("expected invalid credentials, got %v", err)
			}

			if output != nil {
				t.Fatalf("expected no output, got %+v", output)
			}

			if jwt.generations != 0 {
				t.Fatalf("expected no token to be generated, got %d", jwt.generations)
			}

			if tc.finder.calls != 1 {
				t.Fatalf("expected the credentials finder to be called once, got %d", tc.finder.calls)
			}

			// The username must be forwarded untouched to the finder.
			if tc.finder.calledWith != "john.doe" {
				t.Fatalf("expected finder to receive %q, got %q", "john.doe", tc.finder.calledWith)
			}

			hasherCompares := hasher.compares
			if tc.expectComp && hasherCompares != 1 {
				t.Fatalf("expected 1 password comparison, got %d", hasherCompares)
			}

			if !tc.expectComp && hasherCompares != 0 {
				t.Fatalf("expected no password comparison, got %d", hasherCompares)
			}
		})
	}
}

func TestAuthenticationUseCaseAuthenticatesActiveUser(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
		userID    = uint64(42)
	)

	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: userID, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{}

	uc := newAuthUseCase(finder, hasher, jwt)

	output, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
		Username: "john.doe",
		Password: plain,
	})
	if err != nil {
		t.Fatalf("expected successful authentication, got %v", err)
	}

	if output.Token != "generated-token" {
		t.Fatalf("expected token to be returned, got %q", output.Token)
	}

	if output.ExpireIn != 900 {
		t.Fatalf("expected expiration of 900, got %d", output.ExpireIn)
	}

	if jwt.generatedFor != userID {
		t.Fatalf("expected token generated for user %d, got %d", userID, jwt.generatedFor)
	}

	if hasher.comparedHash != validHash {
		t.Fatalf("expected comparison against the stored hash, got %q", hasher.comparedHash)
	}

	if jwt.generatedPurpose != portout.TokenPurposeAccess {
		t.Fatalf("purpose = %q, want %q", jwt.generatedPurpose, portout.TokenPurposeAccess)
	}
}

func TestAuthenticationUseCaseIssuesChangePasswordTokenForTemporaryPassword(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "temporary-password"
	)

	expiresAt := time.Now().Add(time.Hour)
	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{
			ID:                    42,
			PasswordHash:          validHash,
			TempPasswordExpiresAt: &expiresAt,
		},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{}

	uc := newAuthUseCase(finder, hasher, jwt)

	if _, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
		Username: "john.doe",
		Password: plain,
	}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if jwt.generatedPurpose != portout.TokenPurposeChangePassword {
		t.Fatalf("purpose = %q, want %q", jwt.generatedPurpose, portout.TokenPurposeChangePassword)
	}
}

func TestAuthenticationUseCaseRejectsExpiredTemporaryPassword(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "temporary-password"
	)

	expiresAt := time.Now().Add(-time.Minute)
	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{
			ID:                    42,
			PasswordHash:          validHash,
			TempPasswordExpiresAt: &expiresAt,
		},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{}

	uc := newAuthUseCase(finder, hasher, jwt)

	output, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
		Username: "john.doe",
		Password: plain,
	})

	if !errors.Is(err, domainerr.ErrTempPasswordExpired) {
		t.Fatalf("error = %v, want ErrTempPasswordExpired", err)
	}

	if output != nil {
		t.Fatalf("expected no output, got %+v", output)
	}

	if jwt.generations != 0 {
		t.Fatalf("expected no token to be generated, got %d", jwt.generations)
	}
}

func TestAuthenticationUseCaseRejectsInvalidPasswordFormat(t *testing.T) {
	// The password is rejected before the repository is queried, so a malformed
	// (or oversized) password never reaches the database.
	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: 1, PasswordHash: "$2a$12$validhash"},
	}
	hasher := &stubPasswordHasher{hash: "$2a$12$validhash", expectedPlain: "correct-password"}
	jwt := &stubJWTService{}

	uc := newAuthUseCase(finder, hasher, jwt)

	output, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
		Username: "john.doe",
		Password: strings.Repeat("a", 73),
	})

	if !errors.Is(err, domainerr.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}

	if output != nil {
		t.Fatalf("expected no output, got %+v", output)
	}

	if finder.calls != 0 {
		t.Fatalf("expected the credentials finder not to be called, got %d calls", finder.calls)
	}

	if hasher.compares != 0 {
		t.Fatalf("expected no password comparison, got %d", hasher.compares)
	}

	if jwt.generations != 0 {
		t.Fatalf("expected no token to be generated, got %d", jwt.generations)
	}
}

func TestAuthenticationUseCasePropagatesUnexpectedFinderErrors(t *testing.T) {
	dbErr := errors.New("connection refused")

	finder := &stubCredentialsRepository{err: dbErr}
	hasher := &stubPasswordHasher{}
	jwt := &stubJWTService{}

	uc := newAuthUseCase(finder, hasher, jwt)

	_, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
		Username: "john.doe",
		Password: "any-password",
	})

	if !errors.Is(err, dbErr) {
		t.Fatalf("expected the finder error to be propagated, got %v", err)
	}

	if hasher.compares != 0 {
		t.Fatalf("expected no password comparison, got %d", hasher.compares)
	}
}

func TestAuthenticationRegistersSessionWithTokenVersion(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
		userID    = uint64(42)
	)

	expiresAt := time.Now().Add(15 * time.Minute)
	claims := &portout.TokenClaims{
		JTI:       "login-jti",
		Subject:   "42",
		TokenVer:  4,
		IssuedAt:  time.Now(),
		ExpiresAt: expiresAt,
	}

	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: userID, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{tokenClaims: claims}
	denylist := &stubDenylist{}
	sessions := &stubSessionRegistry{}
	versions := &stubTokenVersionManager{version: 4}

	uc := NewAuthenticationUseCase(finder, hasher, jwt, denylist, sessions, versions)

	output, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{
		Username:  "john.doe",
		Password:  plain,
		IP:        "203.0.113.10",
		UserAgent: "agent",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if output.Token != "generated-token" {
		t.Fatalf("token = %q, want generated-token", output.Token)
	}
	if jwt.generatedVer != 4 {
		t.Fatalf("token version = %d, want 4", jwt.generatedVer)
	}

	session, ok := sessions.sessions["login-jti"]
	if !ok {
		t.Fatal("session was not registered")
	}
	if session.UserID != userID || session.IP != "203.0.113.10" || session.UserAgent != "agent" {
		t.Fatalf("unexpected session: %+v", session)
	}
	if !session.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("session expiry = %v, want %v", session.ExpiresAt, expiresAt)
	}
}

func TestRevokeTokenDeniesByJTIAndRemovesSession(t *testing.T) {
	expiresAt := time.Now().Add(15 * time.Minute)
	jwt := &stubJWTService{tokenClaims: &portout.TokenClaims{
		JTI:       "jti-1",
		Subject:   "42",
		ExpiresAt: expiresAt,
	}}
	denylist := &stubDenylist{}
	sessions := &stubSessionRegistry{}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, jwt, denylist, sessions, &stubTokenVersionManager{})

	if err := uc.RevokeToken(context.Background(), "some-token"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	if denylist.revokeCalls != 1 {
		t.Fatalf("revoke calls = %d, want 1", denylist.revokeCalls)
	}
	if !denylist.revoked["jti-1"].Equal(expiresAt) {
		t.Fatalf("denylist expiry = %v, want %v", denylist.revoked["jti-1"], expiresAt)
	}
	if sessions.removeCalls != 1 {
		t.Fatalf("remove calls = %d, want 1", sessions.removeCalls)
	}
}

func TestRevokeTokenRejectsUnparseableToken(t *testing.T) {
	jwt := &stubJWTService{parseErr: errors.New("bad token")}
	denylist := &stubDenylist{}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, jwt, denylist, &stubSessionRegistry{}, &stubTokenVersionManager{})

	err := uc.RevokeToken(context.Background(), "broken")

	if !errors.Is(err, domainerr.ErrInvalidToken) {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
	if denylist.revokeCalls != 0 {
		t.Fatalf("revoke calls = %d, want 0", denylist.revokeCalls)
	}
}

func TestLogoutIsIdempotentForRevokedToken(t *testing.T) {
	jwt := &stubJWTService{tokenClaims: &portout.TokenClaims{
		JTI:       "jti-1",
		Subject:   "42",
		ExpiresAt: time.Now().Add(time.Minute),
	}}
	denylist := &stubDenylist{}
	sessions := &stubSessionRegistry{}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, jwt, denylist, sessions, &stubTokenVersionManager{})

	if err := uc.Logout(context.Background(), "token"); err != nil {
		t.Fatalf("first Logout: %v", err)
	}
	if err := uc.Logout(context.Background(), "token"); err != nil {
		t.Fatalf("second Logout: %v", err)
	}

	if denylist.revokeCalls != 2 {
		t.Fatalf("revoke calls = %d, want 2", denylist.revokeCalls)
	}
}

func TestRevokeAllUserTokensBumpsVersionAndClearsSessions(t *testing.T) {
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, &stubJWTService{}, &stubDenylist{}, sessions, versions)

	if err := uc.RevokeAllUserTokens(context.Background(), 42); err != nil {
		t.Fatalf("RevokeAllUserTokens: %v", err)
	}

	if versions.increase != 1 {
		t.Fatalf("increments = %d, want 1", versions.increase)
	}
	if len(sessions.removedAll) != 1 || sessions.removedAll[0] != 42 {
		t.Fatalf("removedAll = %v, want [42]", sessions.removedAll)
	}
}

func TestAuthenticationUseCasePropagatesTokenVersionError(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
	)

	versionErr := errors.New("redis unavailable")
	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{}
	versions := &stubTokenVersionManager{getErr: versionErr}

	uc := NewAuthenticationUseCase(finder, hasher, jwt, &stubDenylist{}, &stubSessionRegistry{}, versions)

	_, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{Username: "john.doe", Password: plain})
	if !errors.Is(err, versionErr) {
		t.Fatalf("error = %v, want %v", err, versionErr)
	}

	if jwt.generations != 0 {
		t.Fatalf("expected no token to be generated, got %d", jwt.generations)
	}
}

func TestAuthenticationUseCasePropagatesTokenGenerationError(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
	)

	generationErr := errors.New("signing failed")
	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{generateErr: generationErr}

	uc := newAuthUseCase(finder, hasher, jwt)

	_, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{Username: "john.doe", Password: plain})
	if !errors.Is(err, generationErr) {
		t.Fatalf("error = %v, want %v", err, generationErr)
	}
}

func TestAuthenticationUseCaseIgnoresSessionRegistrationFailure(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
	)

	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{tokenClaims: &portout.TokenClaims{JTI: "jti-1", Subject: "42"}}
	sessions := &stubSessionRegistry{registerErr: errors.New("registry unavailable")}

	uc := NewAuthenticationUseCase(finder, hasher, jwt, &stubDenylist{}, sessions, &stubTokenVersionManager{})

	output, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{Username: "john.doe", Password: plain})
	if err != nil {
		t.Fatalf("Authenticate should not fail when the session cannot be recorded: %v", err)
	}

	if output.Token != "generated-token" {
		t.Fatalf("token = %q, want generated-token", output.Token)
	}

	if sessions.registerCall != 1 {
		t.Fatalf("register calls = %d, want 1", sessions.registerCall)
	}
}

func TestAuthenticationUseCaseIgnoresUnparseableGeneratedToken(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
	)

	finder := &stubCredentialsRepository{
		credentials: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{parseErr: errors.New("cannot parse")}
	sessions := &stubSessionRegistry{}

	uc := NewAuthenticationUseCase(finder, hasher, jwt, &stubDenylist{}, sessions, &stubTokenVersionManager{})

	if _, err := uc.Authenticate(context.Background(), dto.AuthenticateInput{Username: "john.doe", Password: plain}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if sessions.registerCall != 0 {
		t.Fatalf("expected no session to be registered, got %d calls", sessions.registerCall)
	}
}

func TestRevokeTokenPropagatesDenylistError(t *testing.T) {
	denyErr := errors.New("redis unavailable")
	jwt := &stubJWTService{tokenClaims: &portout.TokenClaims{JTI: "jti-1", ExpiresAt: time.Now().Add(time.Minute)}}
	denylist := &stubDenylist{err: denyErr}
	sessions := &stubSessionRegistry{}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, jwt, denylist, sessions, &stubTokenVersionManager{})

	err := uc.RevokeToken(context.Background(), "token")
	if !errors.Is(err, denyErr) {
		t.Fatalf("error = %v, want %v", err, denyErr)
	}

	if sessions.removeCalls != 0 {
		t.Fatalf("expected the session not to be removed, got %d calls", sessions.removeCalls)
	}
}

func TestRevokeTokenPropagatesSessionRemovalError(t *testing.T) {
	removeErr := errors.New("registry unavailable")
	jwt := &stubJWTService{tokenClaims: &portout.TokenClaims{JTI: "jti-1", ExpiresAt: time.Now().Add(time.Minute)}}
	sessions := &stubSessionRegistry{removeErr: removeErr}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, jwt, &stubDenylist{}, sessions, &stubTokenVersionManager{})

	err := uc.RevokeToken(context.Background(), "token")
	if !errors.Is(err, removeErr) {
		t.Fatalf("error = %v, want %v", err, removeErr)
	}
}

func TestRevokeAllUserTokensPropagatesErrors(t *testing.T) {
	incrementErr := errors.New("version failed")
	removeErr := errors.New("registry failed")

	t.Run("increment fails", func(t *testing.T) {
		versions := &stubTokenVersionManager{incrementErr: incrementErr}
		sessions := &stubSessionRegistry{}

		uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, &stubJWTService{}, &stubDenylist{}, sessions, versions)

		if err := uc.RevokeAllUserTokens(context.Background(), 42); !errors.Is(err, incrementErr) {
			t.Fatalf("error = %v, want %v", err, incrementErr)
		}

		if len(sessions.removedAll) != 0 {
			t.Fatalf("expected sessions not to be removed, got %v", sessions.removedAll)
		}
	})

	t.Run("session removal fails", func(t *testing.T) {
		versions := &stubTokenVersionManager{}
		sessions := &stubSessionRegistry{removeAllErr: removeErr}

		uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, &stubPasswordHasher{}, &stubJWTService{}, &stubDenylist{}, sessions, versions)

		if err := uc.RevokeAllUserTokens(context.Background(), 42); !errors.Is(err, removeErr) {
			t.Fatalf("error = %v, want %v", err, removeErr)
		}
	})
}

func TestNewAuthenticationUseCaseFallsBackToStaticDummyHash(t *testing.T) {
	// If the dummy hash cannot be generated the constructor must still return a
	// usable use case, falling back to the embedded hash.
	hasher := &stubPasswordHasher{hashErr: errors.New("hashing failed")}

	uc := NewAuthenticationUseCase(&stubCredentialsRepository{}, hasher, &stubJWTService{}, &stubDenylist{}, &stubSessionRegistry{}, &stubTokenVersionManager{})

	authentication, ok := uc.(*authenticationUseCase)
	if !ok {
		t.Fatalf("unexpected use case type %T", uc)
	}

	if authentication.dummyHash != dummyPasswordHash {
		t.Fatalf("dummyHash = %q, want the static fallback", authentication.dummyHash)
	}
}
