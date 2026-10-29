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

type stubCredentialsFinder struct {
	credentials *portout.Credentials
	err         error
	calledWith  string
	calls       int
}

func (s *stubCredentialsFinder) FindCredentialsByUsername(_ context.Context, username string) (*portout.Credentials, error) {
	s.calls++
	s.calledWith = username

	if s.err != nil {
		return nil, s.err
	}

	return s.credentials, nil
}

type stubPasswordHasher struct {
	hash          string
	expectedPlain string
	hashes        int
	compares      int
	comparedHash  string
}

func (s *stubPasswordHasher) Hash(string) (string, error) {
	s.hashes++

	return s.hash, nil
}

func (s *stubPasswordHasher) Compare(hashed, plain string) error {
	s.compares++
	s.comparedHash = hashed

	if hashed != s.hash || plain != s.expectedPlain {
		return errors.New("invalid password")
	}

	return nil
}

type stubJWTService struct {
	generatedFor     uint64
	generatedVer     int
	generatedPurpose string
	generations      int
	tokenClaims      *portout.TokenClaims
	parseErr         error
}

func (s *stubJWTService) GenerateToken(userID uint64, tokenVersion int) (string, error) {
	return s.GenerateTokenWithPurpose(userID, tokenVersion, portout.TokenPurposeAccess)
}

func (s *stubJWTService) GenerateTokenWithPurpose(userID uint64, tokenVersion int, purpose string) (string, error) {
	s.generatedFor = userID
	s.generatedVer = tokenVersion
	s.generatedPurpose = purpose
	s.generations++

	return "generated-token", nil
}

func (s *stubJWTService) ExpireSeconds() int64 { return 900 }

func (s *stubJWTService) ValidateToken(string) (uint64, error) { return 0, nil }

func (s *stubJWTService) ParseClaims(string) (*portout.TokenClaims, error) {
	if s.parseErr != nil {
		return nil, s.parseErr
	}

	if s.tokenClaims != nil {
		return s.tokenClaims, nil
	}

	return &portout.TokenClaims{
		JTI:      "generated-jti",
		Subject:  "1",
		IssuedAt: time.Now(),
	}, nil
}

type stubDenylist struct {
	revoked     map[string]time.Time
	revokeCalls int
	err         error
}

func (s *stubDenylist) Revoke(_ context.Context, jti string, expiresAt time.Time) error {
	s.revokeCalls++
	if s.err != nil {
		return s.err
	}
	if s.revoked == nil {
		s.revoked = make(map[string]time.Time)
	}
	s.revoked[jti] = expiresAt

	return nil
}

func (s *stubDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	_, ok := s.revoked[jti]
	return ok, s.err
}

type stubSessionRegistry struct {
	sessions     map[string]portout.Session
	removeCalls  int
	removedAll   []uint64
	err          error
	registerCall int
}

func (s *stubSessionRegistry) Register(_ context.Context, session portout.Session) error {
	s.registerCall++
	if s.sessions == nil {
		s.sessions = make(map[string]portout.Session)
	}
	s.sessions[session.JTI] = session

	return s.err
}

func (s *stubSessionRegistry) GetByJTI(_ context.Context, jti string) (*portout.Session, error) {
	if s.err != nil {
		return nil, s.err
	}
	session, ok := s.sessions[jti]
	if !ok {
		return nil, domainerr.ErrSessionNotFound
	}

	return &session, nil
}

func (s *stubSessionRegistry) ListByUserID(_ context.Context, userID uint64) ([]*portout.Session, error) {
	if s.err != nil {
		return nil, s.err
	}

	sessions := make([]*portout.Session, 0)
	for _, session := range s.sessions {
		if session.UserID == userID {
			copied := session
			sessions = append(sessions, &copied)
		}
	}

	return sessions, nil
}

func (s *stubSessionRegistry) Remove(_ context.Context, jti string) error {
	s.removeCalls++
	delete(s.sessions, jti)

	return s.err
}

func (s *stubSessionRegistry) RemoveAllByUserID(_ context.Context, userID uint64) error {
	s.removedAll = append(s.removedAll, userID)

	return s.err
}

type stubTokenVersionManager struct {
	version  int
	increase int
	err      error
}

func (s *stubTokenVersionManager) GetVersion(context.Context, uint64) (int, error) {
	return s.version, s.err
}

func (s *stubTokenVersionManager) IncrementVersion(context.Context, uint64) (int, error) {
	s.increase++
	s.version++

	return s.version, s.err
}

type authTestDeps struct {
	finder   *stubCredentialsFinder
	hasher   *stubPasswordHasher
	jwt      *stubJWTService
	denylist *stubDenylist
	sessions *stubSessionRegistry
	tokenVer *stubTokenVersionManager
}

func newAuthUseCase(finder *stubCredentialsFinder, hasher *stubPasswordHasher, jwt *stubJWTService) portin.AuthenticationUseCase {
	denylist := &stubDenylist{}
	sessions := &stubSessionRegistry{}
	tokenVer := &stubTokenVersionManager{}

	return NewAuthenticationUseCase(finder, &stubUserRepository{}, hasher, jwt, denylist, sessions, tokenVer)
}

func TestAuthenticationUseCaseRejectsInvalidCredentials(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
	)

	testCases := []struct {
		name         string
		finder       *stubCredentialsFinder
		expectFinder bool
		expectComp   bool
	}{
		{
			name:         "unknown user",
			finder:       &stubCredentialsFinder{err: domainerr.ErrUserNotFound},
			expectFinder: true,
			expectComp:   true,
		},
		{
			name:         "wrong password",
			finder:       &stubCredentialsFinder{credentials: &portout.Credentials{ID: 7, PasswordHash: validHash}},
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

	finder := &stubCredentialsFinder{
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
	finder := &stubCredentialsFinder{
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
	finder := &stubCredentialsFinder{
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
	finder := &stubCredentialsFinder{
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

	finder := &stubCredentialsFinder{err: dbErr}
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

	finder := &stubCredentialsFinder{
		credentials: &portout.Credentials{ID: userID, PasswordHash: validHash},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{tokenClaims: claims}
	denylist := &stubDenylist{}
	sessions := &stubSessionRegistry{}
	versions := &stubTokenVersionManager{version: 4}

	uc := NewAuthenticationUseCase(finder, &stubUserRepository{}, hasher, jwt, denylist, sessions, versions)

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

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, &stubUserRepository{}, &stubPasswordHasher{}, jwt, denylist, sessions, &stubTokenVersionManager{})

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

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, &stubUserRepository{}, &stubPasswordHasher{}, jwt, denylist, &stubSessionRegistry{}, &stubTokenVersionManager{})

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

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, &stubUserRepository{}, &stubPasswordHasher{}, jwt, denylist, sessions, &stubTokenVersionManager{})

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

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, &stubUserRepository{}, &stubPasswordHasher{}, &stubJWTService{}, &stubDenylist{}, sessions, versions)

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

func TestChangePasswordRejectsExpiredTemporaryPassword(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "current-password"
	)

	expiresAt := time.Now().Add(-time.Minute)
	repo := &stubUserRepository{
		credentials: &portout.Credentials{
			ID:                    42,
			PasswordHash:          validHash,
			TempPasswordExpiresAt: &expiresAt,
		},
	}
	versions := &stubTokenVersionManager{}

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, repo, &stubPasswordHasher{hash: validHash, expectedPlain: plain}, &stubJWTService{}, &stubDenylist{}, &stubSessionRegistry{}, versions)

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
	repo := &stubUserRepository{
		credentials: &portout.Credentials{
			ID:                    42,
			PasswordHash:          validHash,
			TempPasswordExpiresAt: &expiresAt,
		},
	}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, repo, &stubPasswordHasher{hash: validHash, expectedPlain: plain}, &stubJWTService{}, &stubDenylist{}, sessions, versions)

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

	repo := &stubUserRepository{
		credentials: &portout.Credentials{ID: 42, PasswordHash: validHash},
	}

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, repo, &stubPasswordHasher{hash: validHash, expectedPlain: "correct-password"}, &stubJWTService{}, &stubDenylist{}, &stubSessionRegistry{}, &stubTokenVersionManager{})

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
	repo := &stubUserRepository{
		credentials: &portout.Credentials{ID: 42, PasswordHash: "$2a$12$validhash"},
	}

	uc := NewAuthenticationUseCase(&stubCredentialsFinder{}, repo, &stubPasswordHasher{}, &stubJWTService{}, &stubDenylist{}, &stubSessionRegistry{}, &stubTokenVersionManager{})

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
