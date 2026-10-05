package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
)

type stubCredentialsFinder struct {
	credentials *dto.UserCredentials
	err         error
	calledWith  string
	calls       int
}

func (s *stubCredentialsFinder) FindCredentialsByUsername(_ context.Context, username string) (*dto.UserCredentials, error) {
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
	compares      int
	comparedHash  string
}

func (s *stubPasswordHasher) Hash(string) (string, error) {
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
	generatedFor uint64
	generations  int
}

func (s *stubJWTService) GenerateToken(userID uint64) (string, error) {
	s.generatedFor = userID
	s.generations++

	return "generated-token", nil
}

func (s *stubJWTService) ExpireSeconds() int64 { return 3600 }

func (s *stubJWTService) ValidateToken(string) (uint64, error) { return 0, nil }

func TestAuthUseCaseRejectsInvalidCredentials(t *testing.T) {
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
			name:         "inactive user",
			finder:       &stubCredentialsFinder{credentials: &dto.UserCredentials{ID: 7, PasswordHash: validHash, IsActive: false}},
			expectFinder: true,
			expectComp:   false,
		},
		{
			name:         "wrong password",
			finder:       &stubCredentialsFinder{credentials: &dto.UserCredentials{ID: 7, PasswordHash: validHash, IsActive: true}},
			expectFinder: true,
			expectComp:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
			jwt := &stubJWTService{}

			uc := NewAuthUseCase(tc.finder, hasher, jwt)

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

func TestAuthUseCaseAuthenticatesActiveUser(t *testing.T) {
	const (
		validHash = "$2a$12$validhash"
		plain     = "correct-password"
		userID    = uint64(42)
	)

	finder := &stubCredentialsFinder{
		credentials: &dto.UserCredentials{ID: userID, PasswordHash: validHash, IsActive: true},
	}
	hasher := &stubPasswordHasher{hash: validHash, expectedPlain: plain}
	jwt := &stubJWTService{}

	uc := NewAuthUseCase(finder, hasher, jwt)

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

	if output.ExpireIn != 3600 {
		t.Fatalf("expected expiration of 3600, got %d", output.ExpireIn)
	}

	if jwt.generatedFor != userID {
		t.Fatalf("expected token generated for user %d, got %d", userID, jwt.generatedFor)
	}

	if hasher.comparedHash != validHash {
		t.Fatalf("expected comparison against the stored hash, got %q", hasher.comparedHash)
	}
}

func TestAuthUseCasePropagatesUnexpectedFinderErrors(t *testing.T) {
	dbErr := errors.New("connection refused")

	finder := &stubCredentialsFinder{err: dbErr}
	hasher := &stubPasswordHasher{}
	jwt := &stubJWTService{}

	uc := NewAuthUseCase(finder, hasher, jwt)

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
