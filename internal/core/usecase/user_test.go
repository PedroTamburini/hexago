package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
)

type stubUserRepository struct {
	users  []*entity.User
	limit  int
	offset int
}

func (s *stubUserRepository) Create(context.Context, *entity.User) error { return nil }

func (s *stubUserRepository) FindByID(context.Context, uint64) (*entity.User, error) {
	return nil, nil
}

func (s *stubUserRepository) FindAll(_ context.Context, limit, offset int) ([]*entity.User, error) {
	s.limit = limit
	s.offset = offset

	return s.users, nil
}

func (s *stubUserRepository) Update(context.Context, *entity.User) error { return nil }

func (s *stubUserRepository) Delete(context.Context, uint64) error { return nil }

func TestUserUseCaseFindAllNormalizesPagination(t *testing.T) {
	testCases := []struct {
		name       string
		limit      int
		offset     int
		wantLimit  int
		wantOffset int
	}{
		{
			name:      "omitted limit falls back to the default",
			limit:     0,
			offset:    0,
			wantLimit: DefaultLimit,
		},
		{
			name:      "negative limit falls back to the default",
			limit:     -5,
			offset:    0,
			wantLimit: DefaultLimit,
		},
		{
			name:      "limit above the cap is clamped",
			limit:     MaxLimit + 50,
			offset:    0,
			wantLimit: MaxLimit,
		},
		{
			name:       "valid pagination is preserved",
			limit:      10,
			offset:     30,
			wantLimit:  10,
			wantOffset: 30,
		},
		{
			name:       "negative offset is clamped",
			limit:      10,
			offset:     -1,
			wantLimit:  10,
			wantOffset: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubUserRepository{}

			uc := NewUserUseCase(repo, &stubPasswordHasher{})

			if _, err := uc.FindAll(context.Background(), dto.FindAllUsersInput{
				Limit:  tc.limit,
				Offset: tc.offset,
			}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if repo.limit != tc.wantLimit {
				t.Fatalf("expected limit %d, got %d", tc.wantLimit, repo.limit)
			}

			if repo.offset != tc.wantOffset {
				t.Fatalf("expected offset %d, got %d", tc.wantOffset, repo.offset)
			}
		})
	}
}

func TestUserUseCaseFindAllNeverRequestsZeroLimit(t *testing.T) {
	// A zero limit reaches GORM as "LIMIT 0", which silently returns an empty
	// page instead of the default one.
	repo := &stubUserRepository{}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	if _, err := uc.FindAll(context.Background(), dto.FindAllUsersInput{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.limit <= 0 {
		t.Fatalf("expected a positive limit, got %d", repo.limit)
	}
}

func TestUserUseCaseFindAllMapsUsers(t *testing.T) {
	repo := &stubUserRepository{
		users: []*entity.User{
			{ID: 1, Username: "john.doe", Email: "john@example.com", IsActive: true},
			{ID: 2, Username: "jane.doe", Email: "jane@example.com", IsActive: false},
		},
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	output, err := uc.FindAll(context.Background(), dto.FindAllUsersInput{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(output.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(output.Users))
	}

	if output.Users[0].Username != "john.doe" || !output.Users[0].IsActive {
		t.Fatalf("unexpected first user mapping: %+v", output.Users[0])
	}

	if output.Users[1].Username != "jane.doe" || output.Users[1].IsActive {
		t.Fatalf("unexpected second user mapping: %+v", output.Users[1])
	}
}

func TestUserUseCaseCreateRejectsPasswordAboveBcryptLimit(t *testing.T) {
	// 73 ascii bytes pass the rune based binding tag but exceed the 72 byte
	// limit enforced by bcrypt, which used to surface as a 500.
	hasher := &stubPasswordHasher{}
	repo := &stubUserRepository{}

	uc := NewUserUseCase(repo, hasher)

	output, err := uc.Create(context.Background(), dto.CreateUserInput{
		Name:     "John Doe",
		Username: "john.doe",
		Email:    "john@example.com",
		Password: strings.Repeat("a", 73),
	})

	if !errors.Is(err, domainerr.ErrInvalidPassword) {
		t.Fatalf("expected invalid password, got %v", err)
	}

	if output != nil {
		t.Fatalf("expected no output, got %+v", output)
	}

	if hasher.hashes != 0 {
		t.Fatalf("expected the hasher not to be called, got %d calls", hasher.hashes)
	}
}
