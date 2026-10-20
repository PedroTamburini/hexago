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

	findByID     *entity.User
	findByIDErr  error
	isAdmin      bool
	activeAdmins int64
	deletedID    uint64
	deleteCalls  int
}

func (s *stubUserRepository) Create(context.Context, *entity.User) error { return nil }

func (s *stubUserRepository) FindByID(context.Context, uint64) (*entity.User, error) {
	return s.findByID, s.findByIDErr
}

func (s *stubUserRepository) FindAll(_ context.Context, limit, offset int) ([]*entity.User, error) {
	s.limit = limit
	s.offset = offset

	return s.users, nil
}

func (s *stubUserRepository) Update(context.Context, *entity.User) error { return nil }

func (s *stubUserRepository) Delete(_ context.Context, id uint64) error {
	s.deleteCalls++
	s.deletedID = id

	return nil
}

func (s *stubUserRepository) IsAdmin(context.Context, uint64) (bool, error) {
	return s.isAdmin, nil
}

func (s *stubUserRepository) CountActiveAdmins(context.Context) (int64, error) {
	return s.activeAdmins, nil
}

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

func TestUserUseCaseDeleteBlocksAdminSelfDeletion(t *testing.T) {
	repo := &stubUserRepository{
		findByID:     &entity.User{ID: 5, IsActive: true},
		isAdmin:      true,
		activeAdmins: 3,
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 5, ActorID: 5})
	if !errors.Is(err, domainerr.ErrAdminSelfDelete) {
		t.Fatalf("expected ErrAdminSelfDelete, got %v", err)
	}

	if repo.deleteCalls != 0 {
		t.Fatalf("expected the repository not to be called, got %d calls", repo.deleteCalls)
	}
}

func TestUserUseCaseDeleteBlocksRemovingLastActiveAdmin(t *testing.T) {
	// Another user (with users:delete) tries to remove the only active admin,
	// which would lock the application out of privileged operations.
	repo := &stubUserRepository{
		findByID:     &entity.User{ID: 5, IsActive: true},
		isAdmin:      true,
		activeAdmins: 1,
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 5, ActorID: 9})
	if !errors.Is(err, domainerr.ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin, got %v", err)
	}

	if repo.deleteCalls != 0 {
		t.Fatalf("expected the repository not to be called, got %d calls", repo.deleteCalls)
	}
}

func TestUserUseCaseDeleteAllowsAdminToRemoveAnotherAdmin(t *testing.T) {
	repo := &stubUserRepository{
		findByID:     &entity.User{ID: 5, IsActive: true},
		isAdmin:      true,
		activeAdmins: 2,
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	if err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 5, ActorID: 9}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.deleteCalls != 1 || repo.deletedID != 5 {
		t.Fatalf("expected user 5 to be deleted, got %d calls for id %d", repo.deleteCalls, repo.deletedID)
	}
}

func TestUserUseCaseDeleteAllowsRemovingDeactivatedSoleAdmin(t *testing.T) {
	// A deactivated admin cannot exercise any permission, so the account is
	// already not usable as an administrator and may be cleaned up.
	repo := &stubUserRepository{
		findByID:     &entity.User{ID: 5, IsActive: false},
		isAdmin:      true,
		activeAdmins: 0,
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	if err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 5, ActorID: 9}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.deleteCalls != 1 || repo.deletedID != 5 {
		t.Fatalf("expected user 5 to be deleted, got %d calls for id %d", repo.deleteCalls, repo.deletedID)
	}
}

func TestUserUseCaseDeleteAllowsRegularUserSelfDeletion(t *testing.T) {
	// The self-deletion restriction only applies to administrators.
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7, IsActive: true},
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	if err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 7, ActorID: 7}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.deleteCalls != 1 || repo.deletedID != 7 {
		t.Fatalf("expected user 7 to be deleted, got %d calls for id %d", repo.deleteCalls, repo.deletedID)
	}
}

func TestUserUseCaseDeletePropagatesNotFound(t *testing.T) {
	repo := &stubUserRepository{
		findByIDErr: domainerr.ErrUserNotFound,
		isAdmin:     true,
	}

	uc := NewUserUseCase(repo, &stubPasswordHasher{})

	err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 404, ActorID: 9})
	if !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	if repo.deleteCalls != 0 {
		t.Fatalf("expected the repository not to be called, got %d calls", repo.deleteCalls)
	}
}
