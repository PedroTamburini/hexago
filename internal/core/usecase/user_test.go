package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

type stubUserRepository struct {
	users  []*entity.User
	limit  int
	offset int

	findByID    *entity.User
	findByIDErr error

	isAdmin    bool
	isAdminErr error

	activeAdmins    int64
	activeAdminsErr error

	deletedID   uint64
	deleteCalls int

	statusID     uint64
	statusActive bool
	statusCalls  int
	statusErr    error

	tempPasswordID        uint64
	tempPasswordHash      string
	tempPasswordExpiresAt time.Time
	tempPasswordCalls     int
	tempPasswordErr       error

	credentials    *portout.Credentials
	credentialsErr error

	updatedPasswordID   uint64
	updatedPasswordHash string
	updatePasswordCalls int
	updatePasswordErr   error

	role    *entity.Role
	roleErr error

	hasRole     bool
	hasRoleErr  error
	hasRoleCall int

	assignedUserID uint64
	assignedRoleID uint64
	assignCalls    int
	assignErr      error

	removedUserID uint64
	removedRoleID uint64
	removeCalls   int
	removeErr     error
}

func newTestUserUseCase(repo *stubUserRepository, hasher portout.PasswordHasher) portin.UserUseCase {
	return NewUserUseCase(repo, hasher, &stubTokenVersionManager{}, &stubSessionRegistry{})
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
	return s.isAdmin, s.isAdminErr
}

func (s *stubUserRepository) CountActiveAdmins(context.Context) (int64, error) {
	return s.activeAdmins, s.activeAdminsErr
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

			uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, hasher)

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

	err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 404, ActorID: 9})
	if !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	if repo.deleteCalls != 0 {
		t.Fatalf("expected the repository not to be called, got %d calls", repo.deleteCalls)
	}
}

func (s *stubUserRepository) SetStatus(_ context.Context, id uint64, isActive bool) error {
	s.statusCalls++
	s.statusID = id
	s.statusActive = isActive

	return s.statusErr
}

func (s *stubUserRepository) FindCredentialsByID(context.Context, uint64) (*portout.Credentials, error) {
	if s.credentialsErr != nil {
		return nil, s.credentialsErr
	}

	return s.credentials, nil
}

func (s *stubUserRepository) UpdatePasswordAndClearTemp(_ context.Context, id uint64, passwordHash string) error {
	s.updatePasswordCalls++
	s.updatedPasswordID = id
	s.updatedPasswordHash = passwordHash

	return s.updatePasswordErr
}

func (s *stubUserRepository) SetTempPassword(_ context.Context, id uint64, passwordHash string, expiresAt time.Time) error {
	s.tempPasswordCalls++
	s.tempPasswordID = id
	s.tempPasswordHash = passwordHash
	s.tempPasswordExpiresAt = expiresAt

	return s.tempPasswordErr
}

func (s *stubUserRepository) FindRoleByID(context.Context, uint64) (*entity.Role, error) {
	if s.roleErr != nil {
		return nil, s.roleErr
	}

	if s.role != nil {
		return s.role, nil
	}

	return &entity.Role{ID: 1, Name: "admin"}, nil
}

func (s *stubUserRepository) HasRole(context.Context, uint64, uint64) (bool, error) {
	s.hasRoleCall++

	return s.hasRole, s.hasRoleErr
}

func (s *stubUserRepository) AssignRole(_ context.Context, userID, roleID uint64) error {
	s.assignCalls++
	s.assignedUserID = userID
	s.assignedRoleID = roleID

	return s.assignErr
}

func (s *stubUserRepository) RemoveRole(_ context.Context, userID, roleID uint64) error {
	s.removeCalls++
	s.removedUserID = userID
	s.removedRoleID = roleID

	return s.removeErr
}

func TestUserUseCaseSetStatusRevokesTokensWhenDeactivating(t *testing.T) {
	repo := &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewUserUseCase(repo, &stubPasswordHasher{}, versions, sessions)

	output, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{
		ID:       7,
		ActorID:  9,
		IsActive: false,
	})
	if err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	if output.IsActive {
		t.Fatal("expected the account to be inactive")
	}

	if repo.statusCalls != 1 || repo.statusID != 7 || repo.statusActive {
		t.Fatalf("unexpected status update: calls=%d id=%d active=%v", repo.statusCalls, repo.statusID, repo.statusActive)
	}

	if versions.increase != 1 {
		t.Fatalf("expected the token version to be incremented once, got %d", versions.increase)
	}

	if len(sessions.removedAll) != 1 || sessions.removedAll[0] != 7 {
		t.Fatalf("expected sessions of user 7 to be removed, got %v", sessions.removedAll)
	}
}

func TestUserUseCaseSetStatusDoesNotRevokeAlreadyInactiveAccount(t *testing.T) {
	repo := &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: false}}
	versions := &stubTokenVersionManager{}

	uc := NewUserUseCase(repo, &stubPasswordHasher{}, versions, &stubSessionRegistry{})

	if _, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{ID: 7, IsActive: false}); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	if versions.increase != 0 {
		t.Fatalf("expected no revocation for an already inactive account, got %d increments", versions.increase)
	}
}

func TestUserUseCaseSetStatusBlocksDeactivatingLastActiveAdmin(t *testing.T) {
	repo := &stubUserRepository{
		findByID:     &entity.User{ID: 7, IsActive: true},
		isAdmin:      true,
		activeAdmins: 1,
	}

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

	_, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{ID: 7, ActorID: 9, IsActive: false})
	if !errors.Is(err, domainerr.ErrCannotDeactivateLastAdmin) {
		t.Fatalf("error = %v, want ErrCannotDeactivateLastAdmin", err)
	}

	if repo.statusCalls != 0 {
		t.Fatalf("expected no status update, got %d", repo.statusCalls)
	}
}

func TestUserUseCaseResetPasswordStoresTemporaryPasswordAndRevokesTokens(t *testing.T) {
	const hash = "$2a$12$temporaryhash"

	repo := &stubUserRepository{}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewUserUseCase(repo, &stubPasswordHasher{hash: hash}, versions, sessions)

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

func TestUserUseCaseAssignRoleRejectsDuplicate(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7},
		role:     &entity.Role{ID: 3, Name: "editor"},
		hasRole:  true,
	}

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

	err := uc.AssignRole(context.Background(), dto.AssignRoleInput{TargetID: 7, RoleID: 3})
	if !errors.Is(err, domainerr.ErrRoleAlreadyAssigned) {
		t.Fatalf("error = %v, want ErrRoleAlreadyAssigned", err)
	}

	if repo.assignCalls != 0 {
		t.Fatalf("expected no assignment, got %d", repo.assignCalls)
	}
}

func TestUserUseCaseAssignRoleAssignsRoleByID(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7},
		role:     &entity.Role{ID: 3, Name: "editor"},
	}

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

	if err := uc.AssignRole(context.Background(), dto.AssignRoleInput{TargetID: 7, RoleID: 3}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	if repo.assignCalls != 1 || repo.assignedUserID != 7 || repo.assignedRoleID != 3 {
		t.Fatalf("unexpected assignment: calls=%d user=%d role=%d", repo.assignCalls, repo.assignedUserID, repo.assignedRoleID)
	}
}

func TestUserUseCaseRemoveRoleBlocksRemovingLastActiveAdmin(t *testing.T) {
	repo := &stubUserRepository{
		findByID:     &entity.User{ID: 7, IsActive: true},
		role:         &entity.Role{ID: 1, Name: "admin"},
		isAdmin:      true,
		activeAdmins: 1,
	}

	uc := newTestUserUseCase(repo, &stubPasswordHasher{})

	err := uc.RemoveRole(context.Background(), dto.RemoveRoleInput{TargetID: 7, RoleID: 1})
	if !errors.Is(err, domainerr.ErrCannotRemoveLastAdmin) {
		t.Fatalf("error = %v, want ErrCannotRemoveLastAdmin", err)
	}

	if repo.removeCalls != 0 {
		t.Fatalf("expected no removal, got %d", repo.removeCalls)
	}
}
