package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

func newTestUserUseCase(users *stubUserRepository, roles *stubRoleRepository, hasher portout.PasswordHasher) portin.UserUseCase {
	return NewUserUseCase(users, roles, hasher, &stubTokenVersionManager{}, &stubSessionRegistry{})
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

			uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, hasher)

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
		findByID: &entity.User{ID: 5, IsActive: true},
	}
	roles := &stubRoleRepository{
		isAdmin:      true,
		activeAdmins: 3,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

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
		findByID: &entity.User{ID: 5, IsActive: true},
	}
	roles := &stubRoleRepository{
		isAdmin:      true,
		activeAdmins: 1,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

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
		findByID: &entity.User{ID: 5, IsActive: true},
	}
	roles := &stubRoleRepository{
		isAdmin:      true,
		activeAdmins: 2,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

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
		findByID: &entity.User{ID: 5, IsActive: false},
	}
	roles := &stubRoleRepository{
		isAdmin:      true,
		activeAdmins: 0,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

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

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

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
	}
	roles := &stubRoleRepository{
		isAdmin: true,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 404, ActorID: 9})
	if !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	if repo.deleteCalls != 0 {
		t.Fatalf("expected the repository not to be called, got %d calls", repo.deleteCalls)
	}
}

func TestUserUseCaseSetStatusRevokesTokensWhenDeactivating(t *testing.T) {
	repo := &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}}
	versions := &stubTokenVersionManager{}
	sessions := &stubSessionRegistry{}

	uc := NewUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{}, versions, sessions)

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

	uc := NewUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{}, versions, &stubSessionRegistry{})

	if _, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{ID: 7, IsActive: false}); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	if versions.increase != 0 {
		t.Fatalf("expected no revocation for an already inactive account, got %d increments", versions.increase)
	}
}

func TestUserUseCaseSetStatusBlocksDeactivatingLastActiveAdmin(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7, IsActive: true},
	}
	roles := &stubRoleRepository{
		isAdmin:      true,
		activeAdmins: 1,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	_, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{ID: 7, ActorID: 9, IsActive: false})
	if !errors.Is(err, domainerr.ErrCannotDeactivateLastAdmin) {
		t.Fatalf("error = %v, want ErrCannotDeactivateLastAdmin", err)
	}

	if repo.statusCalls != 0 {
		t.Fatalf("expected no status update, got %d", repo.statusCalls)
	}
}

func TestUserUseCaseAssignRoleRejectsDuplicate(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7},
	}
	roles := &stubRoleRepository{
		role:    &entity.Role{ID: 3, Name: "editor"},
		hasRole: true,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	err := uc.AssignRole(context.Background(), dto.AssignRoleInput{TargetID: 7, RoleID: 3})
	if !errors.Is(err, domainerr.ErrRoleAlreadyAssigned) {
		t.Fatalf("error = %v, want ErrRoleAlreadyAssigned", err)
	}

	if roles.assignCalls != 0 {
		t.Fatalf("expected no assignment, got %d", roles.assignCalls)
	}
}

func TestUserUseCaseAssignRoleAssignsRoleByID(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7},
	}
	roles := &stubRoleRepository{
		role: &entity.Role{ID: 3, Name: "editor"},
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	if err := uc.AssignRole(context.Background(), dto.AssignRoleInput{TargetID: 7, RoleID: 3}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	if roles.assignCalls != 1 || roles.assignedUserID != 7 || roles.assignedRoleID != 3 {
		t.Fatalf("unexpected assignment: calls=%d user=%d role=%d", roles.assignCalls, roles.assignedUserID, roles.assignedRoleID)
	}
}

func TestUserUseCaseRemoveRoleBlocksRemovingLastActiveAdmin(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7, IsActive: true},
	}
	roles := &stubRoleRepository{
		role:         &entity.Role{ID: 1, Name: "admin"},
		isAdmin:      true,
		activeAdmins: 1,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	err := uc.RemoveRole(context.Background(), dto.RemoveRoleInput{TargetID: 7, RoleID: 1})
	if !errors.Is(err, domainerr.ErrCannotRemoveLastAdmin) {
		t.Fatalf("error = %v, want ErrCannotRemoveLastAdmin", err)
	}

	if roles.removeCalls != 0 {
		t.Fatalf("expected no removal, got %d", roles.removeCalls)
	}
}
