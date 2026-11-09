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

func TestUserUseCaseCreatePersistsHashedUser(t *testing.T) {
	repo := &stubUserRepository{}
	hasher := &stubPasswordHasher{hash: "hashed-password"}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, hasher)

	output, err := uc.Create(context.Background(), dto.CreateUserInput{
		Name:     " john doe ",
		Username: " John.Doe ",
		Email:    " John@Example.com ",
		Password: "valid-password",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if hasher.hashes != 1 {
		t.Fatalf("hashes = %d, want 1", hasher.hashes)
	}

	if repo.createCalls != 1 || repo.createdUser == nil {
		t.Fatalf("expected the user to be created once, got %d calls", repo.createCalls)
	}

	if repo.createdUser.Name != "JOHN DOE" || repo.createdUser.Username != "john.doe" || repo.createdUser.Email != "john@example.com" {
		t.Fatalf("user was not normalized: %+v", repo.createdUser)
	}

	if repo.createdUser.PasswordHash != "hashed-password" {
		t.Fatalf("PasswordHash = %q, want %q", repo.createdUser.PasswordHash, "hashed-password")
	}

	if output.Name != "JOHN DOE" || output.Username != "john.doe" || output.Email != "john@example.com" {
		t.Fatalf("unexpected output: %+v", output)
	}
}

func TestUserUseCaseCreateRejectsInvalidData(t *testing.T) {
	testCases := []struct {
		name    string
		input   dto.CreateUserInput
		wantErr error
	}{
		{
			name:    "invalid name",
			input:   dto.CreateUserInput{Name: "", Username: "john.doe", Email: "john@example.com", Password: "valid-password"},
			wantErr: domainerr.ErrInvalidName,
		},
		{
			name:    "invalid username",
			input:   dto.CreateUserInput{Name: "John Doe", Username: "johndoe", Email: "john@example.com", Password: "valid-password"},
			wantErr: domainerr.ErrInvalidUsername,
		},
		{
			name:    "invalid email",
			input:   dto.CreateUserInput{Name: "John Doe", Username: "john.doe", Email: "invalid", Password: "valid-password"},
			wantErr: domainerr.ErrInvalidEmail,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubUserRepository{}
			hasher := &stubPasswordHasher{hash: "hashed-password"}

			uc := newTestUserUseCase(repo, &stubRoleRepository{}, hasher)

			output, err := uc.Create(context.Background(), tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}

			if output != nil {
				t.Fatalf("expected no output, got %+v", output)
			}

			if hasher.hashes != 0 || repo.createCalls != 0 {
				t.Fatalf("expected no side effects, got %d hashes and %d creates", hasher.hashes, repo.createCalls)
			}
		})
	}
}

func TestUserUseCaseCreatePropagatesHasherError(t *testing.T) {
	hashErr := errors.New("bcrypt unavailable")
	repo := &stubUserRepository{}
	hasher := &stubPasswordHasher{hashErr: hashErr}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, hasher)

	_, err := uc.Create(context.Background(), dto.CreateUserInput{
		Name:     "John Doe",
		Username: "john.doe",
		Email:    "john@example.com",
		Password: "valid-password",
	})

	if !errors.Is(err, hashErr) {
		t.Fatalf("error = %v, want %v", err, hashErr)
	}

	if repo.createCalls != 0 {
		t.Fatalf("expected the user not to be created, got %d calls", repo.createCalls)
	}
}

func TestUserUseCaseCreatePropagatesRepositoryError(t *testing.T) {
	repoErr := errors.New("duplicate key")
	repo := &stubUserRepository{createErr: repoErr}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{hash: "hashed-password"})

	_, err := uc.Create(context.Background(), dto.CreateUserInput{
		Name:     "John Doe",
		Username: "john.doe",
		Email:    "john@example.com",
		Password: "valid-password",
	})

	if !errors.Is(err, repoErr) {
		t.Fatalf("error = %v, want %v", err, repoErr)
	}

	if repo.createCalls != 1 {
		t.Fatalf("create calls = %d, want 1", repo.createCalls)
	}
}

func TestUserUseCaseFindByIDMapsUser(t *testing.T) {
	now := time.Now()
	repo := &stubUserRepository{
		findByID: &entity.User{
			ID:        7,
			Name:      "JOHN DOE",
			Username:  "john.doe",
			Email:     "john@example.com",
			IsActive:  true,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

	output, err := uc.FindByID(context.Background(), dto.FindUserByIDInput{ID: 7})
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if output.ID != 7 || output.Username != "john.doe" || !output.IsActive {
		t.Fatalf("unexpected output: %+v", output)
	}

	if !output.CreatedAt.Equal(now) || !output.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps were not mapped: %+v", output)
	}
}

func TestUserUseCaseFindByIDPropagatesError(t *testing.T) {
	repo := &stubUserRepository{findByIDErr: domainerr.ErrUserNotFound}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

	_, err := uc.FindByID(context.Background(), dto.FindUserByIDInput{ID: 404})
	if !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}

func TestUserUseCaseUpdateNormalizesAndPersists(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7, Name: "JOHN DOE", Username: "john.doe", Email: "john@example.com"},
	}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

	output, err := uc.Update(context.Background(), dto.UpdateUserInput{
		ID:       7,
		Name:     " jane roe ",
		Username: " Jane.Roe ",
		Email:    " Jane@Example.com ",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if repo.updateCalls != 1 {
		t.Fatalf("update calls = %d, want 1", repo.updateCalls)
	}

	if repo.updatedUser.Name != "JANE ROE" || repo.updatedUser.Username != "jane.roe" || repo.updatedUser.Email != "jane@example.com" {
		t.Fatalf("user was not normalized: %+v", repo.updatedUser)
	}

	if output.Name != "JANE ROE" || output.Username != "jane.roe" || output.Email != "jane@example.com" {
		t.Fatalf("unexpected output: %+v", output)
	}
}

func TestUserUseCaseUpdateRejectsInvalidData(t *testing.T) {
	repo := &stubUserRepository{
		findByID: &entity.User{ID: 7, Name: "JOHN DOE", Username: "john.doe", Email: "john@example.com"},
	}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

	_, err := uc.Update(context.Background(), dto.UpdateUserInput{
		ID:       7,
		Name:     "",
		Username: "jane.roe",
		Email:    "jane@example.com",
	})
	if !errors.Is(err, domainerr.ErrInvalidName) {
		t.Fatalf("error = %v, want ErrInvalidName", err)
	}

	if repo.updateCalls != 0 {
		t.Fatalf("expected no update, got %d calls", repo.updateCalls)
	}
}

func TestUserUseCaseUpdatePropagatesErrors(t *testing.T) {
	updateErr := errors.New("write failed")

	t.Run("find fails", func(t *testing.T) {
		repo := &stubUserRepository{findByIDErr: domainerr.ErrUserNotFound}

		uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

		_, err := uc.Update(context.Background(), dto.UpdateUserInput{ID: 404, Name: "John Doe", Username: "john.doe", Email: "john@example.com"})
		if !errors.Is(err, domainerr.ErrUserNotFound) {
			t.Fatalf("error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("write fails", func(t *testing.T) {
		repo := &stubUserRepository{
			findByID:  &entity.User{ID: 7},
			updateErr: updateErr,
		}

		uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

		_, err := uc.Update(context.Background(), dto.UpdateUserInput{ID: 7, Name: "John Doe", Username: "john.doe", Email: "john@example.com"})
		if !errors.Is(err, updateErr) {
			t.Fatalf("error = %v, want %v", err, updateErr)
		}
	})
}

func TestUserUseCaseFindAllPropagatesError(t *testing.T) {
	repoErr := errors.New("query failed")
	repo := &stubUserRepository{findAllErr: repoErr}

	uc := newTestUserUseCase(repo, &stubRoleRepository{}, &stubPasswordHasher{})

	_, err := uc.FindAll(context.Background(), dto.FindAllUsersInput{})
	if !errors.Is(err, repoErr) {
		t.Fatalf("error = %v, want %v", err, repoErr)
	}
}

func TestUserUseCaseDeletePropagatesDependencyErrors(t *testing.T) {
	roleErr := errors.New("role lookup failed")
	countErr := errors.New("count failed")
	deleteErr := errors.New("delete failed")

	testCases := []struct {
		name string
		repo *stubUserRepository
		role *stubRoleRepository
		want error
	}{
		{
			name: "IsAdmin fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 5}},
			role: &stubRoleRepository{isAdminErr: roleErr},
			want: roleErr,
		},
		{
			name: "CountActiveAdmins fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 5, IsActive: true}},
			role: &stubRoleRepository{isAdmin: true, activeAdminsErr: countErr},
			want: countErr,
		},
		{
			name: "Delete fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 5}, deleteErr: deleteErr},
			role: &stubRoleRepository{},
			want: deleteErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uc := newTestUserUseCase(tc.repo, tc.role, &stubPasswordHasher{})

			err := uc.Delete(context.Background(), dto.DeleteUserInput{ID: 5, ActorID: 9})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUserUseCaseSetStatusBlocksAdminSelfDeactivation(t *testing.T) {
	repo := &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}}
	roles := &stubRoleRepository{isAdmin: true, activeAdmins: 5}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	_, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{ID: 7, ActorID: 7, IsActive: false})
	if !errors.Is(err, domainerr.ErrAdminSelfDeactivate) {
		t.Fatalf("error = %v, want ErrAdminSelfDeactivate", err)
	}

	if repo.statusCalls != 0 {
		t.Fatalf("expected no status update, got %d", repo.statusCalls)
	}
}

func TestUserUseCaseSetStatusPropagatesDependencyErrors(t *testing.T) {
	roleErr := errors.New("role lookup failed")
	countErr := errors.New("count failed")
	statusErr := errors.New("write failed")
	versionErr := errors.New("version failed")
	removeErr := errors.New("remove failed")

	testCases := []struct {
		name     string
		repo     *stubUserRepository
		roles    *stubRoleRepository
		versions *stubTokenVersionManager
		sessions *stubSessionRegistry
		want     error
	}{
		{
			name: "IsAdmin fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			roles: &stubRoleRepository{isAdminErr: roleErr},
			want: roleErr,
		},
		{
			name: "CountActiveAdmins fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			roles: &stubRoleRepository{isAdmin: true, activeAdminsErr: countErr},
			want: countErr,
		},
		{
			name: "SetStatus fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}, statusErr: statusErr},
			roles: &stubRoleRepository{},
			want: statusErr,
		},
		{
			name:     "IncrementVersion fails",
			repo:     &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			roles:    &stubRoleRepository{},
			versions: &stubTokenVersionManager{incrementErr: versionErr},
			want:     versionErr,
		},
		{
			name:     "RemoveAllByUserID fails",
			repo:     &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			roles:    &stubRoleRepository{},
			sessions: &stubSessionRegistry{removeAllErr: removeErr},
			want:     removeErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			versions := tc.versions
			if versions == nil {
				versions = &stubTokenVersionManager{}
			}
			sessions := tc.sessions
			if sessions == nil {
				sessions = &stubSessionRegistry{}
			}

			uc := NewUserUseCase(tc.repo, tc.roles, &stubPasswordHasher{}, versions, sessions)

			_, err := uc.SetStatus(context.Background(), dto.SetUserStatusInput{ID: 7, ActorID: 9, IsActive: false})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUserUseCaseAssignRolePropagatesDependencyErrors(t *testing.T) {
	hasErr := errors.New("has role failed")
	assignErr := errors.New("assign failed")

	testCases := []struct {
		name string
		repo *stubUserRepository
		role *stubRoleRepository
		want error
	}{
		{
			name: "user not found",
			repo: &stubUserRepository{findByIDErr: domainerr.ErrUserNotFound},
			role: &stubRoleRepository{},
			want: domainerr.ErrUserNotFound,
		},
		{
			name: "role not found",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7}},
			role: &stubRoleRepository{roleErr: domainerr.ErrRoleNotFound},
			want: domainerr.ErrRoleNotFound,
		},
		{
			name: "HasRole fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7}},
			role: &stubRoleRepository{hasRoleErr: hasErr},
			want: hasErr,
		},
		{
			name: "AssignRole fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7}},
			role: &stubRoleRepository{role: &entity.Role{ID: 3}, assignErr: assignErr},
			want: assignErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uc := newTestUserUseCase(tc.repo, tc.role, &stubPasswordHasher{})

			err := uc.AssignRole(context.Background(), dto.AssignRoleInput{TargetID: 7, RoleID: 3})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUserUseCaseRemoveRolePropagatesDependencyErrors(t *testing.T) {
	adminErr := errors.New("is admin failed")
	countErr := errors.New("count failed")
	removeErr := errors.New("remove failed")

	testCases := []struct {
		name string
		repo *stubUserRepository
		role *stubRoleRepository
		want error
	}{
		{
			name: "user not found",
			repo: &stubUserRepository{findByIDErr: domainerr.ErrUserNotFound},
			role: &stubRoleRepository{},
			want: domainerr.ErrUserNotFound,
		},
		{
			name: "role not found",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7}},
			role: &stubRoleRepository{roleErr: domainerr.ErrRoleNotFound},
			want: domainerr.ErrRoleNotFound,
		},
		{
			name: "IsAdmin fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			role: &stubRoleRepository{role: &entity.Role{ID: 1, Name: "admin"}, isAdminErr: adminErr},
			want: adminErr,
		},
		{
			name: "CountActiveAdmins fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			role: &stubRoleRepository{role: &entity.Role{ID: 1, Name: "admin"}, isAdmin: true, activeAdminsErr: countErr},
			want: countErr,
		},
		{
			name: "RemoveRole fails",
			repo: &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}},
			role: &stubRoleRepository{role: &entity.Role{ID: 2, Name: "editor"}, removeErr: removeErr},
			want: removeErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uc := newTestUserUseCase(tc.repo, tc.role, &stubPasswordHasher{})

			err := uc.RemoveRole(context.Background(), dto.RemoveRoleInput{TargetID: 7, RoleID: 3})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUserUseCaseRemoveRoleSkipsAdminGuardForNonAdminRole(t *testing.T) {
	repo := &stubUserRepository{findByID: &entity.User{ID: 7, IsActive: true}}
	roles := &stubRoleRepository{
		role:      &entity.Role{ID: 2, Name: "editor"},
		isAdmin:   true,
		roleErr:   nil,
		removeErr: nil,
	}

	uc := newTestUserUseCase(repo, roles, &stubPasswordHasher{})

	if err := uc.RemoveRole(context.Background(), dto.RemoveRoleInput{TargetID: 7, RoleID: 2}); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}

	if roles.removeCalls != 1 || roles.removedUserID != 7 || roles.removedRoleID != 2 {
		t.Fatalf("unexpected removal: calls=%d user=%d role=%d", roles.removeCalls, roles.removedUserID, roles.removedRoleID)
	}
}
