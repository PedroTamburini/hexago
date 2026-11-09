package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
)

func TestCredentialsRepositoryFindByUsernameOnlyReturnsActiveUsers(t *testing.T) {
	db := newTestDB(t)
	repo := NewCredentialsRepository(db)

	createUser(t, db, userSeed{
		name:     "JOHN DOE",
		username: "john.doe",
		email:    "john@example.com",
		hash:     "active-hash",
		active:   true,
	})
	createUser(t, db, userSeed{
		name:     "JANE DOE",
		username: "jane.doe",
		email:    "jane@example.com",
		hash:     "inactive-hash",
		active:   false,
	})

	credentials, err := repo.FindCredentialsByUsername(context.Background(), "john.doe")
	if err != nil {
		t.Fatalf("FindCredentialsByUsername: %v", err)
	}

	if credentials.PasswordHash != "active-hash" {
		t.Fatalf("PasswordHash = %q, want active-hash", credentials.PasswordHash)
	}

	if credentials.TempPasswordExpiresAt != nil {
		t.Fatalf("expected no temporary password, got %v", credentials.TempPasswordExpiresAt)
	}

	if _, err := repo.FindCredentialsByUsername(context.Background(), "jane.doe"); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("inactive user error = %v, want ErrUserNotFound", err)
	}

	if _, err := repo.FindCredentialsByUsername(context.Background(), "missing.user"); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("missing user error = %v, want ErrUserNotFound", err)
	}
}

func TestCredentialsRepositoryFindByUsernameReturnsTempPassword(t *testing.T) {
	db := newTestDB(t)
	repo := NewCredentialsRepository(db)

	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	createUser(t, db, userSeed{
		name:     "JOHN DOE",
		username: "john.doe",
		email:    "john@example.com",
		hash:     "temp-hash",
		active:   true,
		temp:     &expires,
	})

	credentials, err := repo.FindCredentialsByUsername(context.Background(), "john.doe")
	if err != nil {
		t.Fatalf("FindCredentialsByUsername: %v", err)
	}

	if credentials.TempPasswordExpiresAt == nil || !credentials.TempPasswordExpiresAt.Equal(expires) {
		t.Fatalf("TempPasswordExpiresAt = %v, want %v", credentials.TempPasswordExpiresAt, expires)
	}
}

func TestCredentialsRepositoryFindByID(t *testing.T) {
	db := newTestDB(t)
	repo := NewCredentialsRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", hash: "secret-hash", active: true})

	credentials, err := repo.FindCredentialsByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindCredentialsByID: %v", err)
	}

	if credentials.ID != seed.ID || credentials.PasswordHash != "secret-hash" {
		t.Fatalf("unexpected credentials: %+v", credentials)
	}

	if _, err := repo.FindCredentialsByID(context.Background(), 404); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("missing user error = %v, want ErrUserNotFound", err)
	}
}

func TestCredentialsRepositoryUpdatePasswordClearsTempMarker(t *testing.T) {
	db := newTestDB(t)
	repo := NewCredentialsRepository(db)

	expires := time.Now().Add(time.Hour)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", hash: "temp-hash", active: true, temp: &expires})

	if err := repo.UpdatePasswordAndClearTemp(context.Background(), seed.ID, "new-hash"); err != nil {
		t.Fatalf("UpdatePasswordAndClearTemp: %v", err)
	}

	credentials, err := repo.FindCredentialsByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindCredentialsByID: %v", err)
	}

	if credentials.PasswordHash != "new-hash" {
		t.Fatalf("PasswordHash = %q, want new-hash", credentials.PasswordHash)
	}

	if credentials.TempPasswordExpiresAt != nil {
		t.Fatalf("expected the temporary password marker to be cleared, got %v", credentials.TempPasswordExpiresAt)
	}

	if err := repo.UpdatePasswordAndClearTemp(context.Background(), 404, "new-hash"); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("missing user error = %v, want ErrUserNotFound", err)
	}
}

func TestCredentialsRepositorySetTempPassword(t *testing.T) {
	db := newTestDB(t)
	repo := NewCredentialsRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", hash: "old-hash", active: true})

	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := repo.SetTempPassword(context.Background(), seed.ID, "temp-hash", expires); err != nil {
		t.Fatalf("SetTempPassword: %v", err)
	}

	stored, err := repo.FindCredentialsByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindCredentialsByID: %v", err)
	}

	if stored.PasswordHash != "temp-hash" {
		t.Fatalf("PasswordHash = %q, want temp-hash", stored.PasswordHash)
	}

	if stored.TempPasswordExpiresAt == nil || !stored.TempPasswordExpiresAt.Equal(expires) {
		t.Fatalf("TempPasswordExpiresAt = %v, want %v", stored.TempPasswordExpiresAt, expires)
	}

	if err := repo.SetTempPassword(context.Background(), 404, "temp-hash", expires); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("missing user error = %v, want ErrUserNotFound", err)
	}
}

func TestRoleRepositoryFindRoleByID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRoleRepository(db)
	seed := createRole(t, db, "editor")

	role, err := repo.FindRoleByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindRoleByID: %v", err)
	}

	if role.ID != seed.ID || role.Name != "editor" {
		t.Fatalf("unexpected role: %+v", role)
	}

	if _, err := repo.FindRoleByID(context.Background(), 404); !errors.Is(err, domainerr.ErrRoleNotFound) {
		t.Fatalf("missing role error = %v, want ErrRoleNotFound", err)
	}
}

func TestRoleRepositoryAssignAndRemoveRole(t *testing.T) {
	db := newTestDB(t)
	repo := NewRoleRepository(db)
	user := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})
	role := createRole(t, db, "editor")

	if has, err := repo.HasRole(context.Background(), user.ID, role.ID); err != nil || has {
		t.Fatalf("HasRole before assignment = (%v, %v), want (false, nil)", has, err)
	}

	if err := repo.AssignRole(context.Background(), user.ID, role.ID); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// A repeated assignment must not fail and must not create a duplicate.
	if err := repo.AssignRole(context.Background(), user.ID, role.ID); err != nil {
		t.Fatalf("repeated AssignRole: %v", err)
	}

	if has, err := repo.HasRole(context.Background(), user.ID, role.ID); err != nil || !has {
		t.Fatalf("HasRole after assignment = (%v, %v), want (true, nil)", has, err)
	}

	if err := repo.RemoveRole(context.Background(), user.ID, role.ID); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}

	if has, err := repo.HasRole(context.Background(), user.ID, role.ID); err != nil || has {
		t.Fatalf("HasRole after removal = (%v, %v), want (false, nil)", has, err)
	}

	// Removing an assignment that does not exist is a no-op.
	if err := repo.RemoveRole(context.Background(), user.ID, role.ID); err != nil {
		t.Fatalf("repeated RemoveRole: %v", err)
	}
}

func TestRoleRepositoryIsAdmin(t *testing.T) {
	db := newTestDB(t)
	repo := NewRoleRepository(db)
	admin := createRole(t, db, model.AdminRoleName)
	editor := createRole(t, db, "editor")
	user := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})

	if isAdmin, err := repo.IsAdmin(context.Background(), user.ID); err != nil || isAdmin {
		t.Fatalf("IsAdmin before assignment = (%v, %v), want (false, nil)", isAdmin, err)
	}

	assignRole(t, db, user.ID, editor.ID)
	if isAdmin, err := repo.IsAdmin(context.Background(), user.ID); err != nil || isAdmin {
		t.Fatalf("IsAdmin with editor role = (%v, %v), want (false, nil)", isAdmin, err)
	}

	assignRole(t, db, user.ID, admin.ID)
	if isAdmin, err := repo.IsAdmin(context.Background(), user.ID); err != nil || !isAdmin {
		t.Fatalf("IsAdmin with admin role = (%v, %v), want (true, nil)", isAdmin, err)
	}
}

func TestRoleRepositoryIsAdminIgnoresSoftDeletedUser(t *testing.T) {
	db := newTestDB(t)
	repo := NewRoleRepository(db)
	admin := createRole(t, db, model.AdminRoleName)
	user := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})
	assignRole(t, db, user.ID, admin.ID)

	if err := db.Delete(&model.UserModel{}, user.ID).Error; err != nil {
		t.Fatalf("soft delete user: %v", err)
	}

	if isAdmin, err := repo.IsAdmin(context.Background(), user.ID); err != nil || isAdmin {
		t.Fatalf("IsAdmin for a deleted user = (%v, %v), want (false, nil)", isAdmin, err)
	}
}

func TestRoleRepositoryCountActiveAdmins(t *testing.T) {
	db := newTestDB(t)
	repo := NewRoleRepository(db)
	admin := createRole(t, db, model.AdminRoleName)

	if count, err := repo.CountActiveAdmins(context.Background()); err != nil || count != 0 {
		t.Fatalf("CountActiveAdmins = (%d, %v), want (0, nil)", count, err)
	}

	active := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})
	assignRole(t, db, active.ID, admin.ID)

	inactive := createUser(t, db, userSeed{name: "JANE DOE", username: "jane.doe", email: "jane@example.com", active: false})
	assignRole(t, db, inactive.ID, admin.ID)

	deleted := createUser(t, db, userSeed{name: "JIM DOE", username: "jim.doe", email: "jim@example.com", active: true})
	assignRole(t, db, deleted.ID, admin.ID)
	if err := db.Delete(&model.UserModel{}, deleted.ID).Error; err != nil {
		t.Fatalf("soft delete user: %v", err)
	}

	// A non-admin role must not be counted.
	editor := createRole(t, db, "editor")
	plain := createUser(t, db, userSeed{name: "JOE DOE", username: "joe.doe", email: "joe@example.com", active: true})
	assignRole(t, db, plain.ID, editor.ID)

	count, err := repo.CountActiveAdmins(context.Background())
	if err != nil {
		t.Fatalf("CountActiveAdmins: %v", err)
	}

	if count != 1 {
		t.Fatalf("CountActiveAdmins = %d, want 1 (inactive, deleted and non-admin excluded)", count)
	}
}

func TestAuthorizationRepositoryHasPermission(t *testing.T) {
	db := newTestDB(t)
	repo := NewAuthorizationRepository(db)

	role := createRole(t, db, "editor")
	permission := createPermission(t, db, "users.read")
	grantPermission(t, db, role.ID, permission.ID)

	user := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})
	assignRole(t, db, user.ID, role.ID)

	allowed, err := repo.HasPermission(context.Background(), user.ID, "users.read")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}

	if !allowed {
		t.Fatal("expected the granted permission to be allowed")
	}

	allowed, err = repo.HasPermission(context.Background(), user.ID, "users.write")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}

	if allowed {
		t.Fatal("expected an ungranted permission to be denied")
	}
}

func TestAuthorizationRepositoryRejectsUnknownOrInactiveUser(t *testing.T) {
	db := newTestDB(t)
	repo := NewAuthorizationRepository(db)

	permission := createPermission(t, db, "users.read")
	role := createRole(t, db, "editor")
	grantPermission(t, db, role.ID, permission.ID)

	inactive := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: false})
	assignRole(t, db, inactive.ID, role.ID)

	if _, err := repo.HasPermission(context.Background(), 404, "users.read"); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("missing user error = %v, want ErrUserNotFound", err)
	}

	if _, err := repo.HasPermission(context.Background(), inactive.ID, "users.read"); !errors.Is(err, domainerr.ErrUserInactive) {
		t.Fatalf("inactive user error = %v, want ErrUserInactive", err)
	}
}
