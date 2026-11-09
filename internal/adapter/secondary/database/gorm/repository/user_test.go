package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/model"
	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapUserRepositoryError(t *testing.T) {
	unique := &pgconn.PgError{Code: "23505"}
	other := &pgconn.PgError{Code: "23503"}
	plain := errors.New("boom")

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "unique violation maps to conflict", err: unique, want: domainerr.ErrUserAlreadyExists},
		{name: "other pg error is preserved", err: other, want: other},
		{name: "plain error is preserved", err: plain, want: plain},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapUserRepositoryError(tc.err)

			if !errors.Is(got, tc.want) {
				t.Fatalf("error = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUserRepositoryCreateAssignsID(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)

	user, err := entity.NewUser("John Doe", "john.doe", "john@example.com")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	user.SetPasswordHash("hash")

	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if user.ID == 0 {
		t.Fatal("expected the repository to assign an ID")
	}
}

func TestUserRepositoryFindByIDHidesPasswordHash(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", hash: "secret-hash", active: true})

	user, err := repo.FindByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if user.ID != seed.ID || user.Username != "john.doe" {
		t.Fatalf("unexpected user: %+v", user)
	}

	if user.PasswordHash != "" {
		t.Fatalf("PasswordHash leaked through FindByID: %q", user.PasswordHash)
	}
}

func TestUserRepositoryFindByIDReturnsNotFound(t *testing.T) {
	repo := NewUserRepository(newTestDB(t))

	_, err := repo.FindByID(context.Background(), 404)
	if !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}

func TestUserRepositoryFindByIDIgnoresSoftDeletedUser(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})

	if err := repo.Delete(context.Background(), seed.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := repo.FindByID(context.Background(), seed.ID); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}

func TestUserRepositoryFindAllPaginatesAndOrders(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)

	for _, username := range []string{"a.one", "b.two", "c.three"} {
		createUser(t, db, userSeed{
			name:     "User",
			username: username,
			email:    username + "@example.com",
			active:   true,
		})
	}

	users, err := repo.FindAll(context.Background(), 2, 1)
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("len(users) = %d, want 2", len(users))
	}

	if users[0].Username != "b.two" || users[1].Username != "c.three" {
		t.Fatalf("unexpected order: %+v", users)
	}
}

func TestUserRepositorySetStatus(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})

	if err := repo.SetStatus(context.Background(), seed.ID, false); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	user, err := repo.FindByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if user.IsActive {
		t.Fatal("expected the user to be deactivated")
	}
}

func TestUserRepositorySetStatusReturnsNotFound(t *testing.T) {
	repo := NewUserRepository(newTestDB(t))

	if err := repo.SetStatus(context.Background(), 404, false); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}

func TestUserRepositoryDeleteIsSoftAndFreesIdentity(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})

	if err := repo.Delete(context.Background(), seed.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// The row stays in the table but is inactive and outside the read paths.
	var stored model.UserModel
	if err := db.Unscoped().First(&stored, seed.ID).Error; err != nil {
		t.Fatalf("expected the row to remain: %v", err)
	}

	if stored.IsActive {
		t.Fatal("expected the deleted user to be inactive")
	}

	if !stored.DeletedAt.Valid {
		t.Fatal("expected the row to be soft deleted")
	}

	// The partial unique indexes only cover live rows, so the identity can be
	// registered again.
	replacement := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})
	if replacement.ID == seed.ID {
		t.Fatal("expected a new row for the reused identity")
	}
}

func TestUserRepositoryDeleteReturnsNotFoundForMissingUser(t *testing.T) {
	repo := NewUserRepository(newTestDB(t))

	if err := repo.Delete(context.Background(), 404); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}

func TestUserRepositoryUpdateChangesFields(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)
	seed := createUser(t, db, userSeed{name: "JOHN DOE", username: "john.doe", email: "john@example.com", active: true})

	user, err := repo.FindByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if err := user.Update("Jane Roe", "jane.roe", "jane@example.com"); err != nil {
		t.Fatalf("Update entity: %v", err)
	}

	if err := repo.Update(context.Background(), user); err != nil {
		t.Fatalf("Update: %v", err)
	}

	stored, err := repo.FindByID(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if stored.Name != "JANE ROE" || stored.Username != "jane.roe" || stored.Email != "jane@example.com" {
		t.Fatalf("unexpected stored user: %+v", stored)
	}
}

func TestUserRepositoryUpdateReturnsNotFound(t *testing.T) {
	db := newTestDB(t)
	repo := NewUserRepository(db)

	user := &entity.User{
		ID:       404,
		Name:     "JOHN DOE",
		Username: "john.doe",
		Email:    "john@example.com",
	}

	if err := repo.Update(context.Background(), user); !errors.Is(err, domainerr.ErrUserNotFound) {
		t.Fatalf("error = %v, want ErrUserNotFound", err)
	}
}
