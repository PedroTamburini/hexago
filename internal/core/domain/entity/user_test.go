package entity

import (
	"errors"
	"testing"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
)

func TestNewUserNormalizesData(t *testing.T) {
	user, err := NewUser("  john DOE ", " John.Doe ", " John@Example.COM ")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	if user.Name != "JOHN DOE" {
		t.Errorf("Name = %q, want %q", user.Name, "JOHN DOE")
	}
	if user.Username != "john.doe" {
		t.Errorf("Username = %q, want %q", user.Username, "john.doe")
	}
	if user.Email != "john@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "john@example.com")
	}
	if !user.IsActive {
		t.Error("IsActive = false, want a new user to be active")
	}
}

func TestNewUserRejectsInvalidData(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		username string
		email    string
		wantErr  error
	}{
		{
			name:     "empty name",
			userName: "",
			username: "john.doe",
			email:    "john@example.com",
			wantErr:  domainerr.ErrInvalidName,
		},
		{
			name:     "name with digits",
			userName: "John 2",
			username: "john.doe",
			email:    "john@example.com",
			wantErr:  domainerr.ErrInvalidName,
		},
		{
			name:     "username without the first.last format",
			userName: "John Doe",
			username: "johndoe",
			email:    "john@example.com",
			wantErr:  domainerr.ErrInvalidUsername,
		},
		{
			name:     "username with digits",
			userName: "John Doe",
			username: "john.doe2",
			email:    "john@example.com",
			wantErr:  domainerr.ErrInvalidUsername,
		},
		{
			name:     "email without a top level domain",
			userName: "John Doe",
			username: "john.doe",
			email:    "john@example",
			wantErr:  domainerr.ErrInvalidEmail,
		},
		{
			name:     "email with consecutive dots",
			userName: "John Doe",
			username: "john.doe",
			email:    "john..doe@example.com",
			wantErr:  domainerr.ErrInvalidEmail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user, err := NewUser(tc.userName, tc.username, tc.email)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if user != nil {
				t.Fatalf("expected no user, got %+v", user)
			}
		})
	}
}

func TestUserUpdateValidatesAndNormalizes(t *testing.T) {
	user, err := NewUser("John Doe", "john.doe", "john@example.com")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	if err := user.Update(" jane ROE ", " Jane.Roe ", " Jane@Example.com "); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if user.Name != "JANE ROE" || user.Username != "jane.roe" || user.Email != "jane@example.com" {
		t.Fatalf("unexpected normalized user: %+v", user)
	}
}

func TestUserUpdateRejectsInvalidDataWithoutMutating(t *testing.T) {
	user, err := NewUser("John Doe", "john.doe", "john@example.com")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	before := *user

	if err := user.Update("", "jane.roe", "jane@example.com"); !errors.Is(err, domainerr.ErrInvalidName) {
		t.Fatalf("error = %v, want ErrInvalidName", err)
	}

	if *user != before {
		t.Fatalf("user was mutated after a failed update: %+v", user)
	}
}

func TestSetPasswordHash(t *testing.T) {
	user := &User{}

	user.SetPasswordHash("hash")

	if user.PasswordHash != "hash" {
		t.Fatalf("PasswordHash = %q, want %q", user.PasswordHash, "hash")
	}
}
