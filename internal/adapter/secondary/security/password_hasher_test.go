package security

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHasherRoundTrip(t *testing.T) {
	// bcrypt.MinCost keeps the test fast; the configured cost is asserted
	// separately below.
	hasher := NewPasswordHasher(bcrypt.MinCost)

	hash, err := hasher.Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}

	if err := hasher.Compare(hash, "correct-horse-battery"); err != nil {
		t.Errorf("Compare() error = %v, want nil", err)
	}

	if err := hasher.Compare(hash, "wrong-password"); err == nil {
		t.Error("Compare() error = nil, want the wrong password to be rejected")
	}
}

func TestPasswordHasherUsesTheConfiguredCost(t *testing.T) {
	hasher := NewPasswordHasher(11)

	hash, err := hasher.Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}

	if !strings.HasPrefix(hash, "$2a$11$") {
		t.Errorf("hash %q was not produced with cost 11", hash)
	}
}
