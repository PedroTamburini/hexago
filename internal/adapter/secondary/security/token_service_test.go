package security

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestJWTServiceRoundTrip(t *testing.T) {
	service := NewJWTService(testSecret, 15*time.Minute)

	token, err := service.GenerateToken(42, 3)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	userID, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if userID != 42 {
		t.Fatalf("ValidateToken = %d, want 42", userID)
	}

	claims, err := service.ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if claims.Subject != "42" {
		t.Fatalf("Subject = %q, want %q", claims.Subject, "42")
	}
	if claims.TokenVer != 3 {
		t.Fatalf("TokenVer = %d, want 3", claims.TokenVer)
	}
	if claims.JTI == "" {
		t.Fatal("JTI is empty")
	}
	if claims.ExpiresAt.IsZero() || claims.IssuedAt.IsZero() {
		t.Fatal("time claims are zero")
	}
}

func TestJWTServiceRejectsExpiredToken(t *testing.T) {
	service := NewJWTService(testSecret, -time.Minute)

	token, err := service.GenerateToken(1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if _, err := service.ValidateToken(token); err == nil {
		t.Fatal("ValidateToken accepted an expired token")
	}
	if _, err := service.ParseClaims(token); err == nil {
		t.Fatal("ParseClaims accepted an expired token")
	}
}

func TestJWTServiceRejectsWrongSecret(t *testing.T) {
	issuer := NewJWTService(testSecret, time.Minute)
	validator := NewJWTService(strings.Repeat("x", 32), time.Minute)

	token, err := issuer.GenerateToken(1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if _, err := validator.ValidateToken(token); err == nil {
		t.Fatal("ValidateToken accepted a token signed with another secret")
	}
}

func TestJWTServiceRejectsMalformedToken(t *testing.T) {
	service := NewJWTService(testSecret, time.Minute)

	if _, err := service.ParseClaims("not-a-token"); err == nil {
		t.Fatal("ParseClaims accepted a malformed token")
	}
}
