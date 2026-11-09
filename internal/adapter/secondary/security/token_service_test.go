package security

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestJWTServiceExpireSeconds(t *testing.T) {
	service := NewJWTService(testSecret, 15*time.Minute)

	if got := service.ExpireSeconds(); got != 900 {
		t.Fatalf("ExpireSeconds = %d, want 900", got)
	}
}

func TestJWTServiceNormalizesEmptyPurposeToAccess(t *testing.T) {
	service := NewJWTService(testSecret, time.Minute)

	token, err := service.GenerateTokenWithPurpose(1, 0, "")
	if err != nil {
		t.Fatalf("GenerateTokenWithPurpose: %v", err)
	}

	claims, err := service.ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}

	if claims.Purpose != "access" {
		t.Fatalf("Purpose = %q, want access", claims.Purpose)
	}
}

func TestJWTServiceParseClaimsRejectsInvalidClaims(t *testing.T) {
	service := NewJWTService(testSecret, time.Minute)

	now := time.Now()
	valid := tokenClaims{
		TokenVersion: 0,
		Purpose:      "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-1",
			Subject:   "42",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}

	testCases := []struct {
		name   string
		mutate func(*tokenClaims)
	}{
		{
			name:   "missing jti",
			mutate: func(c *tokenClaims) { c.ID = "" },
		},
		{
			name:   "invalid subject",
			mutate: func(c *tokenClaims) { c.Subject = "not-a-number" },
		},
		{
			name:   "missing issued at",
			mutate: func(c *tokenClaims) { c.IssuedAt = nil },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.mutate(&claims)

			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
			if err != nil {
				t.Fatalf("sign token: %v", err)
			}

			if _, err := service.ParseClaims(token); err == nil {
				t.Fatal("ParseClaims accepted invalid claims")
			}
		})
	}
}

func TestJWTServiceParsesLegacyTokenWithoutPurposeAsAccess(t *testing.T) {
	service := NewJWTService(testSecret, time.Minute)

	now := time.Now()
	claims := tokenClaims{
		TokenVersion: 2,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "legacy-jti",
			Subject:   "42",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	parsed, err := service.ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}

	if parsed.Purpose != "access" {
		t.Fatalf("Purpose = %q, want access for a legacy token", parsed.Purpose)
	}
}

func TestJWTServiceValidateTokenRejectsMalformedToken(t *testing.T) {
	service := NewJWTService(testSecret, time.Minute)

	if _, err := service.ValidateToken("not-a-token"); err == nil {
		t.Fatal("ValidateToken accepted a malformed token")
	}
}
