package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	return c, rec
}

func TestGetUserID(t *testing.T) {
	c, _ := newTestContext()

	if _, ok := GetUserID(c); ok {
		t.Fatal("expected no user id before it is set")
	}

	setUserID(c, 42)

	userID, ok := GetUserID(c)
	if !ok || userID != 42 {
		t.Fatalf("GetUserID = (%d, %v), want (42, true)", userID, ok)
	}
}

func TestGetUserIDRejectsWrongType(t *testing.T) {
	c, _ := newTestContext()
	c.Set(string(userIDKey), "42")

	if _, ok := GetUserID(c); ok {
		t.Fatal("expected a non uint64 value to be rejected")
	}
}

func TestGetTokenJTI(t *testing.T) {
	c, _ := newTestContext()

	if _, ok := GetTokenJTI(c); ok {
		t.Fatal("expected no jti before it is set")
	}

	setTokenJTI(c, "jti-1")

	jti, ok := GetTokenJTI(c)
	if !ok || jti != "jti-1" {
		t.Fatalf("GetTokenJTI = (%q, %v), want (%q, true)", jti, ok, "jti-1")
	}

	c.Set(string(tokenJTIKey), 1)
	if _, ok := GetTokenJTI(c); ok {
		t.Fatal("expected a non string jti to be rejected")
	}
}

func TestGetTokenPurpose(t *testing.T) {
	c, _ := newTestContext()

	if _, ok := GetTokenPurpose(c); ok {
		t.Fatal("expected no purpose before it is set")
	}

	setTokenPurpose(c, "access")

	purpose, ok := GetTokenPurpose(c)
	if !ok || purpose != "access" {
		t.Fatalf("GetTokenPurpose = (%q, %v), want (%q, true)", purpose, ok, "access")
	}

	c.Set(string(tokenPurposeKey), 1)
	if _, ok := GetTokenPurpose(c); ok {
		t.Fatal("expected a non string purpose to be rejected")
	}
}

func TestGetRequestIDRejectsWrongType(t *testing.T) {
	c, _ := newTestContext()
	c.Set(string(requestIDKey), 123)

	if got := getRequestID(c); got != "" {
		t.Fatalf("getRequestID = %q, want an empty string", got)
	}
}
