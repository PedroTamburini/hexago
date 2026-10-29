package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

type stubTokenParser struct {
	claims *portout.TokenClaims
	err    error
}

func (s stubTokenParser) ParseClaims(_ string) (*portout.TokenClaims, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.claims, nil
}

type stubTokenDenylist struct {
	revoked bool
	err     error
}

func (s stubTokenDenylist) IsRevoked(context.Context, string) (bool, error) {
	return s.revoked, s.err
}

func (s stubTokenDenylist) Revoke(context.Context, string, time.Time) error {
	return nil
}

type stubTokenVersions struct {
	version int
	err     error
}

func (s stubTokenVersions) GetVersion(context.Context, uint64) (int, error) {
	return s.version, s.err
}

func (s stubTokenVersions) IncrementVersion(context.Context, uint64) (int, error) {
	return s.version + 1, nil
}

func testClaims() *portout.TokenClaims {
	return &portout.TokenClaims{
		JTI:       "token-jti",
		Subject:   "42",
		TokenVer:  0,
		Purpose:   portout.TokenPurposeAccess,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
}

func newTestEngine(
	parser portout.TokenParser,
	denylist portout.TokenDenylist,
	versions portout.TokenVersionManager,
	checker recordingPermissionChecker,
) *gin.Engine {
	engine := gin.New()
	engine.GET(
		"/x",
		JWTAuthMiddleware(parser, denylist, versions),
		RequirePermission(checker, "users:read"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	return engine
}

func serve(engine *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

// TestJWTAuthMiddlewareFeedsRequirePermission guards the regression that caused
// authenticated admins to be rejected: the JWT middleware used to store the user
// under "userID" while the permission middleware read "user_id".
func TestJWTAuthMiddlewareFeedsRequirePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var receivedUserID uint64
	var receivedPermission string

	checker := recordingPermissionChecker{
		userID:     &receivedUserID,
		permission: &receivedPermission,
	}

	engine := newTestEngine(
		stubTokenParser{claims: testClaims()},
		stubTokenDenylist{},
		stubTokenVersions{},
		checker,
	)

	rec := serve(engine, "valid-token")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if receivedUserID != 42 {
		t.Fatalf("checker received userID = %d, want 42", receivedUserID)
	}

	if receivedPermission != "users:read" {
		t.Fatalf("checker received permission = %q, want %q", receivedPermission, "users:read")
	}
}

func TestJWTAuthMiddlewareRejectsRevokedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checker := recordingPermissionChecker{userID: new(uint64), permission: new(string)}
	engine := newTestEngine(
		stubTokenParser{claims: testClaims()},
		stubTokenDenylist{revoked: true},
		stubTokenVersions{},
		checker,
	)

	rec := serve(engine, "revoked-token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuthMiddlewareRejectsStaleTokenVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	claims := testClaims()
	claims.TokenVer = 1

	checker := recordingPermissionChecker{userID: new(uint64), permission: new(string)}
	engine := newTestEngine(
		stubTokenParser{claims: claims},
		stubTokenDenylist{},
		stubTokenVersions{version: 2},
		checker,
	)

	rec := serve(engine, "stale-token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuthMiddlewareFailsClosedWhenDenylistIsUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checker := recordingPermissionChecker{userID: new(uint64), permission: new(string)}
	engine := newTestEngine(
		stubTokenParser{claims: testClaims()},
		stubTokenDenylist{err: context.DeadlineExceeded},
		stubTokenVersions{},
		checker,
	)

	rec := serve(engine, "valid-token")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestJWTAuthMiddlewareRejectsMissingHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checker := recordingPermissionChecker{userID: new(uint64), permission: new(string)}
	engine := newTestEngine(
		stubTokenParser{claims: testClaims()},
		stubTokenDenylist{},
		stubTokenVersions{},
		checker,
	)

	rec := serve(engine, "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuthMiddlewareRejectsPasswordChangeToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	claims := testClaims()
	claims.Purpose = portout.TokenPurposeChangePassword

	engine := gin.New()
	engine.GET("/x", JWTAuthMiddleware(
		stubTokenParser{claims: claims},
		stubTokenDenylist{},
		stubTokenVersions{},
	), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	rec := serve(engine, "temporary-token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuthMiddlewareAllowPasswordChangeAcceptsBothPurposes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name    string
		purpose string
	}{
		{name: "access token", purpose: portout.TokenPurposeAccess},
		{name: "password change token", purpose: portout.TokenPurposeChangePassword},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := testClaims()
			claims.Purpose = tc.purpose

			engine := gin.New()
			engine.GET("/x", JWTAuthMiddlewareAllowPasswordChange(
				stubTokenParser{claims: claims},
				stubTokenDenylist{},
				stubTokenVersions{},
			), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			rec := serve(engine, "token")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

func TestJWTAuthMiddlewareRejectsUnknownPurpose(t *testing.T) {
	gin.SetMode(gin.TestMode)

	claims := testClaims()
	claims.Purpose = "unknown"

	engine := gin.New()
	engine.GET("/x", JWTAuthMiddlewareAllowPasswordChange(
		stubTokenParser{claims: claims},
		stubTokenDenylist{},
		stubTokenVersions{},
	), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	rec := serve(engine, "token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

type recordingPermissionChecker struct {
	userID     *uint64
	permission *string
}

func (c recordingPermissionChecker) HasPermission(_ context.Context, userID uint64, permission string) (bool, error) {
	*c.userID = userID
	*c.permission = permission
	return true, nil
}
