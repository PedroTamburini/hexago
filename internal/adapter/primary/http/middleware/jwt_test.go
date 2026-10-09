package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type stubTokenValidator struct {
	userID uint64
	err    error
}

func (s stubTokenValidator) ValidateToken(_ string) (uint64, error) {
	return s.userID, s.err
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

	engine := gin.New()
	engine.GET(
		"/x",
		JWTAuthMiddleware(stubTokenValidator{userID: 42}),
		RequirePermission(checker, "users:read"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

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

type recordingPermissionChecker struct {
	userID     *uint64
	permission *string
}

func (c recordingPermissionChecker) HasPermission(_ context.Context, userID uint64, permission string) (bool, error) {
	*c.userID = userID
	*c.permission = permission
	return true, nil
}
