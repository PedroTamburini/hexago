package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/gin-gonic/gin"
)

type stubPermissionChecker struct {
	allowed bool
	err     error
}

func (s stubPermissionChecker) HasPermission(_ context.Context, _ uint64, _ string) (bool, error) {
	return s.allowed, s.err
}

func TestRequirePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		userID     uint64
		hasUserID  bool
		checker    stubPermissionChecker
		wantStatus int
		wantCalled bool
	}{
		{
			name:       "missing user in context",
			hasUserID:  false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "allowed",
			hasUserID:  true,
			userID:     1,
			checker:    stubPermissionChecker{allowed: true},
			wantStatus: http.StatusOK,
			wantCalled: true,
		},
		{
			name:       "forbidden",
			hasUserID:  true,
			userID:     1,
			checker:    stubPermissionChecker{allowed: false},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "infrastructure error is not masked as forbidden",
			hasUserID:  true,
			userID:     1,
			checker:    stubPermissionChecker{err: errors.New("database unavailable")},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := gin.New()
			called := false

			engine.GET(
				"/x",
				func(c *gin.Context) {
					if tt.hasUserID {
						setUserID(c, tt.userID)
					}
				},
				RequirePermission(tt.checker, "users:read"),
				func(c *gin.Context) {
					called = true
					c.Status(http.StatusOK)
				},
			)

			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if called != tt.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}

var _ port.PermissionChecker = stubPermissionChecker{}
