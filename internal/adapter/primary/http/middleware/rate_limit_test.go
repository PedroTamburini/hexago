package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

type stubRateLimiter struct {
	decision portout.RateLimitDecision
	err      error
}

func (s stubRateLimiter) Allow(_ context.Context, _ string) (portout.RateLimitDecision, error) {
	return s.decision, s.err
}

func TestRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		limiter        portout.RateLimiter
		wantStatus     int
		wantCalled     bool
		wantLimit      string
		wantRemaining  string
		wantRetryAfter string
	}{
		{
			name:          "allowed",
			limiter:       stubRateLimiter{decision: portout.RateLimitDecision{Allowed: true, Limit: 10, Remaining: 9}},
			wantStatus:    http.StatusOK,
			wantCalled:    true,
			wantLimit:     "10",
			wantRemaining: "9",
		},
		{
			name:           "exceeded",
			limiter:        stubRateLimiter{decision: portout.RateLimitDecision{Allowed: false, Limit: 10, Remaining: 0, RetryAfter: 3 * time.Second}},
			wantStatus:     http.StatusTooManyRequests,
			wantLimit:      "10",
			wantRemaining:  "0",
			wantRetryAfter: "3",
		},
		{
			name:           "backend unavailable fails closed",
			limiter:        stubRateLimiter{err: errors.New("redis unavailable")},
			wantStatus:     http.StatusServiceUnavailable,
			wantRetryAfter: "1",
		},
		{
			name:       "nil limiter is a pass-through",
			limiter:    nil,
			wantStatus: http.StatusOK,
			wantCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := gin.New()
			called := false

			engine.GET("/x", RateLimit(tt.limiter, KeyByIP), func(c *gin.Context) {
				called = true
				c.Status(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if called != tt.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tt.wantCalled)
			}

			if got := rec.Header().Get("X-RateLimit-Limit"); got != tt.wantLimit {
				t.Errorf("X-RateLimit-Limit = %q, want %q", got, tt.wantLimit)
			}

			if got := rec.Header().Get("X-RateLimit-Remaining"); got != tt.wantRemaining {
				t.Errorf("X-RateLimit-Remaining = %q, want %q", got, tt.wantRemaining)
			}

			if got := rec.Header().Get("Retry-After"); got != tt.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryAfter)
			}
		})
	}
}

func TestRateLimitKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.GET("/key", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ip":   KeyByIP(c),
			"user": KeyByUserID(c),
		})
	})

	t.Run("key by user falls back to ip when anonymous", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/key", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		engine.ServeHTTP(rec, req)

		body := rec.Body.String()
		if !strings.Contains(body, `"ip":"203.0.113.7"`) {
			t.Errorf("KeyByIP = %s, want client ip", body)
		}
		if !strings.Contains(body, `"user":"ip:203.0.113.7"`) {
			t.Errorf("KeyByUserID = %s, want ip fallback", body)
		}
	})

	t.Run("key by user uses the authenticated id", func(t *testing.T) {
		engine2 := gin.New()
		engine2.GET("/key", func(c *gin.Context) {
			setUserID(c, 42)
			c.String(http.StatusOK, KeyByUserID(c))
		})

		rec := httptest.NewRecorder()
		engine2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/key", nil))

		if got := rec.Body.String(); got != "42" {
			t.Errorf("KeyByUserID = %q, want %q", got, "42")
		}
	})
}

var _ portout.RateLimiter = stubRateLimiter{}
