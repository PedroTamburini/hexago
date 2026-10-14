package middleware

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

// RateLimit rejects requests that exhaust their token bucket.
//
// It is fail-closed: when the limiter backend cannot answer, the request is
// refused with 503 instead of being allowed through unprotected. The error is
// registered with c.Error so the Logger middleware records it.
//
// A nil limiter disables the filter entirely (pass-through), which lets the
// route tree install it unconditionally and keeps the "disabled" decision in a
// single place.
func RateLimit(limiter portout.RateLimiter, keyFunc func(*gin.Context) string) gin.HandlerFunc {
	if limiter == nil {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		decision, err := limiter.Allow(c.Request.Context(), keyFunc(c))
		if err != nil {
			_ = c.Error(err)
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(
				http.StatusServiceUnavailable,
				response.ErrorResponse{Error: "rate limiter unavailable"},
			)
			return
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))

		if !decision.Allowed {
			c.Header("Retry-After", strconv.Itoa(retryAfterSeconds(decision.RetryAfter)))
			c.AbortWithStatusJSON(
				http.StatusTooManyRequests,
				response.ErrorResponse{Error: "too many requests"},
			)
			return
		}

		c.Next()
	}
}

// KeyByIP keys the bucket on the client IP. It is meant for the unauthenticated
// routes (e.g. login), where no user identity is available yet.
func KeyByIP(c *gin.Context) string {
	return c.ClientIP()
}

// KeyByUserID keys the bucket on the authenticated user. It must run after
// JWTAuthMiddleware; when no user is present it falls back to the client IP so
// the request is still bounded.
func KeyByUserID(c *gin.Context) string {
	if userID, ok := getUserID(c); ok {
		return strconv.FormatUint(userID, 10)
	}

	return "ip:" + c.ClientIP()
}

// retryAfterSeconds rounds the wait up to whole seconds, never advertising 0 so
// a conforming client always backs off for at least a moment.
func retryAfterSeconds(d time.Duration) int {
	seconds := int(math.Ceil(d.Seconds()))
	if seconds < 1 {
		return 1
	}

	return seconds
}
