package secondary

import (
	"context"
	"time"
)

// RateLimitDecision is the outcome of a single rate limit check.
//
// It carries enough information for the caller to build the response headers
// (limit, remaining) and the Retry-After hint without knowing anything about the
// algorithm behind the decision.
type RateLimitDecision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Limit is the bucket capacity (burst) advertised to the client.
	Limit int
	// Remaining is the number of tokens left after this check.
	Remaining int
	// RetryAfter is how long the caller should wait before retrying. It is only
	// meaningful when Allowed is false.
	RetryAfter time.Duration
}

// RateLimiter decides whether a request identified by key is allowed to proceed.
//
// The algorithm (token bucket), the storage backend (Redis) and the refill
// parameters are implementation details of the adapter that satisfies this port.
// Consumers should depend only on this narrow capability.
//
// Implementations must return an error when the underlying backend is
// unavailable so the caller can decide how to fail; they must not silently allow
// the request.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (RateLimitDecision, error)
}
