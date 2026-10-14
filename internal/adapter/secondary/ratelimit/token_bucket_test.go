package ratelimit

import (
	"context"
	"testing"
	"time"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

func newTestBucket(t *testing.T, capacity int, refillPerSec float64) (portout.RateLimiter, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return NewTokenBucket(client, "test", capacity, refillPerSec), server
}

func TestTokenBucketBurstAndExhaustion(t *testing.T) {
	limiter, _ := newTestBucket(t, 3, 1)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		decision, err := limiter.Allow(ctx, "client")
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !decision.Allowed {
			t.Fatalf("Allow #%d denied, want allowed", i)
		}
		if want := 3 - i; decision.Remaining != want {
			t.Errorf("Allow #%d remaining = %d, want %d", i, decision.Remaining, want)
		}
	}

	decision, err := limiter.Allow(ctx, "client")
	if err != nil {
		t.Fatalf("Allow overflow: %v", err)
	}
	if decision.Allowed {
		t.Fatal("Allow overflow = allowed, want denied")
	}
	if decision.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want > 0", decision.RetryAfter)
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	// A fast refill (10 tokens/s) keeps the test quick: one token replenishes
	// every 100ms. miniredis serves TIME from the wall clock inside Lua, so a
	// short sleep is enough to observe the refill.
	limiter, _ := newTestBucket(t, 1, 10)
	ctx := context.Background()

	// Drain the single token.
	if decision, _ := limiter.Allow(ctx, "client"); !decision.Allowed {
		t.Fatal("first Allow denied, want allowed")
	}

	if decision, _ := limiter.Allow(ctx, "client"); decision.Allowed {
		t.Fatal("second Allow allowed, want denied")
	}

	time.Sleep(150 * time.Millisecond)

	decision, err := limiter.Allow(ctx, "client")
	if err != nil {
		t.Fatalf("Allow after refill: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("Allow after refill denied, want allowed")
	}
}

func TestTokenBucketSeparateKeys(t *testing.T) {
	limiter, _ := newTestBucket(t, 1, 1)
	ctx := context.Background()

	if decision, _ := limiter.Allow(ctx, "a"); !decision.Allowed {
		t.Fatal("client a first Allow denied")
	}
	if decision, _ := limiter.Allow(ctx, "a"); decision.Allowed {
		t.Fatal("client a second Allow allowed, want denied")
	}

	// A different key has its own bucket and must not be affected.
	if decision, _ := limiter.Allow(ctx, "b"); !decision.Allowed {
		t.Fatal("client b Allow denied, want allowed")
	}
}

func TestTokenBucketTTLIsPositive(t *testing.T) {
	if got := bucketTTL(60, 1); got < time.Minute {
		t.Errorf("bucketTTL = %v, want >= 1m", got)
	}
	if got := bucketTTL(10, 0.2); got < 99*time.Second || got > 101*time.Second {
		t.Errorf("bucketTTL = %v, want ~%v", got, 100*time.Second)
	}
}
