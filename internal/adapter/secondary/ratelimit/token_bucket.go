package ratelimit

import (
	"context"
	"time"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	goredis "github.com/redis/go-redis/v9"
)

// tokenBucket implements portout.RateLimiter using the token bucket algorithm
// backed by a single Redis hash per key.
//
// The refill and the debit happen inside one Lua script so concurrent requests
// can never read-modify-write the same bucket at the same time. The current time
// is taken from Redis itself (TIME command) rather than the application clock,
// which keeps the refill consistent when several instances with drifting clocks
// share the same bucket.
type tokenBucket struct {
	client      *goredis.Client
	keyPrefix   string
	capacity    int
	refillPerMs float64
	ttl         time.Duration
	script      *goredis.Script
}

// rateLimitScript is evaluated atomically by Redis.
//
// KEYS[1] bucket hash (fields: tokens, ts)
// ARGV[1] capacity (burst)
// ARGV[2] refill rate in tokens per millisecond
// ARGV[3] bucket TTL in milliseconds
//
// It returns {allowed, remaining, retry_after_ms}.
var rateLimitScript = goredis.NewScript(`
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local ttl_ms = tonumber(ARGV[3])

local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  ts = now
end

local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + elapsed * refill_per_ms)

local allowed = 0
if tokens >= 1 then
  allowed = 1
  tokens = tokens - 1
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', key, ttl_ms)

local retry_ms = 0
if allowed == 0 then
  retry_ms = math.ceil((1 - tokens) / refill_per_ms)
end

return {allowed, math.floor(tokens), retry_ms}
`)

// NewTokenBucket wires a limiter for a given namespace. refillPerSec is the
// steady-state rate at which tokens are replenished (capacity is the burst).
// The prefix keeps buckets from different limiter instances (e.g. auth vs user)
// from colliding in the shared Redis keyspace.
func NewTokenBucket(client *goredis.Client, prefix string, capacity int, refillPerSec float64) portout.RateLimiter {
	return &tokenBucket{
		client:      client,
		keyPrefix:   prefix + ":",
		capacity:    capacity,
		refillPerMs: refillPerSec / 1000,
		ttl:         bucketTTL(capacity, refillPerSec),
		script:      rateLimitScript,
	}
}

func (b *tokenBucket) Allow(ctx context.Context, key string) (portout.RateLimitDecision, error) {
	values, err := b.script.Run(
		ctx,
		b.client,
		[]string{b.keyPrefix + key},
		b.capacity,
		b.refillPerMs,
		b.ttl.Milliseconds(),
	).Int64Slice()
	if err != nil {
		return portout.RateLimitDecision{}, err
	}

	return portout.RateLimitDecision{
		Allowed:    values[0] == 1,
		Limit:      b.capacity,
		Remaining:  int(values[1]),
		RetryAfter: time.Duration(values[2]) * time.Millisecond,
	}, nil
}

// bucketTTL lets an idle bucket expire once it would have refilled anyway,
// with a generous margin so a bucket is never dropped while still in use.
func bucketTTL(capacity int, refillPerSec float64) time.Duration {
	seconds := 2 * float64(capacity) / refillPerSec
	ttl := time.Duration(seconds * float64(time.Second))

	if ttl < time.Minute {
		return time.Minute
	}

	return ttl
}

var _ portout.RateLimiter = (*tokenBucket)(nil)
