package tokenstore

import (
	"context"
	"time"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	goredis "github.com/redis/go-redis/v9"
)

// denylistKeyPrefix namespaces the revoked-token keys in the shared Redis
// keyspace (the same database used by the rate limiter and the session
// registry, separated by prefix).
const denylistKeyPrefix = "denylist:token:"

type tokenDenylist struct {
	client *goredis.Client
}

// NewTokenDenylist builds a Redis-backed denylist.
func NewTokenDenylist(client *goredis.Client) portout.TokenDenylist {
	return &tokenDenylist{client: client}
}

// Revoke records the token ID until the token would have expired. The TTL makes
// Redis evict the entry on its own, so the denylist never grows beyond the
// tokens that are still valid.
func (d *tokenDenylist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// The token is already expired: it will be rejected for that reason,
		// so there is nothing to revoke.
		return nil
	}

	return d.client.SetEx(ctx, denylistKeyPrefix+jti, "1", ttl).Err()
}

func (d *tokenDenylist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := d.client.Exists(ctx, denylistKeyPrefix+jti).Result()
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

var _ portout.TokenDenylist = (*tokenDenylist)(nil)
