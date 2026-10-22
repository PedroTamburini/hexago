package tokenstore

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

func newTestClient(t *testing.T) (*goredis.Client, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return client, server
}

func TestTokenDenylistRevokeUntilExpiration(t *testing.T) {
	client, server := newTestClient(t)
	denylist := NewTokenDenylist(client)
	ctx := context.Background()

	expiresAt := time.Now().Add(time.Minute)

	if err := denylist.Revoke(ctx, "jti-1", expiresAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, err := denylist.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("IsRevoked = false, want true")
	}

	// The entry must disappear on its own once the token would have expired.
	server.FastForward(2 * time.Minute)

	revoked, err = denylist.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked after expiry: %v", err)
	}
	if revoked {
		t.Fatal("IsRevoked after expiry = true, want false")
	}
}

func TestTokenDenylistIgnoresAlreadyExpiredToken(t *testing.T) {
	client, _ := newTestClient(t)
	denylist := NewTokenDenylist(client)
	ctx := context.Background()

	if err := denylist.Revoke(ctx, "jti-1", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, err := denylist.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("an already expired token must not be stored")
	}
}
