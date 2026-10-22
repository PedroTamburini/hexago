package tokenstore

import (
	"context"
	"testing"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

func newTestSession(userID uint64, jti string) portout.Session {
	now := time.Now()

	return portout.Session{
		JTI:       jti,
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		IP:        "203.0.113.10",
		UserAgent: "test-agent",
	}
}

func TestSessionRegistryRegisterAndList(t *testing.T) {
	client, _ := newTestClient(t)
	registry := NewSessionRegistry(client)
	ctx := context.Background()

	if err := registry.Register(ctx, newTestSession(1, "jti-a")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := registry.Register(ctx, newTestSession(1, "jti-b")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := registry.Register(ctx, newTestSession(2, "jti-c")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessions, err := registry.ListByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("len(sessions) = %d, want 2", len(sessions))
	}

	session, err := registry.GetByJTI(ctx, "jti-a")
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}
	if session.UserID != 1 || session.IP != "203.0.113.10" {
		t.Fatalf("unexpected session: %+v", session)
	}
}

func TestSessionRegistryRemove(t *testing.T) {
	client, _ := newTestClient(t)
	registry := NewSessionRegistry(client)
	ctx := context.Background()

	if err := registry.Register(ctx, newTestSession(1, "jti-a")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := registry.Remove(ctx, "jti-a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := registry.GetByJTI(ctx, "jti-a"); err != domainerr.ErrSessionNotFound {
		t.Fatalf("GetByJTI error = %v, want ErrSessionNotFound", err)
	}

	sessions, err := registry.ListByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions) = %d, want 0", len(sessions))
	}

	// Removing an unknown session is idempotent.
	if err := registry.Remove(ctx, "jti-a"); err != nil {
		t.Fatalf("Remove unknown: %v", err)
	}
}

func TestSessionRegistryRemoveAll(t *testing.T) {
	client, _ := newTestClient(t)
	registry := NewSessionRegistry(client)
	ctx := context.Background()

	for _, jti := range []string{"jti-a", "jti-b"} {
		if err := registry.Register(ctx, newTestSession(1, jti)); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	if err := registry.Register(ctx, newTestSession(2, "jti-c")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := registry.RemoveAllByUserID(ctx, 1); err != nil {
		t.Fatalf("RemoveAllByUserID: %v", err)
	}

	sessions, err := registry.ListByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions) = %d, want 0", len(sessions))
	}

	// Sessions of other users are untouched.
	if _, err := registry.GetByJTI(ctx, "jti-c"); err != nil {
		t.Fatalf("GetByJTI for another user: %v", err)
	}
}

func TestSessionRegistryPrunesExpiredEntries(t *testing.T) {
	client, server := newTestClient(t)
	registry := NewSessionRegistry(client)
	ctx := context.Background()

	if err := registry.Register(ctx, newTestSession(1, "jti-a")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Expire the payload while the index entry stays behind.
	server.FastForward(20 * time.Minute)

	sessions, err := registry.ListByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions) = %d, want 0", len(sessions))
	}
}
