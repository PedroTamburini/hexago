package tokenstore

import (
	"context"
	"errors"
	"testing"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

func TestMemoryTokenDenylistRevokesActiveToken(t *testing.T) {
	denylist := NewMemoryTokenDenylist()
	ctx := context.Background()

	if err := denylist.Revoke(ctx, "jti-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, err := denylist.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}

	if !revoked {
		t.Fatal("expected the token to be revoked")
	}
}

func TestMemoryTokenDenylistIgnoresExpiredToken(t *testing.T) {
	denylist := NewMemoryTokenDenylist()
	ctx := context.Background()

	// Revoking an already expired token is pointless: the JWT itself is no
	// longer accepted, so nothing needs to be stored.
	if err := denylist.Revoke(ctx, "expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, err := denylist.IsRevoked(ctx, "expired")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}

	if revoked {
		t.Fatal("expected an expired token not to be stored")
	}
}

func TestMemoryTokenDenylistDoesNotReportUnknownToken(t *testing.T) {
	denylist := NewMemoryTokenDenylist()

	revoked, err := denylist.IsRevoked(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}

	if revoked {
		t.Fatal("expected an unknown token not to be revoked")
	}
}

func TestMemoryTokenDenylistCleansExpiredEntries(t *testing.T) {
	now := time.Now()
	denylist := &memoryTokenDenylist{revoked: map[string]time.Time{
		"expired": now.Add(-time.Minute),
		"active":  now.Add(time.Minute),
	}}

	if err := denylist.Revoke(context.Background(), "new", now.Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, ok := denylist.revoked["expired"]; ok {
		t.Fatal("expected the expired entry to be removed")
	}

	if _, ok := denylist.revoked["active"]; !ok {
		t.Fatal("expected the active entry to be preserved")
	}

	if _, ok := denylist.revoked["new"]; !ok {
		t.Fatal("expected the new entry to be stored")
	}
}

func TestMemoryTokenVersionManagerTracksUsersIndependently(t *testing.T) {
	manager := NewMemoryTokenVersionManager()
	ctx := context.Background()

	version, err := manager.GetVersion(ctx, 1)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	if version != 0 {
		t.Fatalf("initial version = %d, want 0", version)
	}

	incremented, err := manager.IncrementVersion(ctx, 1)
	if err != nil {
		t.Fatalf("IncrementVersion: %v", err)
	}

	if incremented != 1 {
		t.Fatalf("incremented version = %d, want 1", incremented)
	}

	// Another user must not be affected by the increment above.
	other, err := manager.GetVersion(ctx, 2)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	if other != 0 {
		t.Fatalf("version of user 2 = %d, want 0", other)
	}

	stored, err := manager.GetVersion(ctx, 1)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	if stored != 1 {
		t.Fatalf("stored version = %d, want 1", stored)
	}
}

func TestMemorySessionRegistryRegistersAndFindsSession(t *testing.T) {
	registry := NewMemorySessionRegistry()
	ctx := context.Background()

	session := portout.Session{
		JTI:       "jti-1",
		UserID:    7,
		ExpiresAt: time.Now().Add(time.Minute),
	}

	if err := registry.Register(ctx, session); err != nil {
		t.Fatalf("Register: %v", err)
	}

	found, err := registry.GetByJTI(ctx, session.JTI)
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}

	if found.UserID != 7 || found.JTI != session.JTI {
		t.Fatalf("unexpected session: %+v", found)
	}
}

func TestMemorySessionRegistryIgnoresExpiredSession(t *testing.T) {
	registry := NewMemorySessionRegistry()
	ctx := context.Background()

	session := portout.Session{
		JTI:       "expired",
		UserID:    7,
		ExpiresAt: time.Now().Add(-time.Minute),
	}

	if err := registry.Register(ctx, session); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := registry.GetByJTI(ctx, session.JTI); !errors.Is(err, domainerr.ErrSessionNotFound) {
		t.Fatalf("error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionRegistryListsOnlyLiveSessions(t *testing.T) {
	registry := NewMemorySessionRegistry()
	ctx := context.Background()

	registryImpl, ok := registry.(*memorySessionRegistry)
	if !ok {
		t.Fatalf("unexpected registry type %T", registry)
	}

	live := portout.Session{JTI: "live", UserID: 7, ExpiresAt: time.Now().Add(time.Minute)}
	if err := registry.Register(ctx, live); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Bypass Register to simulate a session that expired between writes.
	registryImpl.mu.Lock()
	registryImpl.sessions["stale"] = portout.Session{JTI: "stale", UserID: 7, ExpiresAt: time.Now().Add(-time.Minute)}
	registryImpl.byUser[7]["stale"] = struct{}{}
	registryImpl.mu.Unlock()

	other := portout.Session{JTI: "other", UserID: 8, ExpiresAt: time.Now().Add(time.Minute)}
	if err := registry.Register(ctx, other); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessions, err := registry.ListByUserID(ctx, 7)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}

	if len(sessions) != 1 || sessions[0].JTI != "live" {
		t.Fatalf("sessions = %+v, want only the live session", sessions)
	}

	// The stale session must be removed from both indexes.
	if _, err := registry.GetByJTI(ctx, "stale"); !errors.Is(err, domainerr.ErrSessionNotFound) {
		t.Fatalf("error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionRegistryListUnknownUserIsEmpty(t *testing.T) {
	registry := NewMemorySessionRegistry()

	sessions, err := registry.ListByUserID(context.Background(), 99)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}

	if sessions == nil || len(sessions) != 0 {
		t.Fatalf("expected an empty non-nil slice, got %#v", sessions)
	}
}

func TestMemorySessionRegistryRemovesSession(t *testing.T) {
	registry := NewMemorySessionRegistry()
	ctx := context.Background()

	session := portout.Session{JTI: "jti-1", UserID: 7, ExpiresAt: time.Now().Add(time.Minute)}
	if err := registry.Register(ctx, session); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := registry.Remove(ctx, session.JTI); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := registry.GetByJTI(ctx, session.JTI); !errors.Is(err, domainerr.ErrSessionNotFound) {
		t.Fatalf("error = %v, want ErrSessionNotFound", err)
	}

	sessions, err := registry.ListByUserID(ctx, 7)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}

	if len(sessions) != 0 {
		t.Fatalf("expected the user index to be cleaned, got %+v", sessions)
	}
}

func TestMemorySessionRegistryRemoveUnknownIsNoop(t *testing.T) {
	registry := NewMemorySessionRegistry()

	if err := registry.Remove(context.Background(), "missing"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

func TestMemorySessionRegistryRemovesAllSessionsOfUser(t *testing.T) {
	registry := NewMemorySessionRegistry()
	ctx := context.Background()

	for _, jti := range []string{"a", "b"} {
		if err := registry.Register(ctx, portout.Session{JTI: jti, UserID: 7, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	if err := registry.Register(ctx, portout.Session{JTI: "c", UserID: 8, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := registry.RemoveAllByUserID(ctx, 7); err != nil {
		t.Fatalf("RemoveAllByUserID: %v", err)
	}

	for _, jti := range []string{"a", "b"} {
		if _, err := registry.GetByJTI(ctx, jti); !errors.Is(err, domainerr.ErrSessionNotFound) {
			t.Fatalf("session %s: error = %v, want ErrSessionNotFound", jti, err)
		}
	}

	if _, err := registry.GetByJTI(ctx, "c"); err != nil {
		t.Fatalf("session of another user was removed: %v", err)
	}
}
