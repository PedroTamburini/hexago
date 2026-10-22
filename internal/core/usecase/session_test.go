package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

func TestRevokeSessionDeniesTokenAndRemovesRecord(t *testing.T) {
	session := portout.Session{
		JTI:       "jti-1",
		UserID:    7,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	registry := &stubSessionRegistry{sessions: map[string]portout.Session{session.JTI: session}}
	denylist := &stubDenylist{}
	versions := &stubTokenVersionManager{}

	uc := NewSessionManagementUseCase(registry, denylist, versions)

	if err := uc.RevokeSession(context.Background(), session.JTI); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	if denylist.revokeCalls != 1 {
		t.Fatalf("revoke calls = %d, want 1", denylist.revokeCalls)
	}
	if !denylist.revoked[session.JTI].Equal(session.ExpiresAt) {
		t.Fatalf("denylist expiry = %v, want %v", denylist.revoked[session.JTI], session.ExpiresAt)
	}
	if registry.removeCalls != 1 {
		t.Fatalf("remove calls = %d, want 1", registry.removeCalls)
	}
}

func TestRevokeSessionUnknownReturnsNotFound(t *testing.T) {
	uc := NewSessionManagementUseCase(&stubSessionRegistry{}, &stubDenylist{}, &stubTokenVersionManager{})

	err := uc.RevokeSession(context.Background(), "missing")

	if !errors.Is(err, domainerr.ErrSessionNotFound) {
		t.Fatalf("error = %v, want ErrSessionNotFound", err)
	}
}

func TestRevokeAllUserSessionsBumpsVersionAndClearsRegistry(t *testing.T) {
	registry := &stubSessionRegistry{}
	versions := &stubTokenVersionManager{}

	uc := NewSessionManagementUseCase(registry, &stubDenylist{}, versions)

	if err := uc.RevokeAllUserSessions(context.Background(), 7); err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}

	if versions.increase != 1 {
		t.Fatalf("increments = %d, want 1", versions.increase)
	}
	if len(registry.removedAll) != 1 || registry.removedAll[0] != 7 {
		t.Fatalf("removedAll = %v, want [7]", registry.removedAll)
	}
}

func TestListUserSessionsMapsFields(t *testing.T) {
	session := portout.Session{
		JTI:       "jti-1",
		UserID:    7,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		IP:        "203.0.113.10",
		UserAgent: "agent",
	}

	registry := &stubSessionRegistry{sessions: map[string]portout.Session{session.JTI: session}}
	uc := NewSessionManagementUseCase(registry, &stubDenylist{}, &stubTokenVersionManager{})

	sessions, err := uc.ListUserSessions(context.Background(), 7)
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	if sessions[0].JTI != session.JTI || sessions[0].IP != session.IP {
		t.Fatalf("unexpected session: %+v", sessions[0])
	}
}
