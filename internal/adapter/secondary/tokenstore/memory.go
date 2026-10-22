package tokenstore

import (
	"context"
	"sync"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

// The in-memory implementations exist so the API still runs when Redis is
// disabled (RATE_LIMIT_ENABLED=false), which is documented as a valid setup for
// local development. They are process-local: denylist and sessions are lost on
// restart and are not shared across instances. Deployments with more than one
// instance must run with Redis enabled.

type memoryTokenDenylist struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

// NewMemoryTokenDenylist builds a process-local denylist, used when Redis is
// not configured.
func NewMemoryTokenDenylist() portout.TokenDenylist {
	return &memoryTokenDenylist{revoked: make(map[string]time.Time)}
}

func (d *memoryTokenDenylist) Revoke(_ context.Context, jti string, expiresAt time.Time) error {
	now := time.Now()
	if !expiresAt.After(now) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Opportunistic cleanup keeps the map bounded without a background worker.
	for key, expiry := range d.revoked {
		if !expiry.After(now) {
			delete(d.revoked, key)
		}
	}

	d.revoked[jti] = expiresAt

	return nil
}

func (d *memoryTokenDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	expiry, ok := d.revoked[jti]
	if !ok {
		return false, nil
	}

	return expiry.After(time.Now()), nil
}

type memoryTokenVersionManager struct {
	mu       sync.Mutex
	versions map[uint64]int
}

// NewMemoryTokenVersionManager builds a process-local version manager, used
// when Redis is not configured.
func NewMemoryTokenVersionManager() portout.TokenVersionManager {
	return &memoryTokenVersionManager{versions: make(map[uint64]int)}
}

func (m *memoryTokenVersionManager) GetVersion(_ context.Context, userID uint64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.versions[userID], nil
}

func (m *memoryTokenVersionManager) IncrementVersion(_ context.Context, userID uint64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.versions[userID]++
	return m.versions[userID], nil
}

type memorySessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]portout.Session
	byUser   map[uint64]map[string]struct{}
}

// NewMemorySessionRegistry builds a process-local session registry, used when
// Redis is not configured.
func NewMemorySessionRegistry() portout.SessionRegistry {
	return &memorySessionRegistry{
		sessions: make(map[string]portout.Session),
		byUser:   make(map[uint64]map[string]struct{}),
	}
}

func (r *memorySessionRegistry) Register(_ context.Context, session portout.Session) error {
	if !session.ExpiresAt.After(time.Now()) {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessions[session.JTI] = session
	if r.byUser[session.UserID] == nil {
		r.byUser[session.UserID] = make(map[string]struct{})
	}
	r.byUser[session.UserID][session.JTI] = struct{}{}

	return nil
}

func (r *memorySessionRegistry) GetByJTI(_ context.Context, jti string) (*portout.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, ok := r.sessions[jti]
	if !ok || !session.ExpiresAt.After(time.Now()) {
		return nil, domainerr.ErrSessionNotFound
	}

	return &session, nil
}

func (r *memorySessionRegistry) ListByUserID(_ context.Context, userID uint64) ([]*portout.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	sessions := make([]*portout.Session, 0, len(r.byUser[userID]))
	for jti := range r.byUser[userID] {
		session, ok := r.sessions[jti]
		if !ok || !session.ExpiresAt.After(now) {
			delete(r.byUser[userID], jti)
			delete(r.sessions, jti)
			continue
		}
		sessions = append(sessions, &session)
	}

	return sessions, nil
}

func (r *memorySessionRegistry) Remove(_ context.Context, jti string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.sessions[jti]
	if ok {
		delete(r.byUser[session.UserID], jti)
	}
	delete(r.sessions, jti)

	return nil
}

func (r *memorySessionRegistry) RemoveAllByUserID(_ context.Context, userID uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for jti := range r.byUser[userID] {
		delete(r.sessions, jti)
	}
	delete(r.byUser, userID)

	return nil
}

var (
	_ portout.TokenDenylist       = (*memoryTokenDenylist)(nil)
	_ portout.TokenVersionManager = (*memoryTokenVersionManager)(nil)
	_ portout.SessionRegistry     = (*memorySessionRegistry)(nil)
)
