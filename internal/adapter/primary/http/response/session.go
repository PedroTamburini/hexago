package response

import "time"

// SessionResponse describes an active session in the administrative panel.
type SessionResponse struct {
	JTI       string    `json:"jti"`
	UserID    uint64    `json:"user_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	IsCurrent bool      `json:"is_current"`
}

// FindUserSessionsResponse wraps the session list so the payload can grow
// without breaking the response shape.
type FindUserSessionsResponse struct {
	Sessions []*SessionResponse `json:"sessions"`
}
