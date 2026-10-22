package dto

import "time"

// SessionDTO represents an active session for administrative listing.
type SessionDTO struct {
	JTI       string    `json:"jti"`
	UserID    uint64    `json:"user_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	IsCurrent bool      `json:"is_current,omitempty"`
}
