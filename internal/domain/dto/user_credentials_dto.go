package dto

// UserCredentials carries the minimum data required to authenticate a user.
//
// It is intentionally kept out of the generic user output DTOs so the password
// hash is confined to the authentication flow and is never exposed through a
// read model that could be serialized or logged by mistake.
type UserCredentials struct {
	ID           uint64
	PasswordHash string
}
