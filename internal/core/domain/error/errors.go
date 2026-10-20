package domainerr

import "errors"

var (
	ErrInvalidName        = errors.New("invalid name")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrInvalidEmail       = errors.New("invalid email")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserInactive       = errors.New("user inactive")
	ErrAdminSelfDelete    = errors.New("admin cannot delete own account")
	ErrLastAdmin          = errors.New("cannot delete the last active admin")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrMissingAuthHeader  = errors.New("missing authorization header")
	ErrInvalidAuthHeader  = errors.New("invalid authorization header")
	ErrInvalidToken       = errors.New("invalid access token")
)
