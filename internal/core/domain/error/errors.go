package domainerr

import "errors"

var (
	ErrInvalidName               = errors.New("invalid name")
	ErrInvalidUsername           = errors.New("invalid username")
	ErrInvalidEmail              = errors.New("invalid email")
	ErrInvalidPassword           = errors.New("invalid password")
	ErrUserAlreadyExists         = errors.New("user already exists")
	ErrUserNotFound              = errors.New("user not found")
	ErrUserInactive              = errors.New("user inactive")
	ErrAdminSelfDelete           = errors.New("admin cannot delete own account")
	ErrLastAdmin                 = errors.New("cannot delete the last active admin")
	ErrAdminSelfDeactivate       = errors.New("admin cannot deactivate own account")
	ErrCannotDeactivateLastAdmin = errors.New("cannot deactivate the last active admin")
	ErrCannotRemoveLastAdmin     = errors.New("cannot remove the last active admin")
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrMissingAuthHeader         = errors.New("missing authorization header")
	ErrInvalidAuthHeader         = errors.New("invalid authorization header")
	ErrInvalidToken              = errors.New("invalid access token")
	ErrTokenRevoked              = errors.New("token revoked")
	ErrInvalidTokenVer           = errors.New("invalid token version")
	ErrSessionNotFound           = errors.New("session not found")
	ErrTempPasswordExpired       = errors.New("temporary password expired")
	ErrChangePasswordNotAllowed  = errors.New("change password not allowed")
	ErrRoleNotFound              = errors.New("role not found")
	ErrRoleAlreadyAssigned       = errors.New("role already assigned")
)
