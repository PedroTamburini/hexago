package dto

type ChangePasswordInput struct {
	UserID uint64
	// TokenPurpose comes from the authenticated token and selects the flow:
	// change_password requires a live temporary password, while access covers a
	// regular password change.
	TokenPurpose    string
	CurrentPassword string
	NewPassword     string
}

type ResetPasswordInput struct {
	TargetID uint64
}

type ResetPasswordOutput struct {
	// TemporaryPassword is returned as plaintext so an administrator can hand it
	// to the user; only its hash is persisted.
	TemporaryPassword string
}
