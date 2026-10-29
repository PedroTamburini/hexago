package dto

type AuthenticateInput struct {
	Username string
	Password string
	// IP and UserAgent are captured from the request to enrich the session
	// record shown in the administrative panel. They are optional.
	IP        string
	UserAgent string
}

type AuthenticateOutput struct {
	Token    string
	ExpireIn int64
}

type ChangePasswordInput struct {
	UserID uint64
	// TokenPurpose comes from the authenticated token and selects the flow:
	// change_password requires a live temporary password, while access covers a
	// regular password change.
	TokenPurpose    string
	CurrentPassword string
	NewPassword     string
}
