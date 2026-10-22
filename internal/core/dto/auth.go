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
