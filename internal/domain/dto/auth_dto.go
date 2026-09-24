package dto

type AuthenticateInput struct {
	Username string
	Password string
}

type AuthenticateOutput struct {
	Token    string
	ExpireIn int64
}
