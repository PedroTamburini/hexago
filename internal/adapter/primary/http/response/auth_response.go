package response

type AuthenticateResponse struct {
	Token    string `json:"token"`
	ExpireIn int64  `json:"expire_in"`
}
