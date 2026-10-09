package request

type AuthenticateBodyRequest struct {
	Username string `json:"username" binding:"required,max=60"`
	Password string `json:"password" binding:"required,max=64"`
}
