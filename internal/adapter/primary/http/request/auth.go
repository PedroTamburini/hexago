package request

type AuthenticateBodyRequest struct {
	Username string `json:"username" binding:"required,max=60"`
	Password string `json:"password" binding:"required,max=72"`
}

type ChangePasswordBodyRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=72"`
}
