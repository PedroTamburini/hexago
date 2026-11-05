package request

type ChangePasswordBodyRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=72"`
}

type ResetPasswordUriRequest struct {
	ID uint64 `uri:"id" binding:"required"`
}
