package response

type ResetPasswordResponse struct {
	TemporaryPassword string `json:"temporary_password"`
}
