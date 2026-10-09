package request

type CreateUserBodyRequest struct {
	Name     string `json:"name" binding:"required,max=100"`
	Username string `json:"username" binding:"required,max=60"`
	Email    string `json:"email" binding:"required,max=254"`
	Password string `json:"password" binding:"required,min=8,max=64"`
}

type FindUserByIDUriRequest struct {
	ID uint64 `uri:"id" binding:"required"`
}

type FindAllUsersQuery struct {
	Limit  int `form:"limit" binding:"omitempty,min=1,max=100"`
	Offset int `form:"offset" binding:"omitempty,min=0"`
}

type UpdateUserUriRequest struct {
	ID uint64 `uri:"id" binding:"required"`
}

type UpdateUserBodyRequest struct {
	Name     string `json:"name" binding:"required,max=100"`
	Username string `json:"username" binding:"required,max=60"`
	Email    string `json:"email" binding:"required,max=254"`
}

type DeleteUserUriRequest struct {
	ID uint64 `uri:"id" binding:"required"`
}
