package handler

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	usecase portin.UserUseCase
}

func NewUserHandler(usecase portin.UserUseCase) *UserHandler {
	return &UserHandler{usecase: usecase}
}

// Create godoc
// @Summary      Create user
// @Description  Creates a new user.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      request.CreateUserBodyRequest  true  "New user"
// @Success      201  {object}  response.CreateUserResponse
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      409  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /users [post]
func (h *UserHandler) Create(ctx *gin.Context) {
	var body request.CreateUserBodyRequest

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid request body",
		})
		return
	}

	input := dto.CreateUserInput{
		Name:     body.Name,
		Username: body.Username,
		Email:    body.Email,
		Password: body.Password,
	}

	output, err := h.usecase.Create(ctx.Request.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, domainerr.ErrInvalidName):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid name",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidUsername):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid username",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidEmail):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid email",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidPassword):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid password",
			})
			return

		case errors.Is(err, domainerr.ErrUserAlreadyExists):
			ctx.JSON(http.StatusConflict, response.ErrorResponse{
				Error: "user already exists",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	resp := response.CreateUserResponse{
		ID:       output.ID,
		Name:     output.Name,
		Username: output.Username,
		Email:    output.Email,
	}

	ctx.JSON(http.StatusCreated, resp)
}

// Get godoc
// @Summary      Get user
// @Description  Returns a user by ID.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      int  true  "User ID"
// @Success      200  {object}  response.UserResponse
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      404  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /users/{id} [get]
func (h *UserHandler) Get(ctx *gin.Context) {
	var uri request.FindUserByIDUriRequest

	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	input := dto.FindUserByIDInput{ID: uri.ID}

	output, err := h.usecase.FindByID(ctx.Request.Context(), input)
	if err != nil {
		if errors.Is(err, domainerr.ErrUserNotFound) {
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	resp := response.UserResponse{
		ID:        output.ID,
		Name:      output.Name,
		Username:  output.Username,
		Email:     output.Email,
		IsActive:  output.IsActive,
		CreatedAt: output.CreatedAt,
		UpdatedAt: output.UpdatedAt,
	}

	ctx.JSON(http.StatusOK, resp)
}

// List godoc
// @Summary      List users
// @Description  Returns a paginated list of users.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        limit   query     int  false  "Maximum number of records to return (default 20, max 100)"
// @Param        offset  query     int  false  "Number of records to skip"
// @Success      200     {object}  response.FindAllUsersResponse
// @Failure      400     {object}  response.ErrorResponse
// @Failure      401     {object}  response.ErrorResponse
// @Failure      500     {object}  response.ErrorResponse
// @Router       /users [get]
func (h *UserHandler) List(ctx *gin.Context) {
	var query request.FindAllUsersQuery
	if err := ctx.ShouldBindQuery(&query); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid query",
		})
		return
	}

	input := dto.FindAllUsersInput{
		Limit:  query.Limit,
		Offset: query.Offset,
	}

	output, err := h.usecase.FindAll(ctx.Request.Context(), input)
	if err != nil {
		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	users := make([]*response.UserResponse, len(output.Users))
	for i, user := range output.Users {
		users[i] = &response.UserResponse{
			ID:        user.ID,
			Name:      user.Name,
			Username:  user.Username,
			Email:     user.Email,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	resp := response.FindAllUsersResponse{
		Users: users,
	}

	ctx.JSON(http.StatusOK, resp)
}

// Update godoc
// @Summary      Update user
// @Description  Updates an existing user.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      int                          true  "User ID"
// @Param        body  body      request.UpdateUserBodyRequest  true  "Updated user"
// @Success      200   {object}  response.UpdateUserResponse
// @Failure      400   {object}  response.ErrorResponse
// @Failure      401   {object}  response.ErrorResponse
// @Failure      404   {object}  response.ErrorResponse
// @Failure      409   {object}  response.ErrorResponse
// @Failure      500   {object}  response.ErrorResponse
// @Router       /users/{id} [put]
func (h *UserHandler) Update(ctx *gin.Context) {
	var uri request.UpdateUserUriRequest
	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	var body request.UpdateUserBodyRequest
	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid request body",
		})
		return
	}

	input := dto.UpdateUserInput{
		ID:       uri.ID,
		Name:     body.Name,
		Username: body.Username,
		Email:    body.Email,
	}

	output, err := h.usecase.Update(ctx.Request.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, domainerr.ErrUserNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidName):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid name",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidUsername):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid username",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidEmail):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid email",
			})
			return

		case errors.Is(err, domainerr.ErrUserAlreadyExists):
			ctx.JSON(http.StatusConflict, response.ErrorResponse{
				Error: "user already exists",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	resp := response.UpdateUserResponse{
		ID:        output.ID,
		Name:      output.Name,
		Username:  output.Username,
		Email:     output.Email,
		UpdatedAt: output.UpdatedAt,
	}

	ctx.JSON(http.StatusOK, resp)
}

// Delete godoc
// @Summary      Delete user
// @Description  Deletes an existing user. An admin cannot delete their own account, and the last active admin cannot be deleted by anyone. The account is deactivated in the process.
// @Tags         users
// @Security     BearerAuth
// @Param        id   path      int  true  "User ID"
// @Success      204  "User deleted"
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      403  {object}  response.ErrorResponse
// @Failure      404  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /users/{id} [delete]
func (h *UserHandler) Delete(ctx *gin.Context) {
	var uri request.DeleteUserUriRequest

	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	// The rules below depend on who is performing the deletion, so the
	// authenticated user must be available. JWTAuthMiddleware always sets it,
	// and a missing value means the request was not properly authenticated.
	actorID, ok := middleware.GetUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Error: "unauthorized",
		})
		return
	}

	input := dto.DeleteUserInput{ID: uri.ID, ActorID: actorID}

	if err := h.usecase.Delete(ctx.Request.Context(), input); err != nil {
		switch {
		case errors.Is(err, domainerr.ErrUserNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return

		case errors.Is(err, domainerr.ErrAdminSelfDelete):
			ctx.JSON(http.StatusForbidden, response.ErrorResponse{
				Error: "admin cannot delete own account",
			})
			return

		case errors.Is(err, domainerr.ErrLastAdmin):
			ctx.JSON(http.StatusForbidden, response.ErrorResponse{
				Error: "cannot delete the last active admin",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// SetStatus godoc
// @Summary      Set user status
// @Description  Activates or deactivates a user. Requires users:status permission. Cannot deactivate self if admin or the last active admin. Deactivating revokes all sessions.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      int                        true  "User ID"
// @Param        body  body      request.SetUserStatusBodyRequest true "Status"
// @Success      200   {object}  response.SetUserStatusResponse
// @Failure      400   {object}  response.ErrorResponse
// @Failure      401   {object}  response.ErrorResponse
// @Failure      403   {object}  response.ErrorResponse
// @Failure      404   {object}  response.ErrorResponse
// @Failure      500   {object}  response.ErrorResponse
// @Router       /users/{id}/status [patch]
func (h *UserHandler) SetStatus(ctx *gin.Context) {
	var uri request.SetUserStatusUriRequest
	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	var body request.SetUserStatusBodyRequest
	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid request body",
		})
		return
	}

	actorID, ok := middleware.GetUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Error: "unauthorized",
		})
		return
	}

	input := dto.SetUserStatusInput{
		ID:       uri.ID,
		ActorID:  actorID,
		IsActive: *body.IsActive,
	}

	output, err := h.usecase.SetStatus(ctx.Request.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, domainerr.ErrUserNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return

		case errors.Is(err, domainerr.ErrAdminSelfDeactivate):
			ctx.JSON(http.StatusForbidden, response.ErrorResponse{
				Error: "admin cannot deactivate own account",
			})
			return

		case errors.Is(err, domainerr.ErrCannotDeactivateLastAdmin):
			ctx.JSON(http.StatusForbidden, response.ErrorResponse{
				Error: "cannot deactivate the last active admin",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	resp := response.SetUserStatusResponse{
		ID:       output.ID,
		IsActive: output.IsActive,
	}

	ctx.JSON(http.StatusOK, resp)
}

// ResetPassword godoc
// @Summary      Reset user password
// @Description  Administratively resets a user's password and returns a temporary password once. Revokes all sessions.
// @Tags         users
// @Security     BearerAuth
// @Param        id   path      int  true  "User ID"
// @Success      200  {object}  response.ResetPasswordResponse
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      403  {object}  response.ErrorResponse
// @Failure      404  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /users/{id}/password/reset [post]
func (h *UserHandler) ResetPassword(ctx *gin.Context) {
	var uri request.ResetPasswordUriRequest
	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	input := dto.ResetPasswordInput{TargetID: uri.ID}

	output, err := h.usecase.ResetPassword(ctx.Request.Context(), input)
	if err != nil {
		if errors.Is(err, domainerr.ErrUserNotFound) {
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	resp := response.ResetPasswordResponse{
		TemporaryPassword: output.TemporaryPassword,
	}

	ctx.JSON(http.StatusOK, resp)
}

// AssignRole godoc
// @Summary      Assign role to user
// @Description  Assigns a role to a user. Requires roles:manage permission.
// @Tags         users
// @Security     BearerAuth
// @Param        id       path      int  true  "User ID"
// @Param        role_id  path      int  true  "Role ID"
// @Success      204
// @Failure      400       {object}  response.ErrorResponse
// @Failure      401       {object}  response.ErrorResponse
// @Failure      403       {object}  response.ErrorResponse
// @Failure      404       {object}  response.ErrorResponse
// @Failure      409       {object}  response.ErrorResponse
// @Failure      500       {object}  response.ErrorResponse
// @Router       /users/{id}/roles/{role_id} [post]
func (h *UserHandler) AssignRole(ctx *gin.Context) {
	var uri request.AssignRoleUriRequest
	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	input := dto.AssignRoleInput{
		TargetID: uri.ID,
		RoleID:   uri.RoleID,
	}

	if err := h.usecase.AssignRole(ctx.Request.Context(), input); err != nil {
		switch {
		case errors.Is(err, domainerr.ErrUserNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return

		case errors.Is(err, domainerr.ErrRoleNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "role not found",
			})
			return

		case errors.Is(err, domainerr.ErrRoleAlreadyAssigned):
			ctx.JSON(http.StatusConflict, response.ErrorResponse{
				Error: "role already assigned",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// RemoveRole godoc
// @Summary      Remove role from user
// @Description  Removes a role from a user. Requires roles:manage permission. Preserves at least one active admin.
// @Tags         users
// @Security     BearerAuth
// @Param        id       path      int  true  "User ID"
// @Param        role_id  path      int  true  "Role ID"
// @Success      204
// @Failure      400       {object}  response.ErrorResponse
// @Failure      401       {object}  response.ErrorResponse
// @Failure      403       {object}  response.ErrorResponse
// @Failure      404       {object}  response.ErrorResponse
// @Failure      500       {object}  response.ErrorResponse
// @Router       /users/{id}/roles/{role_id} [delete]
func (h *UserHandler) RemoveRole(ctx *gin.Context) {
	var uri request.RemoveRoleUriRequest
	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	input := dto.RemoveRoleInput{
		TargetID: uri.ID,
		RoleID:   uri.RoleID,
	}

	if err := h.usecase.RemoveRole(ctx.Request.Context(), input); err != nil {
		switch {
		case errors.Is(err, domainerr.ErrUserNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "user not found",
			})
			return

		case errors.Is(err, domainerr.ErrRoleNotFound):
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "role not found",
			})
			return

		case errors.Is(err, domainerr.ErrCannotRemoveLastAdmin):
			ctx.JSON(http.StatusForbidden, response.ErrorResponse{
				Error: "forbidden",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}
