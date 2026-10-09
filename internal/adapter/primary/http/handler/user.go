package handler

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	"github.com/PedroTamburini/hexago/internal/domain/dto"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	usecase port.UserUseCase
}

func NewUserHandler(usecase port.UserUseCase) *UserHandler {
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
// @Success      200  {object}  response.FindUserByIDResponse
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

	resp := response.FindUserByIDResponse{
		ID:        output.ID,
		Name:      output.Name,
		Username:  output.Username,
		Email:     output.Email,
		IsAdmin:   output.IsAdmin,
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
			IsAdmin:   user.IsAdmin,
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
// @Description  Deletes an existing user.
// @Tags         users
// @Security     BearerAuth
// @Param        id   path      int  true  "User ID"
// @Success      204  "User deleted"
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
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

	input := dto.DeleteUserInput{ID: uri.ID}

	if err := h.usecase.Delete(ctx.Request.Context(), input); err != nil {
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

	ctx.Status(http.StatusNoContent)
}
