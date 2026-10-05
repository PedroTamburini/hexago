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

// Register only declares the routes. Authentication is applied by the router,
// so this adapter stays free of infrastructure concerns.
func (h *UserHandler) Register(router *gin.RouterGroup) {
	router.POST("", h.Create)
	router.GET("/:id", h.Get)
	router.GET("", h.List)
	router.PUT("/:id", h.Update)
	router.DELETE("/:id", h.Delete)
}

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
