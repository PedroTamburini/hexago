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

type AuthHandler struct {
	usecase port.AuthUseCase
}

func NewAuthHandler(usecase port.AuthUseCase) *AuthHandler {
	return &AuthHandler{usecase: usecase}
}

func (h *AuthHandler) Register(router *gin.RouterGroup) {
	router.POST("", h.Authenticate)
}

func (h *AuthHandler) Authenticate(ctx *gin.Context) {
	var body request.AuthenticateBodyRequest

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid request body",
		})
		return
	}

	input := dto.AuthenticateInput{
		Username: body.Username,
		Password: body.Password,
	}

	output, err := h.usecase.Authenticate(ctx.Request.Context(), input)
	if err != nil {
		if errors.Is(err, domainerr.ErrInvalidCredentials) {
			ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
				Error: "invalid credentials",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	resp := response.AuthenticateResponse{
		Token:    output.Token,
		ExpireIn: output.ExpireIn,
	}

	ctx.JSON(http.StatusOK, resp)
}
