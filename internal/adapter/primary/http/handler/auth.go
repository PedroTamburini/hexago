package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	usecase portin.AuthenticationUseCase
}

func NewAuthHandler(usecase portin.AuthenticationUseCase) *AuthHandler {
	return &AuthHandler{usecase: usecase}
}

// Authenticate godoc
// @Summary      Authenticate
// @Description  Authenticates a user and returns an access token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      request.AuthenticateBodyRequest  true  "User credentials"
// @Success      200  {object}  response.AuthenticateResponse
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /auth [post]
func (h *AuthHandler) Authenticate(ctx *gin.Context) {
	var body request.AuthenticateBodyRequest

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid request body",
		})
		return
	}

	input := dto.AuthenticateInput{
		Username:  body.Username,
		Password:  body.Password,
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
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

// Logout godoc
// @Summary      Logout
// @Description  Revokes the access token used in the request. The token is added to the denylist until it would have expired and its session is removed.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      204
// @Failure      401  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /auth/logout [post]
func (h *AuthHandler) Logout(ctx *gin.Context) {
	token, ok := bearerToken(ctx.GetHeader("Authorization"))
	if !ok {
		ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Error: "invalid authorization header",
		})
		return
	}

	if err := h.usecase.Logout(ctx.Request.Context(), token); err != nil {
		if errors.Is(err, domainerr.ErrInvalidToken) {
			ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
				Error: "invalid or expired token",
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

// bearerToken extracts the credentials from an "Authorization: Bearer <token>"
// header.
func bearerToken(header string) (string, bool) {
	parts := strings.Split(header, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}
