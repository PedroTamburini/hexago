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

type PasswordHandler struct {
	usecase portin.PasswordUseCase
}

func NewPasswordHandler(usecase portin.PasswordUseCase) *PasswordHandler {
	return &PasswordHandler{usecase: usecase}
}

// ChangePassword godoc
// @Summary      Change password
// @Description  Changes the user's password. Accepts a normal access token or a token with purpose change_password (issued after login with a temporary password). After success all sessions are revoked.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      request.ChangePasswordBodyRequest  true  "Password change"
// @Success      204
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      403  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /auth/change-password [post]
func (h *PasswordHandler) ChangePassword(ctx *gin.Context) {
	var body request.ChangePasswordBodyRequest
	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid request body",
		})
		return
	}

	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
			Error: "unauthorized",
		})
		return
	}

	purpose, _ := middleware.GetTokenPurpose(ctx)

	input := dto.ChangePasswordInput{
		UserID:          userID,
		TokenPurpose:    purpose,
		CurrentPassword: body.CurrentPassword,
		NewPassword:     body.NewPassword,
	}

	if err := h.usecase.ChangePassword(ctx.Request.Context(), input); err != nil {
		switch {
		case errors.Is(err, domainerr.ErrInvalidPassword):
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
				Error: "invalid password",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidCredentials):
			ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
				Error: "invalid credentials",
			})
			return

		case errors.Is(err, domainerr.ErrTempPasswordExpired):
			ctx.JSON(http.StatusUnauthorized, response.ErrorResponse{
				Error: "temporary password expired",
			})
			return

		case errors.Is(err, domainerr.ErrChangePasswordNotAllowed):
			ctx.JSON(http.StatusForbidden, response.ErrorResponse{
				Error: "change password not allowed",
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
func (h *PasswordHandler) ResetPassword(ctx *gin.Context) {
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
