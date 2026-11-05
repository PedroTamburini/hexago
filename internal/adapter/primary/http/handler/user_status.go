package handler

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	"github.com/gin-gonic/gin"
)

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
