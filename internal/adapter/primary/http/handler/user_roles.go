package handler

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	"github.com/gin-gonic/gin"
)

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
