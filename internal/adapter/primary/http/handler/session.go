package handler

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	"github.com/gin-gonic/gin"
)

type SessionHandler struct {
	usecase portin.SessionManagementUseCase
}

func NewSessionHandler(usecase portin.SessionManagementUseCase) *SessionHandler {
	return &SessionHandler{usecase: usecase}
}

// ListUserSessions godoc
// @Summary      List user sessions
// @Description  Lists the active sessions of a user. The session used in the request is flagged with is_current.
// @Tags         sessions
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      int  true  "User ID"
// @Success      200  {object}  response.FindUserSessionsResponse
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      403  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /admin/users/{id}/sessions [get]
func (h *SessionHandler) ListUserSessions(ctx *gin.Context) {
	var uri request.FindUserByIDUriRequest

	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	sessions, err := h.usecase.ListUserSessions(ctx.Request.Context(), uri.ID)
	if err != nil {
		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	currentJTI, _ := middleware.GetTokenJTI(ctx)

	resp := response.FindUserSessionsResponse{
		Sessions: make([]*response.SessionResponse, 0, len(sessions)),
	}
	for _, session := range sessions {
		resp.Sessions = append(resp.Sessions, &response.SessionResponse{
			JTI:       session.JTI,
			UserID:    session.UserID,
			IssuedAt:  session.IssuedAt,
			ExpiresAt: session.ExpiresAt,
			IP:        session.IP,
			UserAgent: session.UserAgent,
			IsCurrent: currentJTI != "" && session.JTI == currentJTI,
		})
	}

	ctx.JSON(http.StatusOK, resp)
}

// RevokeSession godoc
// @Summary      Revoke session
// @Description  Revokes one active session by its token ID. The token stops being accepted immediately.
// @Tags         sessions
// @Produce      json
// @Security     BearerAuth
// @Param        jti  path      string  true  "Token ID (jti)"
// @Success      204
// @Failure      401  {object}  response.ErrorResponse
// @Failure      403  {object}  response.ErrorResponse
// @Failure      404  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /admin/sessions/{jti} [delete]
func (h *SessionHandler) RevokeSession(ctx *gin.Context) {
	jti := ctx.Param("jti")
	if jti == "" {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	if err := h.usecase.RevokeSession(ctx.Request.Context(), jti); err != nil {
		if errors.Is(err, domainerr.ErrSessionNotFound) {
			ctx.JSON(http.StatusNotFound, response.ErrorResponse{
				Error: "session not found",
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

// RevokeAllUserSessions godoc
// @Summary      Revoke all user sessions
// @Description  Invalidates every token of a user by bumping the token version, and clears the session records.
// @Tags         sessions
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      int  true  "User ID"
// @Success      204
// @Failure      400  {object}  response.ErrorResponse
// @Failure      401  {object}  response.ErrorResponse
// @Failure      403  {object}  response.ErrorResponse
// @Failure      500  {object}  response.ErrorResponse
// @Router       /admin/users/{id}/sessions [delete]
func (h *SessionHandler) RevokeAllUserSessions(ctx *gin.Context) {
	var uri request.FindUserByIDUriRequest

	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse{
			Error: "invalid param",
		})
		return
	}

	if err := h.usecase.RevokeAllUserSessions(ctx.Request.Context(), uri.ID); err != nil {
		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, response.ErrorResponse{
			Error: "internal server error",
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}
