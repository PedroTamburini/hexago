package middleware

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

// RequirePermission guards a route with the permission checker. It must run
// after JWTAuthMiddleware, which is responsible for putting the authenticated
// user ID in the context.
func RequirePermission(checker portout.PermissionChecker, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := GetUserID(c)
		if !ok {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "unauthorized")
			return
		}

		allowed, err := checker.HasPermission(c.Request.Context(), userID, permission)
		if err != nil {
			// A user that no longer exists or was deactivated must be treated as
			// unauthenticated, so a token issued before the change stops working
			// immediately instead of until it expires.
			if errors.Is(err, domainerr.ErrUserNotFound) || errors.Is(err, domainerr.ErrUserInactive) {
				abortWithError(c, http.StatusUnauthorized, err, "unauthorized")
				return
			}

			// Any other failure is infrastructure, and must not be masked as
			// "forbidden".
			_ = c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, response.ErrorResponse{Error: "internal server error"})
			return
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, response.ErrorResponse{Error: "forbidden"})
			return
		}

		c.Next()
	}
}
