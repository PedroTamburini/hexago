package middleware

import (
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/gin-gonic/gin"
)

// RequirePermission guards a route with the permission checker. It must run
// after JWTAuthMiddleware, which is responsible for putting the authenticated
// user ID in the context.
func RequirePermission(checker port.PermissionChecker, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response.ErrorResponse{Error: "unauthorized"})
			return
		}

		allowed, err := checker.HasPermission(c.Request.Context(), userID, permission)
		if err != nil {
			// An infrastructure failure must not be masked as "forbidden".
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
