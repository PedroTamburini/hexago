package middleware

import (
	"net/http"
	"strings"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/gin-gonic/gin"
)

func JWTAuthMiddleware(tokenValidator port.TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrMissingAuthHeader, "missing authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidAuthHeader, "invalid authorization header")
			return
		}

		userID, err := tokenValidator.ValidateToken(parts[1])
		if err != nil {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "invalid or expired token")
			return
		}

		setUserID(c, userID)
		c.Next()
	}
}

func abortWithError(c *gin.Context, status int, cause error, message string) {
	_ = c.Error(cause)
	c.Header("WWW-Authenticate", "Bearer")
	c.AbortWithStatusJSON(status, response.ErrorResponse{Error: message})
}
