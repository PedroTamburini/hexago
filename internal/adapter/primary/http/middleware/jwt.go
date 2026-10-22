package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

// JWTAuthMiddleware authenticates a Bearer token in three steps: the token must
// be cryptographically valid, its jti must not be denied and its token version
// must match the one currently stored for the user. The last two checks are what
// make revocation immediate instead of waiting for the token to expire.
func JWTAuthMiddleware(
	parser portout.TokenParser,
	denylist portout.TokenDenylist,
	tokenVersions portout.TokenVersionManager,
) gin.HandlerFunc {
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

		claims, err := parser.ParseClaims(parts[1])
		if err != nil {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "invalid or expired token")
			return
		}

		userID, err := strconv.ParseUint(claims.Subject, 10, 64)
		if err != nil {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "invalid or expired token")
			return
		}

		revoked, err := denylist.IsRevoked(c.Request.Context(), claims.JTI)
		if err != nil {
			// The denylist is an infrastructure dependency and the check is a
			// security control: fail closed, but report the real cause instead
			// of pretending the credentials are wrong.
			_ = c.Error(err)
			abortWithError(c, http.StatusServiceUnavailable, err, "authentication temporarily unavailable")
			return
		}
		if revoked {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrTokenRevoked, "token revoked")
			return
		}

		currentVersion, err := tokenVersions.GetVersion(c.Request.Context(), userID)
		if err != nil {
			_ = c.Error(err)
			abortWithError(c, http.StatusServiceUnavailable, err, "authentication temporarily unavailable")
			return
		}
		if claims.TokenVer != currentVersion {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidTokenVer, "invalid or expired token")
			return
		}

		setUserID(c, userID)
		setTokenJTI(c, claims.JTI)
		c.Next()
	}
}

func abortWithError(c *gin.Context, status int, cause error, message string) {
	_ = c.Error(cause)
	c.Header("WWW-Authenticate", "Bearer")
	c.AbortWithStatusJSON(status, response.ErrorResponse{Error: message})
}
