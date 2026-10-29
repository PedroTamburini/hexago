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
	return jwtAuth(parser, denylist, tokenVersions, false)
}

// JWTAuthMiddlewareAllowPasswordChange behaves like JWTAuthMiddleware but also
// accepts tokens whose purpose is change_password. It is used only by the
// change-password endpoint.
func JWTAuthMiddlewareAllowPasswordChange(
	parser portout.TokenParser,
	denylist portout.TokenDenylist,
	tokenVersions portout.TokenVersionManager,
) gin.HandlerFunc {
	return jwtAuth(parser, denylist, tokenVersions, true)
}

// jwtAuth builds the middleware shared by the standard and the password-change
// variants. allowPasswordChange only widens the accepted purposes; all other
// checks are identical, which keeps both entry points from drifting apart.
func jwtAuth(
	parser portout.TokenParser,
	denylist portout.TokenDenylist,
	tokenVersions portout.TokenVersionManager,
	allowPasswordChange bool,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, userID, ok := authenticate(c, parser, denylist, tokenVersions)
		if !ok {
			return
		}

		if !isPurposeAllowed(claims.Purpose, allowPasswordChange) {
			abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "invalid or expired token")
			return
		}

		setUserID(c, userID)
		setTokenJTI(c, claims.JTI)
		setTokenPurpose(c, claims.Purpose)
		c.Next()
	}
}

// authenticate performs the checks shared by every JWT protected route. It
// writes the error response and returns false when the request must be aborted.
func authenticate(
	c *gin.Context,
	parser portout.TokenParser,
	denylist portout.TokenDenylist,
	tokenVersions portout.TokenVersionManager,
) (*portout.TokenClaims, uint64, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		abortWithError(c, http.StatusUnauthorized, domainerr.ErrMissingAuthHeader, "missing authorization header")
		return nil, 0, false
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidAuthHeader, "invalid authorization header")
		return nil, 0, false
	}

	claims, err := parser.ParseClaims(parts[1])
	if err != nil {
		abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "invalid or expired token")
		return nil, 0, false
	}

	// Tokens issued before purposes were introduced have no purpose claim. They
	// are treated as access tokens so an upgrade does not invalidate sessions
	// that were still valid.
	if claims.Purpose == "" {
		claims.Purpose = portout.TokenPurposeAccess
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidToken, "invalid or expired token")
		return nil, 0, false
	}

	revoked, err := denylist.IsRevoked(c.Request.Context(), claims.JTI)
	if err != nil {
		// The denylist is an infrastructure dependency and the check is a
		// security control: fail closed, but report the real cause instead of
		// pretending the credentials are wrong.
		_ = c.Error(err)
		abortWithError(c, http.StatusServiceUnavailable, err, "authentication temporarily unavailable")
		return nil, 0, false
	}
	if revoked {
		abortWithError(c, http.StatusUnauthorized, domainerr.ErrTokenRevoked, "token revoked")
		return nil, 0, false
	}

	currentVersion, err := tokenVersions.GetVersion(c.Request.Context(), userID)
	if err != nil {
		_ = c.Error(err)
		abortWithError(c, http.StatusServiceUnavailable, err, "authentication temporarily unavailable")
		return nil, 0, false
	}
	if claims.TokenVer != currentVersion {
		abortWithError(c, http.StatusUnauthorized, domainerr.ErrInvalidTokenVer, "invalid or expired token")
		return nil, 0, false
	}

	return claims, userID, true
}

// isPurposeAllowed enforces the purpose gate: access tokens work everywhere,
// while change_password tokens are accepted only by routes that explicitly opt
// in.
func isPurposeAllowed(purpose string, allowPasswordChange bool) bool {
	if purpose == portout.TokenPurposeAccess {
		return true
	}

	return allowPasswordChange && purpose == portout.TokenPurposeChangePassword
}

func abortWithError(c *gin.Context, status int, cause error, message string) {
	_ = c.Error(cause)
	c.Header("WWW-Authenticate", "Bearer")
	c.AbortWithStatusJSON(status, response.ErrorResponse{Error: message})
}
