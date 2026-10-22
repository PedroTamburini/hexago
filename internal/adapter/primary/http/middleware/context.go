package middleware

import "github.com/gin-gonic/gin"

// contextKey is an unexported type used for keys stored in the gin context.
// Using a dedicated type instead of a bare string makes collisions impossible
// and lets the setter/getter pairs be the single source of truth, which prevents
// the "userID" vs "user_id" mismatch that silently broke authorization.
type contextKey string

const (
	userIDKey    contextKey = "user_id"
	tokenJTIKey  contextKey = "token_jti"
	requestIDKey contextKey = "request_id"
)

func setUserID(c *gin.Context, userID uint64) {
	c.Set(string(userIDKey), userID)
}

// GetUserID returns the ID of the user placed in the context by
// JWTAuthMiddleware. Handlers use it to know who is performing a request, for
// instance when the rules of an operation depend on the actor (deleting
// oneself, deleting the last admin, ...).
func GetUserID(c *gin.Context) (uint64, bool) {
	value, exists := c.Get(string(userIDKey))
	if !exists {
		return 0, false
	}

	userID, ok := value.(uint64)
	return userID, ok
}

func setTokenJTI(c *gin.Context, jti string) {
	c.Set(string(tokenJTIKey), jti)
}

// GetTokenJTI returns the jti of the token that authenticated the request. It
// lets handlers distinguish the current session from the others when listing
// them.
func GetTokenJTI(c *gin.Context) (string, bool) {
	value, exists := c.Get(string(tokenJTIKey))
	if !exists {
		return "", false
	}

	jti, ok := value.(string)
	return jti, ok
}

func setRequestID(c *gin.Context, requestID string) {
	c.Set(string(requestIDKey), requestID)
}

func getRequestID(c *gin.Context) string {
	value, exists := c.Get(string(requestIDKey))
	if !exists {
		return ""
	}

	requestID, ok := value.(string)
	if !ok {
		return ""
	}

	return requestID
}
