package middleware

import "github.com/gin-gonic/gin"

// contextKey is an unexported type used for keys stored in the gin context.
// Using a dedicated type instead of a bare string makes collisions impossible
// and lets setUserID/getUserID be the single source of truth, which prevents the
// "userID" vs "user_id" mismatch that silently broke authorization.
type contextKey string

const userIDKey contextKey = "user_id"

func setUserID(c *gin.Context, userID uint64) {
	c.Set(string(userIDKey), userID)
}

func getUserID(c *gin.Context) (uint64, bool) {
	value, exists := c.Get(string(userIDKey))
	if !exists {
		return 0, false
	}

	userID, ok := value.(uint64)
	return userID, ok
}
