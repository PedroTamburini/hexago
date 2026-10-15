package middleware

import (
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	"github.com/gin-gonic/gin"
)

// BodyLimit caps the size of a request body.
//
// It first rejects requests that advertise a Content-Length above max with 413,
// so oversized uploads are refused before any body is read. As a backstop for
// chunked requests (which omit Content-Length), it wraps the body in
// http.MaxBytesReader, so a stream that grows past the limit fails instead of
// being buffered without bound.
func BodyLimit(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > max {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, response.ErrorResponse{
				Error: "request body too large",
			})
			return
		}

		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		}

		c.Next()
	}
}
