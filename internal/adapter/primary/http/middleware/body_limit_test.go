package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBodyLimitRejectsOversizedContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const max = int64(16)

	engine := gin.New()
	engine.POST("/x", BodyLimit(max), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Declares a body larger than the limit; the middleware must reject it
	// without reading the body.
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", 64)))
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimitAllowsSmallBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const max = int64(1024)

	var received []byte

	engine := gin.New()
	engine.POST("/x", BodyLimit(max), func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		received = body
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("hello"))
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if string(received) != "hello" {
		t.Fatalf("handler received %q, want %q", received, "hello")
	}
}

func TestBodyLimitStopsChunkedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const max = int64(16)

	engine := gin.New()
	engine.POST("/x", BodyLimit(max), func(c *gin.Context) {
		// A chunked request has no Content-Length, so the middleware can only
		// enforce the limit while the body is being read.
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", 64)))
	req.ContentLength = -1
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}
