package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const allowedOrigin = "https://app.example.com"

func newCORSEngine(cfg CORSConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(CORS(cfg))

	engine.GET("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})
	engine.OPTIONS("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "options")
	})

	return engine
}

func performCORSRequest(engine *gin.Engine, method, origin string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/test", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)

	return recorder
}

func TestCORSAllowedOrigin(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
		AllowedMethods: []string{http.MethodGet},
	})

	response := performCORSRequest(engine, http.MethodGet, allowedOrigin, nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
	}
	if got := response.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Fatalf("Vary = %q, want it to contain Origin", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want it omitted", got)
	}
}

func TestCORSDisallowedOrigin(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
	})

	response := performCORSRequest(engine, http.MethodGet, "https://evil.example.com", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want it omitted", got)
	}
}

func TestCORSWildcard(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{"*"},
	})

	response := performCORSRequest(engine, http.MethodGet, allowedOrigin, nil)

	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
	}
}

func TestCORSWildcardWithCredentialsReflectsOrigin(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})

	response := performCORSRequest(engine, http.MethodGet, allowedOrigin, nil)

	if got := response.Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want the request origin", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
	}
	if got := response.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Fatalf("Vary = %q, want it to contain Origin", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		MaxAge:         12 * time.Hour,
	})

	response := performCORSRequest(engine, http.MethodOptions, allowedOrigin, map[string]string{
		"Access-Control-Request-Method":  http.MethodPatch,
		"Access-Control-Request-Headers": "Authorization",
	})

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
	}
	if got := response.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodPatch) {
		t.Fatalf("Access-Control-Allow-Methods = %q, want it to contain PATCH", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("Access-Control-Allow-Headers = %q, want it to contain Authorization", got)
	}
	if got := response.Header().Get("Access-Control-Max-Age"); got != "43200" {
		t.Fatalf("Access-Control-Max-Age = %q, want 43200", got)
	}

	vary := response.Header().Get("Vary")
	for _, field := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !strings.Contains(vary, field) {
			t.Fatalf("Vary = %q, want it to contain %q", vary, field)
		}
	}
}

func TestCORSPreflightDisallowedOrigin(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
		AllowedMethods: []string{http.MethodPatch},
	})

	response := performCORSRequest(engine, http.MethodOptions, "https://evil.example.com", map[string]string{
		"Access-Control-Request-Method": http.MethodPatch,
	})

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want it omitted", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Methods"); got != "" {
		t.Fatalf("Access-Control-Allow-Methods = %q, want it omitted", got)
	}
}

func TestCORSOrdinaryOptionsReachesHandler(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
	})

	// An OPTIONS request without Access-Control-Request-Method is not a
	// preflight and must not be short-circuited by the middleware.
	response := performCORSRequest(engine, http.MethodOptions, allowedOrigin, nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Body.String(); got != "options" {
		t.Fatalf("body = %q, want %q", got, "options")
	}
}

func TestCORSWithoutOrigin(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
	})

	response := performCORSRequest(engine, http.MethodGet, "", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want it omitted", got)
	}
	if got := response.Header().Get("Vary"); got != "" {
		t.Fatalf("Vary = %q, want it omitted", got)
	}
}

func TestCORSExposedHeaders(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
		ExposedHeaders: []string{"X-Request-ID"},
	})

	response := performCORSRequest(engine, http.MethodGet, allowedOrigin, nil)

	if got := response.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-ID" {
		t.Fatalf("Access-Control-Expose-Headers = %q, want %q", got, "X-Request-ID")
	}
}

func TestCORSPreflightWithoutOrigin(t *testing.T) {
	engine := newCORSEngine(CORSConfig{
		AllowedOrigins: []string{allowedOrigin},
		AllowedMethods: []string{http.MethodGet},
	})

	response := performCORSRequest(engine, http.MethodOptions, "", map[string]string{
		"Access-Control-Request-Method": http.MethodGet,
	})

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want it omitted", got)
	}
}
