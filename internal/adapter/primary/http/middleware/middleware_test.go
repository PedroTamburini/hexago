package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeadersSetsHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.GET("/x", SecurityHeaders(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestRequestIDPreservesProvidedValue(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const provided = "request-123"

	engine := gin.New()
	engine.GET("/x", RequestID(), func(c *gin.Context) {
		if got := getRequestID(c); got != provided {
			t.Errorf("getRequestID = %q, want %q", got, provided)
		}
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Request-ID", provided)
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != provided {
		t.Fatalf("X-Request-ID = %q, want %q", got, provided)
	}
}

func TestRequestIDGeneratesMissingValue(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var stored string

	engine := gin.New()
	engine.GET("/x", RequestID(), func(c *gin.Context) {
		stored = getRequestID(c)
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	header := rec.Header().Get("X-Request-ID")
	if header == "" {
		t.Fatal("expected an X-Request-ID header to be generated")
	}

	if stored != header {
		t.Fatalf("context request id = %q, header = %q", stored, header)
	}
}

func TestRecoveryConvertsPanicToInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	engine := gin.New()
	engine.Use(Recovery(logger))
	engine.GET("/x", func(*gin.Context) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if body["error"] != "internal server error" {
		t.Fatalf("body = %v, want a generic error", body)
	}

	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatal("the panic value leaked into the response")
	}

	if !strings.Contains(logs.String(), "panic recovered") {
		t.Fatalf("expected the panic to be logged, got %q", logs.String())
	}
}

func TestLoggerRecordsRequestData(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	engine := gin.New()
	engine.Use(RequestID())
	engine.Use(Logger(logger))
	engine.GET("/x", func(c *gin.Context) {
		_ = c.Error(errTestRequest)
		c.Status(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/x?foo=bar", nil)
	req.Header.Set("X-Request-ID", "request-42")
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	output := logs.String()
	for _, expected := range []string{
		"request completed",
		"request_id",
		"request-42",
		"GET",
		"/x",
		"foo=bar",
		"418",
		"request error",
		errTestRequest.Error(),
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("log output does not contain %q: %s", expected, output)
		}
	}
}

var errTestRequest = &testError{"handler failed"}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
