package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newHTTPSEngine(cfg TLSConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(RequireHTTPS(cfg))

	engine.GET("/health", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})
	engine.GET("/api/v1/users", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})
	engine.POST("/api/v1/users", func(ctx *gin.Context) {
		ctx.String(http.StatusCreated, "ok")
	})

	return engine
}

func performHTTPSRequest(engine *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)

	return recorder
}

func TestHTTPSRedirectsPlaintext(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: true})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users?page=1", nil)
	req.RemoteAddr = "203.0.113.10:4321"

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
	}
	if got, want := response.Header().Get("Location"), "https://api.example.com/api/v1/users?page=1"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if got, want := response.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Fatalf("Cache-Control = %q, want %q", got, want)
	}
}

func TestHTTPSRedirectPreservesMethod(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: true})

	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "203.0.113.10:4321"

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
	}
}

func TestHTTPSRedirectDropsDefaultPort(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: true})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com:80/api/v1/users", nil)
	req.RemoteAddr = "203.0.113.10:4321"

	response := performHTTPSRequest(engine, req)

	if got, want := response.Header().Get("Location"), "https://api.example.com/api/v1/users"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestHTTPSExemptsHealth(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: true})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/health", nil)
	req.RemoteAddr = "203.0.113.10:4321"

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestHTTPSSecureDirectRequest(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:   true,
		Direct:     true,
		HSTSMaxAge: time.Hour,
	})

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/api/v1/users", nil)
	req.TLS = &tls.ConnectionState{}

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got, want := response.Header().Get("Strict-Transport-Security"), "max-age=3600"; got != want {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestHTTPSTrustedProxyRequest(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:       true,
		TrustedProxies: []string{"10.0.0.0/8"},
		HSTSMaxAge:     time.Hour,
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-Proto", "https")

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got, want := response.Header().Get("Strict-Transport-Security"), "max-age=3600"; got != want {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestHTTPSTrustedProxyWithBareIP(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:       true,
		TrustedProxies: []string{"127.0.0.1"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Forwarded-Proto", "https")

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestHTTPSRejectsSpoofedForwardedProto(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:       true,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "203.0.113.5:5555"
	req.Header.Set("X-Forwarded-Proto", "https")

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
	}
}

func TestHTTPSUsesRightmostForwardedProto(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:       true,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	t.Run("client spoof is overridden by the proxy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
		req.RemoteAddr = "10.1.2.3:5555"
		req.Header.Set("X-Forwarded-Proto", "https, http")

		response := performHTTPSRequest(engine, req)

		if response.Code != http.StatusPermanentRedirect {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
		}
	})

	t.Run("proxy confirms https", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
		req.RemoteAddr = "10.1.2.3:5555"
		req.Header.Set("X-Forwarded-Proto", "http, https")

		response := performHTTPSRequest(engine, req)

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
		}
	})
}

func TestHTTPSDirectIgnoresForwardedProto(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:       true,
		Direct:         true,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-Proto", "https")

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
	}
}

func TestHTTPSIgnoresMalformedTrustedProxy(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:       true,
		TrustedProxies: []string{"not-an-ip"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "203.0.113.5:5555"
	req.Header.Set("X-Forwarded-Proto", "https")

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusPermanentRedirect)
	}
}

func TestHTTPSHSTSIncludeSubDomains(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{
		Required:              true,
		Direct:                true,
		HSTSMaxAge:            time.Hour,
		HSTSIncludeSubDomains: true,
	})

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/api/v1/users", nil)
	req.TLS = &tls.ConnectionState{}

	response := performHTTPSRequest(engine, req)

	if got, want := response.Header().Get("Strict-Transport-Security"), "max-age=3600; includeSubDomains"; got != want {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestHTTPSOmitsHSTSWhenDisabled(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: true, Direct: true})

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/api/v1/users", nil)
	req.TLS = &tls.ConnectionState{}

	response := performHTTPSRequest(engine, req)

	if got := response.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want empty", got)
	}
}

func TestHTTPSDisabledPassesPlaintext(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: false, HSTSMaxAge: time.Hour})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.RemoteAddr = "203.0.113.10:4321"

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want empty", got)
	}
}

func TestHTTPSRejectsMissingHost(t *testing.T) {
	engine := newHTTPSEngine(TLSConfig{Required: true})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/v1/users", nil)
	req.Host = ""
	req.RemoteAddr = "203.0.113.10:4321"

	response := performHTTPSRequest(engine, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}
