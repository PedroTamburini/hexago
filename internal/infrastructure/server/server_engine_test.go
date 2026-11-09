package server

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/gin-gonic/gin"
)

func testLogger() *logger.Logger {
	return &logger.Logger{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestNewEngineConfiguresTrustedProxies(t *testing.T) {
	cfg := &config.Config{TrustedProxies: []string{"10.0.0.0/8"}}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if engine == nil {
		t.Fatal("NewEngine returned a nil engine")
	}

	if err := engine.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		t.Fatalf("trusted proxies were not accepted: %v", err)
	}
}

func TestNewEngineRejectsInvalidTrustedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine, err := NewEngine(&config.Config{TrustedProxies: []string{"not-an-ip"}})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want an invalid proxy error")
	}

	if engine != nil {
		t.Fatal("NewEngine() returned an engine alongside an error")
	}
}

func TestNewSetsServerTimeoutsAndAddress(t *testing.T) {
	cfg := &config.Config{
		ServerPort:         "9090",
		ServerReadTimeOut:  2 * time.Second,
		ServerWriteTimeOut: 3 * time.Second,
		ServerIdleTimeOut:  4 * time.Second,
		TLSMode:            config.TLSModeOff,
	}

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	srv, err := New(cfg, testLogger(), handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if srv.http.Addr != ":9090" {
		t.Fatalf("Addr = %q, want :9090", srv.http.Addr)
	}

	if srv.http.ReadTimeout != cfg.ServerReadTimeOut ||
		srv.http.WriteTimeout != cfg.ServerWriteTimeOut ||
		srv.http.IdleTimeout != cfg.ServerIdleTimeOut {
		t.Fatalf("unexpected timeouts: %+v", srv.http)
	}

	if srv.http.TLSConfig != nil {
		t.Fatal("expected no TLS config when TLS_MODE=off")
	}
}

func TestNewFailsOnUnreadableCertificate(t *testing.T) {
	cfg := &config.Config{
		TLSMode:     config.TLSModeDirect,
		TLSCertFile: "/does/not/exist/fullchain.pem",
		TLSKeyFile:  "/does/not/exist/privkey.pem",
	}

	srv, err := New(cfg, testLogger(), http.NewServeMux())
	if err == nil {
		t.Fatal("New() error = nil, want a certificate loading error")
	}

	if srv != nil {
		t.Fatal("New() returned a server alongside an error")
	}
}
