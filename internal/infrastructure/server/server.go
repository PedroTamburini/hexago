package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/gin-gonic/gin"
)

// NewEngine builds the bare gin engine: framework mode and trusted proxy
// handling. It deliberately installs no routes or middleware, so the HTTP
// adapter (not the infrastructure layer) owns request handling concerns.
//
// TrustedProxies is passed straight through to gin: an empty list means "trust
// no proxy", so c.ClientIP() falls back to the socket address and
// X-Forwarded-For is ignored. That is the safe default when the API is exposed
// directly; set TRUSTED_PROXIES only when running behind a known reverse proxy.
func NewEngine(cfg *config.Config) (*gin.Engine, error) {
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()

	if err := engine.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("failed to configure trusted proxies: %w", err)
	}

	return engine, nil
}

type Server struct {
	http   *http.Server
	config *config.Config
	logger *logger.Logger
}

// New wraps the assembled HTTP handler in a server. It only owns the HTTP
// lifecycle (timeouts, graceful shutdown) and stays unaware of routing,
// authentication or authorization concerns.
//
// In direct TLS mode the certificate pair is loaded here so an unreadable or
// mismatched file fails the boot before the process starts serving.
func New(cfg *config.Config, logger *logger.Logger, handler http.Handler) (*Server, error) {
	tlsConfig, err := newTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Server{
		http: &http.Server{
			Addr:         ":" + cfg.ServerPort,
			Handler:      handler,
			ReadTimeout:  cfg.ServerReadTimeOut,
			WriteTimeout: cfg.ServerWriteTimeOut,
			IdleTimeout:  cfg.ServerIdleTimeOut,
			TLSConfig:    tlsConfig,
		},
		config: cfg,
		logger: logger,
	}, nil
}

// newTLSConfig loads the certificate only when this server terminates TLS.
// In proxy mode the listener stays plaintext and the proxy owns the certificate.
func newTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.TLSMode != config.TLSModeDirect {
		return nil, nil
	}

	certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS certificate: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func (s *Server) Start() error {
	server := s.http

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(quit)

	errCh := make(chan error, 1)

	go func() {
		s.logger.Info("starting server", "addr", s.config.ServerPort, "tls_mode", s.config.TLSMode)

		var serveErr error
		if s.config.TLSMode == config.TLSModeDirect {
			// The certificate was already loaded into TLSConfig, so the empty
			// file names tell ServeTLS to use it.
			serveErr = server.ListenAndServeTLS("", "")
		} else {
			serveErr = server.ListenAndServe()
		}

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.logger.Error("server failed", "error", serveErr)
			errCh <- serveErr
		}
	}()

	select {
	case err := <-errCh:
		shutdownErr := s.shutdown()
		if shutdownErr != nil {
			s.logger.Error("shutdown after server failure", "error", shutdownErr)
		}
		return err

	case sig := <-quit:
		s.logger.Info("shutdown signal received", "signal", sig.String())
		return s.shutdown()
	}
}

// shutdown drains in flight requests within the configured timeout. On timeout
// it forces the listener closed and returns the error so the caller can decide
// the exit code, instead of panicking and skipping the remaining cleanup.
func (s *Server) shutdown() error {
	s.logger.Info("shutting down server...")

	ctxTimeout, cancel := context.WithTimeout(context.Background(), s.config.ServerShutdownTimeout)
	defer cancel()

	if err := s.http.Shutdown(ctxTimeout); err != nil {
		s.logger.Error("graceful shutdown failed, forcing close", "error", err)

		if closeErr := s.http.Close(); closeErr != nil {
			s.logger.Error("forced close failed", "error", closeErr)
		}

		return err
	}

	s.logger.Info("server exited gracefully")
	return nil
}
