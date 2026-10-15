package server

import (
	"context"
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
func New(cfg *config.Config, logger *logger.Logger, handler http.Handler) *Server {
	return &Server{
		http: &http.Server{
			Addr:         ":" + cfg.ServerPort,
			Handler:      handler,
			ReadTimeout:  cfg.ServerReadTimeOut,
			WriteTimeout: cfg.ServerWriteTimeOut,
			IdleTimeout:  cfg.ServerIdleTimeOut,
		},
		config: cfg,
		logger: logger,
	}
}

func (s *Server) Start() error {
	server := s.http

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(quit)

	errCh := make(chan error, 1)

	go func() {
		s.logger.Info("starting server", "addr", s.config.ServerPort)

		if err := server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("server failed", "error", err)
			errCh <- err
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
