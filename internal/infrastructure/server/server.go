package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
)

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
