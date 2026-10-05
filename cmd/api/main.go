// Package main bootstraps the hexago API.
//
//	@title						hexago API
//	@version					1.0
//	@description				REST API built with hexagonal architecture.
//	@description				Obtain a token via /auth and send it as a Bearer token.
//	@BasePath					/api/v1
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Type "Bearer" followed by a space and the access token.
package main

import (
	"fmt"
	"os"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/security"
	"github.com/PedroTamburini/hexago/internal/application/usecase"
	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/repository"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/PedroTamburini/hexago/internal/infrastructure/router"
	"github.com/PedroTamburini/hexago/internal/infrastructure/server"
)

func main() {
	// os.Exit is kept out of run() so deferred cleanup (database close) always
	// executes, no matter which path the process takes.
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	log := logger.NewLogger(cfg)

	database, err := gorm.NewPostgresConnection(cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Error("failed to close database", "error", err)
		}
	}()

	if cfg.DBAutoMigration {
		if err := gorm.RunAutoMigrations(database); err != nil {
			return err
		}
	}

	tokens := security.NewJWTService(cfg)

	handlers := setupHandlers(database, cfg, tokens)

	srv := server.NewServer(cfg, log, handlers, tokens)
	return srv.Start()
}

func setupHandlers(db *gorm.Database, cfg *config.Config, tokens port.TokenService) *router.Handlers {
	// Repository
	userRepository := repository.NewUserRepository(db.DB)

	// Adapters
	hasher := security.NewPasswordHasher(cfg.HasherCost)

	// Use cases
	userUseCase := usecase.NewUserUseCase(userRepository, hasher)
	authUseCase := usecase.NewAuthUseCase(userRepository, hasher, tokens)

	// Handlers
	userHandler := handler.NewUserHandler(userUseCase)
	authHandler := handler.NewAuthHandler(authUseCase)

	return &router.Handlers{
		User: userHandler,
		Auth: authHandler,
	}
}
