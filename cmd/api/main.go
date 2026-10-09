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
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/repository"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/PedroTamburini/hexago/internal/infrastructure/router"
	"github.com/PedroTamburini/hexago/internal/infrastructure/seed"
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

	if cfg.SeedEnabled {
		if err := seed.RunSeed(database, cfg); err != nil {
			return err
		}
	}

	rt := router.New(log, cfg, wire(cfg, database))
	rt.RegisterRoutes()

	return server.New(cfg, log, rt.Engine()).Start()
}

// wire is the composition root: it builds the adapters, use cases, authorization
// checker and handlers in one place, so nothing has to be assembled piecemeal in
// run(). It returns exactly what the router needs.
func wire(cfg *config.Config, db *gorm.Database) router.Dependencies {
	// Repositories (secondary adapters)
	userRepository := repository.NewUserRepository(db.DB)
	authenticationRepository := repository.NewAuthenticationRepository(db.DB)
	permissionChecker := repository.NewAuthorizationRepository(db.DB)

	// Supporting adapters
	hasher := security.NewPasswordHasher(cfg.HasherCost)
	tokens := security.NewJWTService(cfg)

	// Use cases
	userUseCase := usecase.NewUserUseCase(userRepository, hasher)
	authenticationUseCase := usecase.NewAuthenticationUseCase(authenticationRepository, hasher, tokens)

	// Primary adapters (handlers)
	handlers := &router.Handlers{
		User: handler.NewUserHandler(userUseCase),
		Auth: handler.NewAuthHandler(authenticationUseCase),
	}

	return router.Dependencies{
		Tokens:     tokens,
		Permission: permissionChecker,
		Handlers:   handlers,
	}
}
