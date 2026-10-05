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

	handlers := setupHandlers(database, cfg)

	srv := server.NewServer(cfg, log, handlers)
	return srv.Start()
}

func setupHandlers(db *gorm.Database, cfg *config.Config) *router.Handlers {
	// Repository
	userRepository := repository.NewUserRepository(db.DB)

	// Services
	jwtService := security.NewJWTService(cfg)
	hasherService := security.NewPasswordHasherService(cfg.HasherCost)

	// Use cases
	userUseCase := usecase.NewUserUseCase(userRepository, hasherService)
	authUseCase := usecase.NewAuthUseCase(userRepository, hasherService, jwtService)

	// Handlers
	userHandler := handler.NewUserHandler(userUseCase, jwtService)
	authHandler := handler.NewAuthHandler(authUseCase)

	return &router.Handlers{
		User: userHandler,
		Auth: authHandler,
	}
}
