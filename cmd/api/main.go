package main

import (
	"fmt"
	"os"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/controller"
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
	config, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	logger := logger.NewLogger(config)

	database, err := gorm.NewPostgresConnection(config, logger)
	if err != nil {
		logger.Error("failed to connect to database", "error", err.Error())
		os.Exit(1)
	}

	if config.DBAutoMigration {
		if err := gorm.RunAutoMigrations(database); err != nil {
			logger.Error("failed to run migrations", "error", err.Error())
			os.Exit(1)
		}
	}

	handlers := setupHandlers(database, config)

	server := server.NewServer(config, logger, handlers)
	if err := server.Start(); err != nil {
		logger.Error("server failed to start", "error", err.Error())
		os.Exit(1)
	}
}

func setupHandlers(db *gorm.Database, cfg *config.Config) *router.Handlers {
	// Repository
	userRepository := repository.NewUserRepository(db.DB)

	// Services
	jwtService := security.NewJWTService(cfg)
	hasherService := security.NewPasswordHasherService(cfg.HasherCost)

	// Use cases
	userUseCase := usecase.NewUserUseCase(userRepository, hasherService)
	authUseCase := usecase.NewAuthUseCase(userUseCase, hasherService, jwtService)

	// Controllers
	userController := controller.NewUserController(userUseCase)
	authController := controller.NewAuthController(authUseCase)

	// Handlers
	userHandler := handler.NewUserHandler(userController, jwtService)
	authHandler := handler.NewAuthHandler(authController)

	handlers := &router.Handlers{
		User: userHandler,
		Auth: authHandler,
	}

	return handlers
}
