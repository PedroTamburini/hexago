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
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/ratelimit"
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/security"
	"github.com/PedroTamburini/hexago/internal/core/usecase"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/repository"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/PedroTamburini/hexago/internal/infrastructure/redis"
	"github.com/PedroTamburini/hexago/internal/infrastructure/router"
	"github.com/PedroTamburini/hexago/internal/infrastructure/seed"
	"github.com/PedroTamburini/hexago/internal/infrastructure/server"
	goredis "github.com/redis/go-redis/v9"
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

	redisClient, err := newRedisClient(cfg, log)
	if err != nil {
		return err
	}
	if redisClient != nil {
		defer func() {
			if err := redisClient.Close(); err != nil {
				log.Error("failed to close redis", "error", err)
			}
		}()
	}

	rt := router.New(log, cfg, wire(cfg, database, redisClient))
	rt.RegisterRoutes()

	return server.New(cfg, log, rt.Engine()).Start()
}

// newRedisClient connects to Redis only when rate limiting is enabled. Returning
// a nil client is a valid, intentional state: the router then omits the rate
// limit middleware altogether.
func newRedisClient(cfg *config.Config, log *logger.Logger) (*goredis.Client, error) {
	if !cfg.RateLimitEnabled {
		return nil, nil
	}

	return redis.NewClient(cfg, log)
}

// wire is the composition root: it builds the adapters, use cases, authorization
// checker and handlers in one place, so nothing has to be assembled piecemeal in
// run(). It returns exactly what the router needs.
func wire(cfg *config.Config, db *gorm.Database, redisClient *goredis.Client) router.Dependencies {
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
		RateLimit:  newRateLimiters(cfg, redisClient),
	}
}

// newRateLimiters builds the two token buckets used by the API: a strict one for
// the unauthenticated login route and a more generous one for authenticated
// users. When rate limiting is disabled the returned limiters are nil, which the
// middleware reads as "pass-through".
func newRateLimiters(cfg *config.Config, redisClient *goredis.Client) router.RateLimiters {
	limiters := router.RateLimiters{}
	if redisClient == nil {
		return limiters
	}

	limiters.Auth = ratelimit.NewTokenBucket(redisClient, "ratelimit:auth", cfg.RateLimitAuthCapacity, cfg.RateLimitAuthRefill)
	limiters.User = ratelimit.NewTokenBucket(redisClient, "ratelimit:user", cfg.RateLimitUserCapacity, cfg.RateLimitUserRefill)

	return limiters
}
