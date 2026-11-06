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
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/routes"
	gormdb "github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm"
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/database/gorm/repository"
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/ratelimit"
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/security"
	"github.com/PedroTamburini/hexago/internal/adapter/secondary/tokenstore"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/PedroTamburini/hexago/internal/core/usecase"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/PedroTamburini/hexago/internal/infrastructure/redis"
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

	// The database connection is left to the operator, but a TLS-protected API
	// talking to a database over plaintext is worth flagging at boot.
	if cfg.TLSEnabled() && !cfg.DatabaseUsesTLS() {
		log.Warn(
			"TLS is enabled for the API but the database connection may be plaintext",
			"tls_mode", cfg.TLSMode,
			"db_sslmode", cfg.DBSSLMode,
		)
	}

	db, err := database.NewPostgresConnection(cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("failed to close database", "error", err)
		}
	}()

	// Supporting adapters. They are built once and shared so the seed and the
	// use cases go through the same hashing and token implementations.
	hasher := security.NewPasswordHasher(cfg.HasherCost)
	tokens := security.NewJWTService(cfg.JWTSecret, cfg.JWTExpiration)

	if cfg.DBAutoMigration {
		if err := gormdb.RunAutoMigrations(db.DB); err != nil {
			return err
		}
	}

	if cfg.SeedEnabled {
		if err := gormdb.RunSeed(db.DB, gormdb.SeedOptions{
			AdminUsername: cfg.AdminUsername,
			AdminEmail:    cfg.AdminEmail,
			AdminPassword: cfg.AdminPassword,
		}, hasher); err != nil {
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

	engine, err := server.NewEngine(cfg)
	if err != nil {
		return err
	}

	// HSTS is a production-only policy: applying it to a development origin
	// would pin localhost to HTTPS long after the process stopped serving TLS.
	hstsMaxAge := time.Duration(0)
	if cfg.IsProduction() {
		hstsMaxAge = cfg.TLSHSTSMaxAge
	}

	routes.Register(engine, log.Logger, routes.Options{
		DocsEnabled:  !cfg.IsProduction(),
		MaxBodyBytes: cfg.ServerMaxBodyBytes,
		CORS: middleware.CORSConfig{
			AllowedOrigins:   cfg.CORSAllowedOrigins,
			AllowedMethods:   cfg.CORSAllowedMethods,
			AllowedHeaders:   cfg.CORSAllowedHeaders,
			ExposedHeaders:   cfg.CORSExposedHeaders,
			AllowCredentials: cfg.CORSAllowCredentials,
			MaxAge:           cfg.CORSMaxAge,
		},
		TLS: middleware.TLSConfig{
			Required:              cfg.TLSEnabled(),
			Direct:                cfg.TLSMode == config.TLSModeDirect,
			TrustedProxies:        cfg.TrustedProxies,
			HSTSMaxAge:            hstsMaxAge,
			HSTSIncludeSubDomains: cfg.TLSHSTSIncludeSubDomains,
		},
	}, wire(cfg, db, redisClient, hasher, tokens))

	srv, err := server.New(cfg, log, engine)
	if err != nil {
		return err
	}

	return srv.Start()
}

// newRedisClient connects to Redis only when rate limiting is enabled. Returning
// a nil client is a valid, intentional state: the route tree then omits the rate
// limit middleware altogether.
func newRedisClient(cfg *config.Config, log *logger.Logger) (*goredis.Client, error) {
	if !cfg.RateLimitEnabled {
		return nil, nil
	}

	return redis.NewClient(cfg, log)
}

// wire is the composition root: it builds the adapters, use cases, authorization
// checker and handlers in one place, so nothing has to be assembled piecemeal in
// run(). It returns exactly what the route tree needs.
func wire(
	cfg *config.Config,
	db *database.Database,
	redisClient *goredis.Client,
	hasher portout.PasswordHasher,
	tokens portout.TokenService,
) routes.Dependencies {
	// Repositories (secondary adapters). Each one owns a single capability:
	// profile CRUD, password credentials and role assignments.
	userRepository := repository.NewUserRepository(db.DB)
	credentialsRepository := repository.NewCredentialsRepository(db.DB)
	roleRepository := repository.NewRoleRepository(db.DB)
	permissionChecker := repository.NewAuthorizationRepository(db.DB)

	// Token management (denylist, session registry and token versions). They
	// share the Redis instance used by the rate limiter, separated by key
	// prefix. Without Redis they fall back to process-local implementations so
	// the documented "rate limiting disabled" development setup still boots.
	denylist, sessions, tokenVersions := newTokenStores(redisClient)

	// Use cases
	authenticationUseCase := usecase.NewAuthenticationUseCase(
		credentialsRepository,
		hasher,
		tokens,
		denylist,
		sessions,
		tokenVersions,
	)

	// The password use case owns both the self-service change and the
	// administrative reset, and revokes every session of the affected user.
	passwordUseCase := usecase.NewPasswordUseCase(
		credentialsRepository,
		hasher,
		tokenVersions,
		sessions,
	)

	// The user use case owns the profile lifecycle, status changes and role
	// assignments. Roles live in their own repository because they answer the
	// authorization questions the business rules depend on.
	userUseCase := usecase.NewUserUseCase(
		userRepository,
		roleRepository,
		hasher,
		tokenVersions,
		sessions,
	)

	sessionManagementUseCase := usecase.NewSessionManagementUseCase(
		sessions,
		denylist,
		tokenVersions,
	)

	// Primary adapters (handlers)
	handlers := &routes.Handlers{
		User:           handler.NewUserHandler(userUseCase),
		Authentication: handler.NewAuthenticationHandler(authenticationUseCase),
		Password:       handler.NewPasswordHandler(passwordUseCase),
		Session:        handler.NewSessionHandler(sessionManagementUseCase),
	}

	return routes.Dependencies{
		TokenParser:   tokens,
		Denylist:      denylist,
		TokenVersions: tokenVersions,
		Permission:    permissionChecker,
		Handlers:      handlers,
		RateLimit:     newRateLimiters(cfg, redisClient),
	}
}

// newTokenStores builds the token management stores. Redis is the production
// choice because the state must survive a restart and be shared by every
// instance; the in-memory variants keep the API usable when Redis is disabled.
func newTokenStores(redisClient *goredis.Client) (
	portout.TokenDenylist,
	portout.SessionRegistry,
	portout.TokenVersionManager,
) {
	if redisClient == nil {
		return tokenstore.NewMemoryTokenDenylist(),
			tokenstore.NewMemorySessionRegistry(),
			tokenstore.NewMemoryTokenVersionManager()
	}

	return tokenstore.NewTokenDenylist(redisClient),
		tokenstore.NewSessionRegistry(redisClient),
		tokenstore.NewTokenVersionManager(redisClient)
}

// newRateLimiters builds the two token buckets used by the API: a strict one for
// the unauthenticated login route and a more generous one for authenticated
// users. When rate limiting is disabled the returned limiters are nil, which the
// middleware reads as "pass-through".
func newRateLimiters(cfg *config.Config, redisClient *goredis.Client) routes.RateLimiters {
	limiters := routes.RateLimiters{}
	if redisClient == nil {
		return limiters
	}

	limiters.Auth = ratelimit.NewTokenBucket(redisClient, "ratelimit:auth", cfg.RateLimitAuthCapacity, cfg.RateLimitAuthRefill)
	limiters.User = ratelimit.NewTokenBucket(redisClient, "ratelimit:user", cfg.RateLimitUserCapacity, cfg.RateLimitUserRefill)

	return limiters
}
