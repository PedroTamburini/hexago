package router

import (
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	"github.com/PedroTamburini/hexago/internal/core/permission"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/gin-gonic/gin"
)

// Dependencies bundles everything the HTTP router needs to build the route tree.
// Keeping it in a single struct avoids a growing list of positional constructor
// parameters and makes the composition root explicit.
type Dependencies struct {
	Tokens     portout.TokenValidator
	Permission portout.PermissionChecker
	Handlers   *Handlers
	// RateLimit carries the per-scope limiters. A nil field disables that scope
	// (the middleware becomes a pass-through), so the route tree can install it
	// unconditionally.
	RateLimit RateLimiters
}

// RateLimiters groups the limiter instances used by the route tree. Auth is keyed
// by client IP (login is unauthenticated) while User is keyed by the
// authenticated user ID.
type RateLimiters struct {
	Auth portout.RateLimiter
	User portout.RateLimiter
}

type Router struct {
	engine     *gin.Engine
	deps       Dependencies
	docsEnable bool
}

func New(logger *logger.Logger, cfg *config.Config, deps Dependencies) *Router {
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
	engine.Use(
		middleware.RequestID(),
		middleware.Logger(logger),
		middleware.Recovery(logger),
		middleware.CORS(),
	)

	r := &Router{
		engine:     engine,
		deps:       deps,
		docsEnable: !cfg.IsProduction(),
	}

	if r.docsEnable {
		registerDocs(engine)
	}

	return r
}

func (r *Router) RegisterRoutes() {
	r.engine.GET("/health", handler.Health)

	v1 := r.engine.Group("/api/v1")
	{
		v1.POST("/auth",
			middleware.RateLimit(r.deps.RateLimit.Auth, middleware.KeyByIP),
			r.deps.Handlers.Auth.Authenticate,
		)

		users := v1.Group("/users")
		users.Use(
			middleware.JWTAuthMiddleware(r.deps.Tokens),
			// Rate limiting must run after JWTAuthMiddleware so the bucket can be
			// keyed on the authenticated user instead of the shared client IP.
			middleware.RateLimit(r.deps.RateLimit.User, middleware.KeyByUserID),
		)

		users.POST("", r.guard(permission.UsersCreate), r.deps.Handlers.User.Create)
		users.GET("", r.guard(permission.UsersRead), r.deps.Handlers.User.List)
		users.GET("/:id", r.guard(permission.UsersRead), r.deps.Handlers.User.Get)
		users.PUT("/:id", r.guard(permission.UsersUpdate), r.deps.Handlers.User.Update)
		users.DELETE("/:id", r.guard(permission.UsersDelete), r.deps.Handlers.User.Delete)
	}
}

func (r *Router) guard(name string) gin.HandlerFunc {
	return middleware.RequirePermission(r.deps.Permission, name)
}

type Handlers struct {
	User *handler.UserHandler
	Auth *handler.AuthHandler
}

func (r *Router) Engine() *gin.Engine {
	return r.engine
}
