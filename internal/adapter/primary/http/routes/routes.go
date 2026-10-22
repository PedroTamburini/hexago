package routes

import (
	"log/slog"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	"github.com/PedroTamburini/hexago/internal/core/permission"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

// Options carries the transport settings the route tree needs. Plain values are
// used instead of the infrastructure config so this adapter stays independent
// from it.
type Options struct {
	// DocsEnabled registers the Swagger UI. It is meant to be false in
	// production so the interactive explorer is never publicly reachable.
	DocsEnabled bool
	// MaxBodyBytes caps the size of a request body on the versioned API.
	MaxBodyBytes int
}

// Dependencies bundles everything the HTTP route tree needs to build itself.
// Keeping it in a single struct avoids a growing list of positional parameters
// and makes the composition root explicit.
type Dependencies struct {
	TokenParser   portout.TokenParser
	Denylist      portout.TokenDenylist
	TokenVersions portout.TokenVersionManager
	Permission    portout.PermissionChecker
	Handlers      *Handlers
	// RateLimit carries the per-scope limiters. A nil field disables that scope
	// (the middleware becomes a pass-through), so the route tree can install it
	// unconditionally.
	RateLimit RateLimiters
}

// RateLimiters groups the limiter instances used by the route tree. Auth is
// keyed by client IP (login is unauthenticated) while User is keyed by the
// authenticated user ID.
type RateLimiters struct {
	Auth portout.RateLimiter
	User portout.RateLimiter
}

// Handlers groups the primary adapters (HTTP handlers) bound to the routes.
type Handlers struct {
	User    *handler.UserHandler
	Auth    *handler.AuthHandler
	Session *handler.SessionHandler
}

// Register installs the global middleware and the route tree on the engine. It
// must be called once, before the server starts.
func Register(engine *gin.Engine, log *slog.Logger, opts Options, deps Dependencies) {
	// Global middleware must be installed before any route is registered,
	// otherwise gin builds those routes' handler chains without them.
	engine.Use(
		middleware.RequestID(),
		middleware.Logger(log),
		middleware.Recovery(log),
		middleware.CORS(),
		middleware.SecurityHeaders(),
	)

	if opts.DocsEnabled {
		registerDocs(engine)
	}

	engine.GET("/health", handler.Health)

	authenticate := middleware.JWTAuthMiddleware(deps.TokenParser, deps.Denylist, deps.TokenVersions)

	v1 := engine.Group("/api/v1")
	v1.Use(middleware.BodyLimit(int64(opts.MaxBodyBytes)))
	{
		v1.POST("/auth",
			middleware.RateLimit(deps.RateLimit.Auth, middleware.KeyByIP),
			deps.Handlers.Auth.Authenticate,
		)

		v1.POST("/auth/logout",
			authenticate,
			middleware.RateLimit(deps.RateLimit.User, middleware.KeyByUserID),
			deps.Handlers.Auth.Logout,
		)

		users := v1.Group("/users")
		users.Use(
			authenticate,
			// Rate limiting must run after JWTAuthMiddleware so the bucket can be
			// keyed on the authenticated user instead of the shared client IP.
			middleware.RateLimit(deps.RateLimit.User, middleware.KeyByUserID),
		)

		users.POST("", guard(deps, permission.UsersCreate), deps.Handlers.User.Create)
		users.GET("", guard(deps, permission.UsersRead), deps.Handlers.User.List)
		users.GET("/:id", guard(deps, permission.UsersRead), deps.Handlers.User.Get)
		users.PUT("/:id", guard(deps, permission.UsersUpdate), deps.Handlers.User.Update)
		users.DELETE("/:id", guard(deps, permission.UsersDelete), deps.Handlers.User.Delete)

		admin := v1.Group("/admin")
		admin.Use(
			authenticate,
			middleware.RateLimit(deps.RateLimit.User, middleware.KeyByUserID),
		)

		admin.GET("/users/:id/sessions", guard(deps, permission.SessionsRead), deps.Handlers.Session.ListUserSessions)
		admin.DELETE("/users/:id/sessions", guard(deps, permission.SessionsRevoke), deps.Handlers.Session.RevokeAllUserSessions)
		admin.DELETE("/sessions/:jti", guard(deps, permission.SessionsRevoke), deps.Handlers.Session.RevokeSession)
	}
}

func guard(deps Dependencies, name string) gin.HandlerFunc {
	return middleware.RequirePermission(deps.Permission, name)
}
