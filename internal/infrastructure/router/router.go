package router

import (
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/PedroTamburini/hexago/internal/infrastructure/middleware"
	"github.com/gin-gonic/gin"
)

type Router struct {
	engine *gin.Engine
	tokens port.TokenValidator
}

func NewRouter(logger *logger.Logger, cfg *config.Config, tokens port.TokenValidator) *Router {
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
		engine: engine,
		tokens: tokens,
	}

	return r
}

func (r *Router) RegisterRoutes(handlers *Handlers) {
	v1 := r.engine.Group("/api/v1")
	{
		handlers.Auth.Register(v1.Group("/auth"))

		// The router owns the authentication chain: primary adapters only
		// declare routes and stay unaware of the middleware implementation.
		users := v1.Group("/users")
		users.Use(middleware.JWTAuthMiddleware(r.tokens))
		handlers.User.Register(users)
	}
}

type Handlers struct {
	User *handler.UserHandler
	Auth *handler.AuthHandler
}

func (r *Router) Engine() *gin.Engine {
	return r.engine
}
