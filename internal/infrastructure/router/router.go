package router

import (
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/PedroTamburini/hexago/internal/infrastructure/middleware"
	"github.com/gin-gonic/gin"
)

type Router struct {
	engine *gin.Engine
}

func NewRouter(logger *logger.Logger, cfg *config.Config) *Router {
	if cfg.Environment == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
	engine.Use(
		middleware.RequestID(),
		middleware.Logger(logger),
		middleware.Recovery(logger),
		middleware.CORS(),
	)

	return &Router{
		engine: engine,
	}
}

func (r *Router) RegisterRoutes(handlers *Handlers) {
	v1 := r.engine.Group("/api/v1")
	{
		handlers.User.Register(v1.Group("/users"))
	}
}

type Handlers struct {
	User *handler.UserHandler
}

func (r *Router) Engine() *gin.Engine {
	return r.engine
}
