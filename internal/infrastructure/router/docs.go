package router

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	// Registers the generated OpenAPI specification. Regenerate with:
	// swag init -g cmd/api/main.go -o docs --parseDependency --parseInternal
	_ "github.com/PedroTamburini/hexago/docs"
)

// registerDocs exposes the Swagger UI. It is only called outside production, so
// the interactive API explorer is never publicly reachable in a deployed
// environment.
func registerDocs(engine *gin.Engine) {
	engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}
