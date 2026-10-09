package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func Logger(log *logger.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		path := ctx.Request.URL.Path
		query := ctx.Request.URL.RawQuery
		requestID := ctx.GetString("request_id")

		ctx.Next()

		log.InfoContext(
			ctx.Request.Context(),
			"request completed",
			"request_id", requestID,
			"method", ctx.Request.Method,
			"path", path,
			"query", query,
			"status", ctx.Writer.Status(),
			"latency", time.Since(start),
			"client_ip", ctx.ClientIP(),
			"body_size", ctx.Writer.Size(),
		)

		if len(ctx.Errors) > 0 {
			for _, err := range ctx.Errors {
				log.Error("request error", slog.String("error", err.Error()))
			}
		}
	}
}

func CORS() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("Access-Control-Allow-Origin", "*")
		ctx.Header("Access-Control-Allow-Credentials", "false") // Modify as needed and when specifying Allowed-Origins
		ctx.Header("Access-Control-Allow-Headers", "Authorization, Accept, Content-Type, Origin, X-CSRF-Token, X-Requested-With")
		ctx.Header("Access-Control-Allow-Methods", "DELETE, GET, OPTIONS, POST, PUT")

		if ctx.Request.Method == http.MethodOptions {
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}
		ctx.Next()
	}
}

func RequestID() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		requestID := ctx.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		ctx.Set("request_id", requestID)
		ctx.Header("X-Request-ID", requestID)
		ctx.Next()
	}
}

func Recovery(logger *logger.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.ErrorContext(ctx.Request.Context(),
					"panic recovered",
					"error", err,
					"request_id", ctx.GetString("request_id"),
				)
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, response.ErrorResponse{Error: "internal server error"})
			}
		}()
		ctx.Next()
	}
}
