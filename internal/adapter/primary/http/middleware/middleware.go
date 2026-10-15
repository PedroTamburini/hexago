package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Logger records one structured line per request.
func Logger(log *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		path := ctx.Request.URL.Path
		query := ctx.Request.URL.RawQuery
		requestID := getRequestID(ctx)

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

		for _, err := range ctx.Errors {
			log.ErrorContext(ctx.Request.Context(), "request error", slog.String("error", err.Error()))
		}
	}
}

func CORS() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("Access-Control-Allow-Origin", "*")
		ctx.Header("Access-Control-Allow-Credentials", "false") // Modify as needed and when specifying Allowed-Origins
		ctx.Header("Access-Control-Allow-Headers", "Authorization, Accept, Content-Type, Origin, X-Requested-With")
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
		setRequestID(ctx, requestID)
		ctx.Header("X-Request-ID", requestID)
		ctx.Next()
	}
}

// Recovery converts a panic into a 500 response and logs it, accepting a plain
// *slog.Logger to keep the adapter free of infrastructure imports.
func Recovery(log *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.ErrorContext(ctx.Request.Context(),
					"panic recovered",
					"error", err,
					"request_id", getRequestID(ctx),
				)
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, response.ErrorResponse{Error: "internal server error"})
			}
		}()
		ctx.Next()
	}
}
