package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORSConfig carries the transport settings the CORS middleware needs. It uses
// plain values so the adapter stays independent from the infrastructure config.
type CORSConfig struct {
	// AllowedOrigins is an exact allowlist. A single "*" allows every origin,
	// which is only safe without credentials (the config loader enforces that
	// in production).
	AllowedOrigins []string
	// AllowedMethods and AllowedHeaders are advertised on preflight responses.
	AllowedMethods []string
	AllowedHeaders []string
	// ExposedHeaders lists response headers the browser may read.
	ExposedHeaders []string
	// AllowCredentials reflects the request Origin and enables credentials.
	AllowCredentials bool
	// MaxAge is how long a browser may cache the preflight response.
	MaxAge time.Duration
}

// CORS installs a configurable cross-origin policy. The response depends on the
// request Origin whenever an allowlist is used, so Vary: Origin is always set
// in that case to keep shared caches from serving one origin's headers to
// another.
func CORS(cfg CORSConfig) gin.HandlerFunc {
	allowAll := containsFold(cfg.AllowedOrigins, "*")
	allowMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	exposeHeaders := strings.Join(cfg.ExposedHeaders, ", ")
	maxAge := strconv.FormatInt(int64(cfg.MaxAge/time.Second), 10)

	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")
		preflight := isPreflight(ctx)

		// Without an Origin this is not a cross-origin request: same-origin
		// calls and non-browser clients need no CORS headers.
		if origin == "" {
			if preflight {
				ctx.AbortWithStatus(http.StatusNoContent)
				return
			}
			ctx.Next()
			return
		}

		allowed := allowAll || containsFold(cfg.AllowedOrigins, origin)

		if allowed {
			if allowAll && !cfg.AllowCredentials {
				ctx.Header("Access-Control-Allow-Origin", "*")
			} else {
				// Credentials cannot be combined with "*": echo the exact
				// request Origin instead and vary on it.
				ctx.Header("Access-Control-Allow-Origin", origin)
				addVary(ctx, "Origin")
			}

			if cfg.AllowCredentials {
				ctx.Header("Access-Control-Allow-Credentials", "true")
			}

			if exposeHeaders != "" {
				ctx.Header("Access-Control-Expose-Headers", exposeHeaders)
			}
		}

		if preflight {
			if allowed {
				ctx.Header("Access-Control-Allow-Methods", allowMethods)
				ctx.Header("Access-Control-Allow-Headers", allowHeaders)
				addVary(ctx, "Access-Control-Request-Method", "Access-Control-Request-Headers")
				if cfg.MaxAge > 0 {
					ctx.Header("Access-Control-Max-Age", maxAge)
				}
			}

			// An origin outside the allowlist gets a bare 204: the browser
			// blocks the response because no Access-Control-Allow-Origin is
			// present, and no information is leaked.
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}

		ctx.Next()
	}
}

// isPreflight reports whether the request is a real CORS preflight, so ordinary
// OPTIONS requests still reach their handlers.
func isPreflight(ctx *gin.Context) bool {
	return ctx.Request.Method == http.MethodOptions &&
		ctx.GetHeader("Access-Control-Request-Method") != ""
}

func containsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

// addVary appends fields to the Vary header without duplicating existing ones.
func addVary(ctx *gin.Context, fields ...string) {
	header := ctx.Writer.Header()
	existing := header.Get("Vary")

	var tokens []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(existing, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		tokens = append(tokens, token)
		seen[strings.ToLower(token)] = struct{}{}
	}

	for _, field := range fields {
		key := strings.ToLower(field)
		if _, ok := seen[key]; ok {
			continue
		}
		tokens = append(tokens, field)
		seen[key] = struct{}{}
	}

	header.Set("Vary", strings.Join(tokens, ", "))
}
