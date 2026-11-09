package routes

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/handler"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/middleware"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/gin-gonic/gin"
)

type routeTokenParser struct {
	claims *portout.TokenClaims
	err    error
}

func (p routeTokenParser) ParseClaims(string) (*portout.TokenClaims, error) {
	if p.err != nil {
		return nil, p.err
	}

	return p.claims, nil
}

type routeDenylist struct {
	revoked bool
}

func (d routeDenylist) Revoke(context.Context, string, time.Time) error { return nil }

func (d routeDenylist) IsRevoked(context.Context, string) (bool, error) {
	return d.revoked, nil
}

type routeTokenVersions struct{}

func (routeTokenVersions) GetVersion(context.Context, uint64) (int, error) { return 0, nil }

func (routeTokenVersions) IncrementVersion(context.Context, uint64) (int, error) { return 1, nil }

type routePermissionChecker struct {
	allowed bool
	err     error
}

func (c routePermissionChecker) HasPermission(context.Context, uint64, string) (bool, error) {
	return c.allowed, c.err
}

type routeRateLimiter struct {
	decision portout.RateLimitDecision
	err      error
	calls    *int
}

func (l routeRateLimiter) Allow(context.Context, string) (portout.RateLimitDecision, error) {
	if l.calls != nil {
		*l.calls = *l.calls + 1
	}

	return l.decision, l.err
}

type routeUserUseCase struct {
	findAllFn func(context.Context, dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error)
}

func (u routeUserUseCase) Create(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
	return nil, nil
}

func (u routeUserUseCase) FindByID(context.Context, dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
	return nil, domainerr.ErrUserNotFound
}

func (u routeUserUseCase) FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
	if u.findAllFn != nil {
		return u.findAllFn(ctx, input)
	}

	return &dto.FindAllUsersOutput{}, nil
}

func (u routeUserUseCase) Update(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
	return nil, nil
}

func (u routeUserUseCase) Delete(context.Context, dto.DeleteUserInput) error { return nil }

func (u routeUserUseCase) SetStatus(context.Context, dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
	return nil, nil
}

func (u routeUserUseCase) AssignRole(context.Context, dto.AssignRoleInput) error { return nil }

func (u routeUserUseCase) RemoveRole(context.Context, dto.RemoveRoleInput) error { return nil }

type routeAuthenticationUseCase struct{}

func (routeAuthenticationUseCase) Authenticate(context.Context, dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	return &dto.AuthenticateOutput{Token: "token"}, nil
}

func (routeAuthenticationUseCase) Logout(context.Context, string) error { return nil }

func (routeAuthenticationUseCase) RevokeToken(context.Context, string) error { return nil }

func (routeAuthenticationUseCase) RevokeAllUserTokens(context.Context, uint64) error { return nil }

type routePasswordUseCase struct{}

func (routePasswordUseCase) ChangePassword(context.Context, dto.ChangePasswordInput) error {
	return nil
}

func (routePasswordUseCase) ResetPassword(context.Context, dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
	return &dto.ResetPasswordOutput{}, nil
}

type routeSessionUseCase struct{}

func (routeSessionUseCase) ListUserSessions(context.Context, uint64) ([]*dto.SessionDTO, error) {
	return nil, nil
}

func (routeSessionUseCase) RevokeSession(context.Context, string) error { return nil }

func (routeSessionUseCase) RevokeAllUserSessions(context.Context, uint64) error { return nil }

func routeClaims() *portout.TokenClaims {
	return &portout.TokenClaims{
		JTI:       "jti-1",
		Subject:   "42",
		TokenVer:  0,
		Purpose:   portout.TokenPurposeAccess,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func newRouteEngine(t *testing.T, opts Options, deps Dependencies) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	Register(engine, slog.New(slog.NewTextHandler(io.Discard, nil)), opts, deps)

	return engine
}

func defaultRouteDependencies() Dependencies {
	return Dependencies{
		TokenParser:   routeTokenParser{claims: routeClaims()},
		Denylist:      routeDenylist{},
		TokenVersions: routeTokenVersions{},
		Permission:    routePermissionChecker{allowed: true},
		Handlers: &Handlers{
			User:           handler.NewUserHandler(routeUserUseCase{}),
			Authentication: handler.NewAuthenticationHandler(routeAuthenticationUseCase{}),
			Password:       handler.NewPasswordHandler(routePasswordUseCase{}),
			Session:        handler.NewSessionHandler(routeSessionUseCase{}),
		},
	}
}

func defaultRouteOptions() Options {
	return Options{
		MaxBodyBytes: 1 << 20,
		TLS:          middleware.TLSConfig{},
	}
}

func serveRoute(engine *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

func TestRoutesHealthIsPublic(t *testing.T) {
	engine := newRouteEngine(t, defaultRouteOptions(), defaultRouteDependencies())

	rec := serveRoute(engine, http.MethodGet, "/health", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRoutesProtectedEndpointRequiresAuthentication(t *testing.T) {
	engine := newRouteEngine(t, defaultRouteOptions(), defaultRouteDependencies())

	rec := serveRoute(engine, http.MethodGet, "/api/v1/users", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRoutesProtectedEndpointRequiresPermission(t *testing.T) {
	deps := defaultRouteDependencies()
	deps.Permission = routePermissionChecker{allowed: false}

	engine := newRouteEngine(t, defaultRouteOptions(), deps)

	rec := serveRoute(engine, http.MethodGet, "/api/v1/users", "token")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRoutesAuthorizedRequestReachesHandler(t *testing.T) {
	called := false

	deps := defaultRouteDependencies()
	deps.Handlers.User = handler.NewUserHandler(routeUserUseCase{
		findAllFn: func(context.Context, dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
			called = true

			return &dto.FindAllUsersOutput{}, nil
		},
	})

	engine := newRouteEngine(t, defaultRouteOptions(), deps)

	rec := serveRoute(engine, http.MethodGet, "/api/v1/users", "token")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if !called {
		t.Fatal("expected the handler to be reached")
	}
}

func TestRoutesRateLimitRunsAfterJWTAuthentication(t *testing.T) {
	// An unauthenticated request must be rejected before the limiter runs; a
	// valid one must reach (and be limited by) the configured limiter.
	authCalls := 0
	userCalls := 0

	deps := defaultRouteDependencies()
	deps.RateLimit = RateLimiters{
		Auth: routeRateLimiter{decision: portout.RateLimitDecision{Allowed: true, Limit: 10, Remaining: 9}, calls: &authCalls},
		User: routeRateLimiter{decision: portout.RateLimitDecision{Allowed: false, RetryAfter: time.Second}, calls: &userCalls},
	}

	engine := newRouteEngine(t, defaultRouteOptions(), deps)

	rec := serveRoute(engine, http.MethodGet, "/api/v1/users", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	if userCalls != 0 {
		t.Fatalf("expected the user limiter not to run, got %d calls", userCalls)
	}

	rec = serveRoute(engine, http.MethodGet, "/api/v1/users", "token")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("authenticated status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	if userCalls != 1 {
		t.Fatalf("user limiter calls = %d, want 1", userCalls)
	}
}

func TestRoutesBodyLimitAppliesToVersionedAPI(t *testing.T) {
	opts := defaultRouteOptions()
	opts.MaxBodyBytes = 16

	engine := newRouteEngine(t, opts, defaultRouteDependencies())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth", strings.NewReader(strings.Repeat("a", 64)))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 64
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestRoutesDocsDependOnEnvironment(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		opts := defaultRouteOptions()
		opts.DocsEnabled = true

		engine := newRouteEngine(t, opts, defaultRouteDependencies())

		rec := serveRoute(engine, http.MethodGet, "/swagger/index.html", "")

		if rec.Code == http.StatusNotFound {
			t.Fatal("expected the Swagger UI to be registered")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		engine := newRouteEngine(t, defaultRouteOptions(), defaultRouteDependencies())

		rec := serveRoute(engine, http.MethodGet, "/swagger/index.html", "")

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}
