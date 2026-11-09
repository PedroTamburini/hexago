package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
)

func TestAuthenticationHandlerAuthenticate(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		usecase    *fakeAuthenticationUseCase
		wantStatus int
	}{
		{
			name:       "invalid body",
			body:       `{`,
			usecase:    &fakeAuthenticationUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid credentials",
			body: `{"username":"john.doe","password":"wrong-password"}`,
			usecase: &fakeAuthenticationUseCase{
				authenticateFn: func(context.Context, dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
					return nil, domainerr.ErrInvalidCredentials
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired temporary password",
			body: `{"username":"john.doe","password":"temp-password"}`,
			usecase: &fakeAuthenticationUseCase{
				authenticateFn: func(context.Context, dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
					return nil, domainerr.ErrTempPasswordExpired
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "internal error",
			body: `{"username":"john.doe","password":"any-password"}`,
			usecase: &fakeAuthenticationUseCase{
				authenticateFn: func(context.Context, dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			body: `{"username":"john.doe","password":"correct-password"}`,
			usecase: &fakeAuthenticationUseCase{
				authenticateFn: func(_ context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
					if input.Username != "john.doe" || input.Password != "correct-password" {
						t.Errorf("unexpected input: %+v", input)
					}

					return &dto.AuthenticateOutput{Token: "token", ExpireIn: 900}, nil
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewAuthenticationHandler(tc.usecase)
			engine.POST("/auth", h.Authenticate)

			rec := performRequest(engine, jsonRequest(http.MethodPost, "/auth", tc.body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			if tc.wantStatus == http.StatusOK {
				var resp struct {
					Token    string `json:"token"`
					ExpireIn int64  `json:"expire_in"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v", err)
				}

				if resp.Token != "token" || resp.ExpireIn != 900 {
					t.Fatalf("unexpected response: %+v", resp)
				}
			}
		})
	}
}

func TestAuthenticationHandlerLogout(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		usecase    *fakeAuthenticationUseCase
		wantStatus int
		wantToken  string
	}{
		{
			name:       "missing header",
			usecase:    &fakeAuthenticationUseCase{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed header",
			header:     "Basic abc",
			usecase:    &fakeAuthenticationUseCase{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "invalid token",
			header: "Bearer broken",
			usecase: &fakeAuthenticationUseCase{
				logoutFn: func(context.Context, string) error {
					return domainerr.ErrInvalidToken
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "internal error",
			header: "Bearer token",
			usecase: &fakeAuthenticationUseCase{
				logoutFn: func(context.Context, string) error {
					return errors.New("redis unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:   "success",
			header: "Bearer token",
			usecase: &fakeAuthenticationUseCase{
				logoutFn: func(_ context.Context, token string) error {
					if token != "token" {
						t.Errorf("token = %q, want %q", token, "token")
					}

					return nil
				},
			},
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewAuthenticationHandler(tc.usecase)
			engine.POST("/auth/logout", h.Logout)

			req := jsonRequest(http.MethodPost, "/auth/logout", "")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			rec := performRequest(engine, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{name: "valid", header: "Bearer token", wantToken: "token", wantOK: true},
		{name: "lowercase scheme", header: "bearer token", wantToken: "token", wantOK: true},
		{name: "empty header", header: "", wantOK: false},
		{name: "wrong scheme", header: "Basic token", wantOK: false},
		{name: "missing token", header: "Bearer", wantOK: false},
		{name: "empty token", header: "Bearer ", wantOK: false},
		{name: "extra parts", header: "Bearer a b", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, ok := bearerToken(tc.header)

			if ok != tc.wantOK {
				t.Fatalf("bearerToken(%q) ok = %v, want %v", tc.header, ok, tc.wantOK)
			}

			if token != tc.wantToken {
				t.Fatalf("bearerToken(%q) = %q, want %q", tc.header, token, tc.wantToken)
			}
		})
	}
}
