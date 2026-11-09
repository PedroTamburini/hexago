package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	"github.com/gin-gonic/gin"
)

func TestSessionHandlerListUserSessions(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		path       string
		currentJTI string
		usecase    *fakeSessionUseCase
		wantStatus int
		wantFlag   map[string]bool
	}{
		{
			name:       "invalid id",
			path:       "/admin/users/abc/sessions",
			usecase:    &fakeSessionUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "internal error",
			path: "/admin/users/42/sessions",
			usecase: &fakeSessionUseCase{
				listFn: func(context.Context, uint64) ([]*dto.SessionDTO, error) {
					return nil, errors.New("redis unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "empty list",
			path:       "/admin/users/42/sessions",
			usecase:    &fakeSessionUseCase{},
			wantStatus: http.StatusOK,
			wantFlag:   map[string]bool{},
		},
		{
			name:       "flags current session",
			path:       "/admin/users/42/sessions",
			currentJTI: "jti-1",
			usecase: &fakeSessionUseCase{
				listFn: func(_ context.Context, userID uint64) ([]*dto.SessionDTO, error) {
					if userID != 42 {
						t.Errorf("userID = %d, want 42", userID)
					}

					return []*dto.SessionDTO{
						{JTI: "jti-1", UserID: 42, IssuedAt: now, ExpiresAt: now.Add(time.Hour), IP: "203.0.113.10", UserAgent: "agent"},
						{JTI: "jti-2", UserID: 42, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
					}, nil
				},
			},
			wantStatus: http.StatusOK,
			wantFlag:   map[string]bool{"jti-1": true, "jti-2": false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewSessionHandler(tc.usecase)

			handlers := []gin.HandlerFunc{}
			if tc.currentJTI != "" {
				handlers = append(handlers, withTokenContext(tc.currentJTI, "access"))
			}
			handlers = append(handlers, h.ListUserSessions)
			engine.GET("/admin/users/:id/sessions", handlers...)

			rec := performRequest(engine, jsonRequest(http.MethodGet, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			if tc.wantStatus != http.StatusOK {
				return
			}

			var resp struct {
				Sessions []struct {
					JTI       string `json:"jti"`
					IsCurrent bool   `json:"is_current"`
				} `json:"sessions"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode body: %v", err)
			}

			if len(resp.Sessions) != len(tc.wantFlag) {
				t.Fatalf("len(sessions) = %d, want %d", len(resp.Sessions), len(tc.wantFlag))
			}

			for _, session := range resp.Sessions {
				if session.IsCurrent != tc.wantFlag[session.JTI] {
					t.Errorf("session %s is_current = %v, want %v", session.JTI, session.IsCurrent, tc.wantFlag[session.JTI])
				}
			}
		})
	}
}

func TestSessionHandlerRevokeSession(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakeSessionUseCase
		wantStatus int
	}{
		{
			name:       "empty jti",
			path:       "/admin/sessions",
			usecase:    &fakeSessionUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "not found",
			path: "/admin/sessions/missing",
			usecase: &fakeSessionUseCase{
				revokeFn: func(context.Context, string) error {
					return domainerr.ErrSessionNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "internal error",
			path: "/admin/sessions/jti-1",
			usecase: &fakeSessionUseCase{
				revokeFn: func(context.Context, string) error {
					return errors.New("redis unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/admin/sessions/jti-1",
			usecase: &fakeSessionUseCase{
				revokeFn: func(_ context.Context, jti string) error {
					if jti != "jti-1" {
						t.Errorf("jti = %q, want jti-1", jti)
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
			h := NewSessionHandler(tc.usecase)
			engine.DELETE("/admin/sessions", h.RevokeSession)
			engine.DELETE("/admin/sessions/:jti", h.RevokeSession)

			rec := performRequest(engine, jsonRequest(http.MethodDelete, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestSessionHandlerRevokeAllUserSessions(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakeSessionUseCase
		wantStatus int
	}{
		{
			name:       "invalid id",
			path:       "/admin/users/abc/sessions",
			usecase:    &fakeSessionUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "internal error",
			path: "/admin/users/42/sessions",
			usecase: &fakeSessionUseCase{
				allFn: func(context.Context, uint64) error {
					return errors.New("redis unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/admin/users/42/sessions",
			usecase: &fakeSessionUseCase{
				allFn: func(_ context.Context, userID uint64) error {
					if userID != 42 {
						t.Errorf("userID = %d, want 42", userID)
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
			h := NewSessionHandler(tc.usecase)
			engine.DELETE("/admin/users/:id/sessions", h.RevokeAllUserSessions)

			rec := performRequest(engine, jsonRequest(http.MethodDelete, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}
