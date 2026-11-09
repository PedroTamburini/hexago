package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	"github.com/gin-gonic/gin"
)

func TestPasswordHandlerChangePassword(t *testing.T) {
	validBody := `{"current_password":"current-password","new_password":"new-password"}`

	tests := []struct {
		name       string
		body       string
		purpose    string
		usecase    *fakePasswordUseCase
		withUser   bool
		wantStatus int
	}{
		{
			name:       "invalid body",
			body:       `{`,
			usecase:    &fakePasswordUseCase{},
			withUser:   true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing user",
			body:       validBody,
			usecase:    &fakePasswordUseCase{},
			withUser:   false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid new password",
			body: validBody,
			usecase: &fakePasswordUseCase{
				changeFn: func(context.Context, dto.ChangePasswordInput) error {
					return domainerr.ErrInvalidPassword
				},
			},
			withUser:   true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid credentials",
			body: validBody,
			usecase: &fakePasswordUseCase{
				changeFn: func(context.Context, dto.ChangePasswordInput) error {
					return domainerr.ErrInvalidCredentials
				},
			},
			withUser:   true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired temporary password",
			body: validBody,
			usecase: &fakePasswordUseCase{
				changeFn: func(context.Context, dto.ChangePasswordInput) error {
					return domainerr.ErrTempPasswordExpired
				},
			},
			withUser:   true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "change not allowed",
			body: validBody,
			usecase: &fakePasswordUseCase{
				changeFn: func(context.Context, dto.ChangePasswordInput) error {
					return domainerr.ErrChangePasswordNotAllowed
				},
			},
			withUser:   true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "internal error",
			body: validBody,
			usecase: &fakePasswordUseCase{
				changeFn: func(context.Context, dto.ChangePasswordInput) error {
					return errors.New("database unavailable")
				},
			},
			withUser:   true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:    "success forwards user and purpose",
			body:    validBody,
			purpose: "change_password",
			usecase: &fakePasswordUseCase{
				changeFn: func(_ context.Context, input dto.ChangePasswordInput) error {
					if input.UserID != 7 {
						t.Errorf("UserID = %d, want 7", input.UserID)
					}
					if input.TokenPurpose != "change_password" {
						t.Errorf("TokenPurpose = %q, want change_password", input.TokenPurpose)
					}
					if input.CurrentPassword != "current-password" || input.NewPassword != "new-password" {
						t.Errorf("unexpected passwords: %+v", input)
					}

					return nil
				},
			},
			withUser:   true,
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewPasswordHandler(tc.usecase)

			handlers := []gin.HandlerFunc{}
			if tc.withUser {
				handlers = append(handlers, withUserID(7))
			}
			if tc.purpose != "" {
				handlers = append(handlers, withTokenContext("jti", tc.purpose))
			}
			handlers = append(handlers, h.ChangePassword)
			engine.POST("/auth/change-password", handlers...)

			rec := performRequest(engine, jsonRequest(http.MethodPost, "/auth/change-password", tc.body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestPasswordHandlerResetPassword(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakePasswordUseCase
		wantStatus int
	}{
		{
			name:       "invalid id",
			path:       "/users/abc/password/reset",
			usecase:    &fakePasswordUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "user not found",
			path: "/users/42/password/reset",
			usecase: &fakePasswordUseCase{
				resetFn: func(context.Context, dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
					return nil, domainerr.ErrUserNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "internal error",
			path: "/users/42/password/reset",
			usecase: &fakePasswordUseCase{
				resetFn: func(context.Context, dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42/password/reset",
			usecase: &fakePasswordUseCase{
				resetFn: func(_ context.Context, input dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
					if input.TargetID != 42 {
						t.Errorf("TargetID = %d, want 42", input.TargetID)
					}

					return &dto.ResetPasswordOutput{TemporaryPassword: "temp-pass"}, nil
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewPasswordHandler(tc.usecase)
			engine.POST("/users/:id/password/reset", h.ResetPassword)

			rec := performRequest(engine, jsonRequest(http.MethodPost, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			if tc.wantStatus == http.StatusOK {
				var resp struct {
					TemporaryPassword string `json:"temporary_password"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v", err)
				}

				if resp.TemporaryPassword != "temp-pass" {
					t.Fatalf("TemporaryPassword = %q, want temp-pass", resp.TemporaryPassword)
				}
			}
		})
	}
}
