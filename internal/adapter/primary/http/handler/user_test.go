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

func TestUserHandlerCreate(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		usecase    *fakeUserUseCase
		wantStatus int
	}{
		{
			name:       "invalid body",
			body:       `{`,
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing required field",
			body:       `{"name":"John Doe"}`,
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid name",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					return nil, domainerr.ErrInvalidName
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid username",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					return nil, domainerr.ErrInvalidUsername
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid email",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					return nil, domainerr.ErrInvalidEmail
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid password",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					return nil, domainerr.ErrInvalidPassword
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate user",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					return nil, domainerr.ErrUserAlreadyExists
				},
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "internal error",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			body: `{"name":"John Doe","username":"john.doe","email":"john@example.com","password":"password"}`,
			usecase: &fakeUserUseCase{
				createFn: func(_ context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error) {
					if input.Username != "john.doe" || input.Password != "password" {
						t.Errorf("unexpected input: %+v", input)
					}

					return &dto.CreateUserOutput{ID: 1, Name: "JOHN DOE", Username: "john.doe", Email: "john@example.com"}, nil
				},
			},
			wantStatus: http.StatusCreated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewUserHandler(tc.usecase)
			engine.POST("/users", h.Create)

			rec := performRequest(engine, jsonRequest(http.MethodPost, "/users", tc.body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			if tc.wantStatus == http.StatusCreated {
				var resp struct {
					ID       uint64 `json:"id"`
					Username string `json:"username"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v", err)
				}

				if resp.ID != 1 || resp.Username != "john.doe" {
					t.Fatalf("unexpected response: %+v", resp)
				}
			}
		})
	}
}

func TestUserHandlerGet(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakeUserUseCase
		wantStatus int
	}{
		{
			name:       "invalid id",
			path:       "/users/abc",
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "not found",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				findByIDFn: func(context.Context, dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
					return nil, domainerr.ErrUserNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "internal error",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				findByIDFn: func(context.Context, dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				findByIDFn: func(_ context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
					if input.ID != 42 {
						t.Errorf("ID = %d, want 42", input.ID)
					}

					return &dto.FindUserByIDOutput{ID: 42, Name: "JOHN DOE", Username: "john.doe", Email: "john@example.com", IsActive: true}, nil
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewUserHandler(tc.usecase)
			engine.GET("/users/:id", h.Get)

			rec := performRequest(engine, jsonRequest(http.MethodGet, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestUserHandlerList(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		path       string
		usecase    *fakeUserUseCase
		wantStatus int
	}{
		{
			name:       "invalid query",
			path:       "/users?limit=abc",
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "internal error",
			path: "/users",
			usecase: &fakeUserUseCase{
				findAllFn: func(context.Context, dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users?limit=10&offset=5",
			usecase: &fakeUserUseCase{
				findAllFn: func(_ context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
					if input.Limit != 10 || input.Offset != 5 {
						t.Errorf("unexpected pagination: %+v", input)
					}

					return &dto.FindAllUsersOutput{Users: []*dto.UserOutput{
						{ID: 1, Username: "john.doe", IsActive: true, CreatedAt: now, UpdatedAt: now},
					}}, nil
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewUserHandler(tc.usecase)
			engine.GET("/users", h.List)

			rec := performRequest(engine, jsonRequest(http.MethodGet, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			if tc.wantStatus == http.StatusOK {
				var resp struct {
					Users []struct {
						ID       uint64 `json:"id"`
						Username string `json:"username"`
					} `json:"users"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v", err)
				}

				if len(resp.Users) != 1 || resp.Users[0].ID != 1 {
					t.Fatalf("unexpected response: %+v", resp)
				}
			}
		})
	}
}

func TestUserHandlerUpdate(t *testing.T) {
	validBody := `{"name":"Jane Doe","username":"jane.doe","email":"jane@example.com"}`

	tests := []struct {
		name       string
		path       string
		body       string
		usecase    *fakeUserUseCase
		wantStatus int
	}{
		{
			name:       "invalid id",
			path:       "/users/abc",
			body:       validBody,
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid body",
			path:       "/users/42",
			body:       `{`,
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "not found",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					return nil, domainerr.ErrUserNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "invalid name",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					return nil, domainerr.ErrInvalidName
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid username",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					return nil, domainerr.ErrInvalidUsername
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid email",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					return nil, domainerr.ErrInvalidEmail
				},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate user",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					return nil, domainerr.ErrUserAlreadyExists
				},
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "internal error",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42",
			body: validBody,
			usecase: &fakeUserUseCase{
				updateFn: func(_ context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
					if input.ID != 42 || input.Username != "jane.doe" {
						t.Errorf("unexpected input: %+v", input)
					}

					return &dto.UpdateUserOutput{ID: 42, Name: "JANE DOE", Username: "jane.doe", Email: "jane@example.com"}, nil
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewUserHandler(tc.usecase)
			engine.PUT("/users/:id", h.Update)

			rec := performRequest(engine, jsonRequest(http.MethodPut, tc.path, tc.body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestUserHandlerDelete(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakeUserUseCase
		withActor  bool
		wantStatus int
	}{
		{
			name:       "invalid id",
			path:       "/users/abc",
			usecase:    &fakeUserUseCase{},
			withActor:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing actor",
			path:       "/users/42",
			usecase:    &fakeUserUseCase{},
			withActor:  false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "not found",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				deleteFn: func(context.Context, dto.DeleteUserInput) error {
					return domainerr.ErrUserNotFound
				},
			},
			withActor:  true,
			wantStatus: http.StatusNotFound,
		},
		{
			name: "self deletion",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				deleteFn: func(context.Context, dto.DeleteUserInput) error {
					return domainerr.ErrAdminSelfDelete
				},
			},
			withActor:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "last admin",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				deleteFn: func(context.Context, dto.DeleteUserInput) error {
					return domainerr.ErrLastAdmin
				},
			},
			withActor:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "internal error",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				deleteFn: func(context.Context, dto.DeleteUserInput) error {
					return errors.New("database unavailable")
				},
			},
			withActor:  true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42",
			usecase: &fakeUserUseCase{
				deleteFn: func(_ context.Context, input dto.DeleteUserInput) error {
					if input.ID != 42 || input.ActorID != 7 {
						t.Errorf("unexpected input: %+v", input)
					}

					return nil
				},
			},
			withActor:  true,
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewUserHandler(tc.usecase)

			handlers := []gin.HandlerFunc{}
			if tc.withActor {
				handlers = append(handlers, withUserID(7))
			}
			handlers = append(handlers, h.Delete)
			engine.DELETE("/users/:id", handlers...)

			rec := performRequest(engine, jsonRequest(http.MethodDelete, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestUserHandlerSetStatus(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		usecase    *fakeUserUseCase
		withActor  bool
		wantStatus int
	}{
		{
			name:       "invalid id",
			path:       "/users/abc/status",
			body:       `{"is_active":false}`,
			usecase:    &fakeUserUseCase{},
			withActor:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid body",
			path:       "/users/42/status",
			body:       `{`,
			usecase:    &fakeUserUseCase{},
			withActor:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing is_active",
			path:       "/users/42/status",
			body:       `{}`,
			usecase:    &fakeUserUseCase{},
			withActor:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing actor",
			path:       "/users/42/status",
			body:       `{"is_active":false}`,
			usecase:    &fakeUserUseCase{},
			withActor:  false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "not found",
			path: "/users/42/status",
			body: `{"is_active":false}`,
			usecase: &fakeUserUseCase{
				setStatusFn: func(context.Context, dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
					return nil, domainerr.ErrUserNotFound
				},
			},
			withActor:  true,
			wantStatus: http.StatusNotFound,
		},
		{
			name: "self deactivation",
			path: "/users/42/status",
			body: `{"is_active":false}`,
			usecase: &fakeUserUseCase{
				setStatusFn: func(context.Context, dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
					return nil, domainerr.ErrAdminSelfDeactivate
				},
			},
			withActor:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "last admin",
			path: "/users/42/status",
			body: `{"is_active":false}`,
			usecase: &fakeUserUseCase{
				setStatusFn: func(context.Context, dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
					return nil, domainerr.ErrCannotDeactivateLastAdmin
				},
			},
			withActor:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "internal error",
			path: "/users/42/status",
			body: `{"is_active":false}`,
			usecase: &fakeUserUseCase{
				setStatusFn: func(context.Context, dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
					return nil, errors.New("database unavailable")
				},
			},
			withActor:  true,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42/status",
			body: `{"is_active":false}`,
			usecase: &fakeUserUseCase{
				setStatusFn: func(_ context.Context, input dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
					if input.ID != 42 || input.ActorID != 7 || input.IsActive {
						t.Errorf("unexpected input: %+v", input)
					}

					return &dto.SetUserStatusOutput{ID: 42, IsActive: false}, nil
				},
			},
			withActor:  true,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestGin()
			h := NewUserHandler(tc.usecase)

			handlers := []gin.HandlerFunc{}
			if tc.withActor {
				handlers = append(handlers, withUserID(7))
			}
			handlers = append(handlers, h.SetStatus)
			engine.PATCH("/users/:id/status", handlers...)

			rec := performRequest(engine, jsonRequest(http.MethodPatch, tc.path, tc.body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestUserHandlerAssignRole(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakeUserUseCase
		wantStatus int
	}{
		{
			name:       "invalid params",
			path:       "/users/abc/roles/1",
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "user not found",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				assignFn: func(context.Context, dto.AssignRoleInput) error {
					return domainerr.ErrUserNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "role not found",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				assignFn: func(context.Context, dto.AssignRoleInput) error {
					return domainerr.ErrRoleNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "already assigned",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				assignFn: func(context.Context, dto.AssignRoleInput) error {
					return domainerr.ErrRoleAlreadyAssigned
				},
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "internal error",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				assignFn: func(context.Context, dto.AssignRoleInput) error {
					return errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42/roles/3",
			usecase: &fakeUserUseCase{
				assignFn: func(_ context.Context, input dto.AssignRoleInput) error {
					if input.TargetID != 42 || input.RoleID != 3 {
						t.Errorf("unexpected input: %+v", input)
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
			h := NewUserHandler(tc.usecase)
			engine.POST("/users/:id/roles/:role_id", h.AssignRole)

			rec := performRequest(engine, jsonRequest(http.MethodPost, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestUserHandlerRemoveRole(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		usecase    *fakeUserUseCase
		wantStatus int
	}{
		{
			name:       "invalid params",
			path:       "/users/abc/roles/1",
			usecase:    &fakeUserUseCase{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "user not found",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				removeFn: func(context.Context, dto.RemoveRoleInput) error {
					return domainerr.ErrUserNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "role not found",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				removeFn: func(context.Context, dto.RemoveRoleInput) error {
					return domainerr.ErrRoleNotFound
				},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "last admin",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				removeFn: func(context.Context, dto.RemoveRoleInput) error {
					return domainerr.ErrCannotRemoveLastAdmin
				},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "internal error",
			path: "/users/42/roles/1",
			usecase: &fakeUserUseCase{
				removeFn: func(context.Context, dto.RemoveRoleInput) error {
					return errors.New("database unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			path: "/users/42/roles/3",
			usecase: &fakeUserUseCase{
				removeFn: func(_ context.Context, input dto.RemoveRoleInput) error {
					if input.TargetID != 42 || input.RoleID != 3 {
						t.Errorf("unexpected input: %+v", input)
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
			h := NewUserHandler(tc.usecase)
			engine.DELETE("/users/:id/roles/:role_id", h.RemoveRole)

			rec := performRequest(engine, jsonRequest(http.MethodDelete, tc.path, ""))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}
