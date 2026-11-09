package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/PedroTamburini/hexago/internal/core/dto"
	"github.com/gin-gonic/gin"
)

type fakeUserUseCase struct {
	createFn    func(context.Context, dto.CreateUserInput) (*dto.CreateUserOutput, error)
	findByIDFn  func(context.Context, dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error)
	findAllFn   func(context.Context, dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error)
	updateFn    func(context.Context, dto.UpdateUserInput) (*dto.UpdateUserOutput, error)
	deleteFn    func(context.Context, dto.DeleteUserInput) error
	setStatusFn func(context.Context, dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error)
	assignFn    func(context.Context, dto.AssignRoleInput) error
	removeFn    func(context.Context, dto.RemoveRoleInput) error
}

func (f *fakeUserUseCase) Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error) {
	if f.createFn != nil {
		return f.createFn(ctx, input)
	}

	return nil, nil
}

func (f *fakeUserUseCase) FindByID(ctx context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
	if f.findByIDFn != nil {
		return f.findByIDFn(ctx, input)
	}

	return nil, nil
}

func (f *fakeUserUseCase) FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
	if f.findAllFn != nil {
		return f.findAllFn(ctx, input)
	}

	return nil, nil
}

func (f *fakeUserUseCase) Update(ctx context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
	if f.updateFn != nil {
		return f.updateFn(ctx, input)
	}

	return nil, nil
}

func (f *fakeUserUseCase) Delete(ctx context.Context, input dto.DeleteUserInput) error {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, input)
	}

	return nil
}

func (f *fakeUserUseCase) SetStatus(ctx context.Context, input dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
	if f.setStatusFn != nil {
		return f.setStatusFn(ctx, input)
	}

	return nil, nil
}

func (f *fakeUserUseCase) AssignRole(ctx context.Context, input dto.AssignRoleInput) error {
	if f.assignFn != nil {
		return f.assignFn(ctx, input)
	}

	return nil
}

func (f *fakeUserUseCase) RemoveRole(ctx context.Context, input dto.RemoveRoleInput) error {
	if f.removeFn != nil {
		return f.removeFn(ctx, input)
	}

	return nil
}

type fakeAuthenticationUseCase struct {
	authenticateFn func(context.Context, dto.AuthenticateInput) (*dto.AuthenticateOutput, error)
	logoutFn       func(context.Context, string) error
}

func (f *fakeAuthenticationUseCase) Authenticate(ctx context.Context, input dto.AuthenticateInput) (*dto.AuthenticateOutput, error) {
	if f.authenticateFn != nil {
		return f.authenticateFn(ctx, input)
	}

	return nil, nil
}

func (f *fakeAuthenticationUseCase) Logout(ctx context.Context, token string) error {
	if f.logoutFn != nil {
		return f.logoutFn(ctx, token)
	}

	return nil
}

func (f *fakeAuthenticationUseCase) RevokeToken(context.Context, string) error { return nil }

func (f *fakeAuthenticationUseCase) RevokeAllUserTokens(context.Context, uint64) error { return nil }

type fakePasswordUseCase struct {
	changeFn func(context.Context, dto.ChangePasswordInput) error
	resetFn  func(context.Context, dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error)
}

func (f *fakePasswordUseCase) ChangePassword(ctx context.Context, input dto.ChangePasswordInput) error {
	if f.changeFn != nil {
		return f.changeFn(ctx, input)
	}

	return nil
}

func (f *fakePasswordUseCase) ResetPassword(ctx context.Context, input dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
	if f.resetFn != nil {
		return f.resetFn(ctx, input)
	}

	return nil, nil
}

type fakeSessionUseCase struct {
	listFn   func(context.Context, uint64) ([]*dto.SessionDTO, error)
	revokeFn func(context.Context, string) error
	allFn    func(context.Context, uint64) error
}

func (f *fakeSessionUseCase) ListUserSessions(ctx context.Context, userID uint64) ([]*dto.SessionDTO, error) {
	if f.listFn != nil {
		return f.listFn(ctx, userID)
	}

	return nil, nil
}

func (f *fakeSessionUseCase) RevokeSession(ctx context.Context, jti string) error {
	if f.revokeFn != nil {
		return f.revokeFn(ctx, jti)
	}

	return nil
}

func (f *fakeSessionUseCase) RevokeAllUserSessions(ctx context.Context, userID uint64) error {
	if f.allFn != nil {
		return f.allFn(ctx, userID)
	}

	return nil
}

func newTestGin() *gin.Engine {
	gin.SetMode(gin.TestMode)

	return gin.New()
}

func performRequest(engine *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

func jsonRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return req
}

func withUserID(userID uint64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", userID)
	}
}

func withTokenContext(jti, purpose string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("token_jti", jti)
		c.Set("token_purpose", purpose)
	}
}
