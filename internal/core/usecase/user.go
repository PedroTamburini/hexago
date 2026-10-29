package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	"github.com/PedroTamburini/hexago/internal/core/domain/validator"
	"github.com/PedroTamburini/hexago/internal/core/dto"
	portin "github.com/PedroTamburini/hexago/internal/core/port/primary"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

const (
	// DefaultLimit is applied when the caller does not provide a limit, so an
	// omitted value never reaches the repository as a zero limit.
	DefaultLimit = 20
	// MaxLimit is the hard cap of records returned by a single page.
	MaxLimit = 100
	// tempPasswordTTL bounds how long an administrative password reset can be
	// used to log in and choose a new password.
	tempPasswordTTL = 24 * time.Hour
)

type userUseCase struct {
	repo          portout.UserRepository
	hasher        portout.PasswordHasher
	tokenVersions portout.TokenVersionManager
	sessions      portout.SessionRegistry
}

func NewUserUseCase(
	repo portout.UserRepository,
	hasher portout.PasswordHasher,
	tokenVersions portout.TokenVersionManager,
	sessions portout.SessionRegistry,
) portin.UserUseCase {
	return &userUseCase{
		repo:          repo,
		hasher:        hasher,
		tokenVersions: tokenVersions,
		sessions:      sessions,
	}
}

// revokeAllUserTokens invalidates every token of a user by bumping the version
// and clears the session records. Deactivation and password reset rely on it so
// a token issued before the change stops working immediately.
func (uc *userUseCase) revokeAllUserTokens(ctx context.Context, userID uint64) error {
	if _, err := uc.tokenVersions.IncrementVersion(ctx, userID); err != nil {
		return err
	}

	return uc.sessions.RemoveAllByUserID(ctx, userID)
}

func (uc *userUseCase) Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error) {
	if !validator.IsValidPassword(input.Password) {
		return nil, domainerr.ErrInvalidPassword
	}

	user, err := entity.NewUser(input.Name, input.Username, input.Email)
	if err != nil {
		return nil, err
	}

	passwordHash, err := uc.hasher.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	user.SetPasswordHash(passwordHash)

	if err := uc.repo.Create(ctx, user); err != nil {
		return nil, err
	}

	return &dto.CreateUserOutput{
		ID:       user.ID,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}, nil
}

func (uc *userUseCase) FindByID(ctx context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
	user, err := uc.repo.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	return &dto.FindUserByIDOutput{
		ID:        user.ID,
		Name:      user.Name,
		Username:  user.Username,
		Email:     user.Email,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (uc *userUseCase) FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
	limit, offset := normalizePagination(input.Limit, input.Offset)

	users, err := uc.repo.FindAll(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	output := make([]*dto.UserOutput, len(users))
	for i, user := range users {
		output[i] = &dto.UserOutput{
			ID:        user.ID,
			Name:      user.Name,
			Username:  user.Username,
			Email:     user.Email,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	return &dto.FindAllUsersOutput{
		Users: output,
	}, nil
}

func (uc *userUseCase) Update(ctx context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
	user, err := uc.repo.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	if err := user.Update(input.Name, input.Username, input.Email); err != nil {
		return nil, err
	}

	if err := uc.repo.Update(ctx, user); err != nil {
		return nil, err
	}

	return &dto.UpdateUserOutput{
		ID:        user.ID,
		Name:      user.Name,
		Username:  user.Username,
		Email:     user.Email,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

// Delete removes a user after enforcing the administrator safety rules: an
// administrator cannot delete their own account, and no one may delete the
// last active administrator, since that would lock the application out of
// privileged operations until the database is fixed by hand.
func (uc *userUseCase) Delete(ctx context.Context, input dto.DeleteUserInput) error {
	target, err := uc.repo.FindByID(ctx, input.ID)
	if err != nil {
		return err
	}

	isAdmin, err := uc.repo.IsAdmin(ctx, input.ID)
	if err != nil {
		return err
	}

	if isAdmin {
		if input.ID == input.ActorID {
			return domainerr.ErrAdminSelfDelete
		}

		if target.IsActive {
			activeAdmins, err := uc.repo.CountActiveAdmins(ctx)
			if err != nil {
				return err
			}

			if activeAdmins <= 1 {
				return domainerr.ErrLastAdmin
			}
		}
	}

	return uc.repo.Delete(ctx, input.ID)
}

// normalizePagination clamps caller supplied pagination values so the
// repository never receives a non positive limit (which GORM would translate
// into "LIMIT 0") or a negative offset.
func normalizePagination(limit, offset int) (int, int) {
	switch {
	case limit <= 0:
		limit = DefaultLimit
	case limit > MaxLimit:
		limit = MaxLimit
	}

	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

// SetStatus activates or deactivates an account. The administrator guards only
// apply to admin targets: nobody may deactivate their own admin account, and
// the last active admin cannot be deactivated because that would leave the
// application without a privileged account. Tokens are revoked only on an
// active -> inactive transition, so reactivating an account does not disturb
// sessions that are still valid.
func (uc *userUseCase) SetStatus(ctx context.Context, input dto.SetUserStatusInput) (*dto.SetUserStatusOutput, error) {
	target, err := uc.repo.FindByID(ctx, input.ID)
	if err != nil {
		return nil, err
	}

	isAdmin, err := uc.repo.IsAdmin(ctx, input.ID)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		if input.ID == input.ActorID && !input.IsActive {
			return nil, domainerr.ErrAdminSelfDeactivate
		}

		if !input.IsActive && target.IsActive {
			activeAdmins, err := uc.repo.CountActiveAdmins(ctx)
			if err != nil {
				return nil, err
			}

			if activeAdmins <= 1 {
				return nil, domainerr.ErrCannotDeactivateLastAdmin
			}
		}
	}

	if err := uc.repo.SetStatus(ctx, input.ID, input.IsActive); err != nil {
		return nil, err
	}

	if !input.IsActive && target.IsActive {
		if err := uc.revokeAllUserTokens(ctx, input.ID); err != nil {
			return nil, err
		}
	}

	return &dto.SetUserStatusOutput{
		ID:       input.ID,
		IsActive: input.IsActive,
	}, nil
}

// generateTempPassword produces a URL-safe temporary password from 12 random
// bytes. The entropy comes from crypto/rand, so the result cannot be predicted
// from previous resets.
func generateTempPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ResetPassword replaces the password with a temporary one and returns the
// plaintext exactly once, so an administrator can hand it to the user. Only the
// hash is stored, and a successful reset revokes every existing token because
// the previous password can no longer be trusted.
func (uc *userUseCase) ResetPassword(ctx context.Context, input dto.ResetPasswordInput) (*dto.ResetPasswordOutput, error) {
	tempPass, err := generateTempPassword()
	if err != nil {
		return nil, err
	}

	hash, err := uc.hasher.Hash(tempPass)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(tempPasswordTTL)
	if err := uc.repo.SetTempPassword(ctx, input.TargetID, hash, expiresAt); err != nil {
		return nil, err
	}

	if err := uc.revokeAllUserTokens(ctx, input.TargetID); err != nil {
		return nil, err
	}

	return &dto.ResetPasswordOutput{
		TemporaryPassword: tempPass,
	}, nil
}

// AssignRole attaches a role to a user. The target is resolved before the role
// so a missing user takes precedence over a missing role in the error returned
// to the caller. HasRole keeps a repeated assignment from becoming a silent
// success, which lets the HTTP layer answer 409.
func (uc *userUseCase) AssignRole(ctx context.Context, input dto.AssignRoleInput) error {
	if _, err := uc.repo.FindByID(ctx, input.TargetID); err != nil {
		return err
	}

	role, err := uc.repo.FindRoleByID(ctx, input.RoleID)
	if err != nil {
		return err
	}

	has, err := uc.repo.HasRole(ctx, input.TargetID, role.ID)
	if err != nil {
		return err
	}

	if has {
		return domainerr.ErrRoleAlreadyAssigned
	}

	return uc.repo.AssignRole(ctx, input.TargetID, role.ID)
}

// RemoveRole detaches a role from a user. Removing admin is guarded only for an
// active admin: an inactive admin cannot exercise permissions, so stripping the
// role from it cannot lock the application out.
func (uc *userUseCase) RemoveRole(ctx context.Context, input dto.RemoveRoleInput) error {
	target, err := uc.repo.FindByID(ctx, input.TargetID)
	if err != nil {
		return err
	}

	role, err := uc.repo.FindRoleByID(ctx, input.RoleID)
	if err != nil {
		return err
	}

	if role.Name == "admin" {
		isAdmin, err := uc.repo.IsAdmin(ctx, input.TargetID)
		if err != nil {
			return err
		}

		if isAdmin && target.IsActive {
			activeAdmins, err := uc.repo.CountActiveAdmins(ctx)
			if err != nil {
				return err
			}

			if activeAdmins <= 1 {
				return domainerr.ErrCannotRemoveLastAdmin
			}
		}
	}

	return uc.repo.RemoveRole(ctx, input.TargetID, role.ID)
}
