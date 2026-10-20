package usecase

import (
	"context"

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
)

type userUseCase struct {
	repo   portout.UserRepository
	hasher portout.PasswordHasher
}

func NewUserUseCase(repo portout.UserRepository, hasher portout.PasswordHasher) portin.UserUseCase {
	return &userUseCase{
		repo:   repo,
		hasher: hasher,
	}
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
