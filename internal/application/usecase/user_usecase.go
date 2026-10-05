package usecase

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	"github.com/PedroTamburini/hexago/internal/domain/entity"
	"github.com/PedroTamburini/hexago/internal/domain/port"
)

const (
	// DefaultLimit is applied when the caller does not provide a limit, so an
	// omitted value never reaches the repository as a zero limit.
	DefaultLimit = 20
	// MaxLimit is the hard cap of records returned by a single page.
	MaxLimit = 100
)

type userUseCase struct {
	repo   port.UserRepository
	hasher port.PasswordHasher
}

func NewUserUseCase(repo port.UserRepository, hasher port.PasswordHasher) port.UserUseCase {
	return &userUseCase{
		repo:   repo,
		hasher: hasher,
	}
}

func (uc *userUseCase) Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error) {
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
		IsAdmin:   user.IsAdmin,
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
			IsAdmin:   user.IsAdmin,
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

func (uc *userUseCase) Delete(ctx context.Context, input dto.DeleteUserInput) error {
	err := uc.repo.Delete(ctx, input.ID)
	if err != nil {
		return err
	}

	return nil
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
