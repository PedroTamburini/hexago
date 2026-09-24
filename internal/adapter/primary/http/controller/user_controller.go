package controller

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/domain/dto"
	"github.com/PedroTamburini/hexago/internal/domain/port"
)

type UserController struct {
	usecase port.UserUseCase
}

func NewUserController(usecase port.UserUseCase) *UserController {
	return &UserController{usecase: usecase}
}

func (c *UserController) Create(ctx context.Context, input dto.CreateUserInput) (*dto.CreateUserOutput, error) {
	output, err := c.usecase.Create(ctx, input)
	if err != nil {
		return nil, err
	}

	return &dto.CreateUserOutput{
		ID:       output.ID,
		Name:     output.Name,
		Username: output.Username,
		Email:    output.Email,
	}, nil
}

func (c *UserController) FindByID(ctx context.Context, input dto.FindUserByIDInput) (*dto.FindUserByIDOutput, error) {
	output, err := c.usecase.FindByID(ctx, input)
	if err != nil {
		return nil, err
	}

	return &dto.FindUserByIDOutput{
		ID:        output.ID,
		Name:      output.Name,
		Username:  output.Username,
		Email:     output.Email,
		IsAdmin:   output.IsAdmin,
		IsActive:  output.IsActive,
		CreatedAt: output.CreatedAt,
		UpdatedAt: output.UpdatedAt,
	}, nil
}

func (c *UserController) FindAll(ctx context.Context, input dto.FindAllUsersInput) (*dto.FindAllUsersOutput, error) {
	output, err := c.usecase.FindAll(ctx, input)
	if err != nil {
		return nil, err
	}

	users := make([]*dto.UserOutput, len(output.Users))
	for i, user := range output.Users {
		users[i] = &dto.UserOutput{
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
		Users: users,
	}, nil
}

func (c *UserController) Update(ctx context.Context, input dto.UpdateUserInput) (*dto.UpdateUserOutput, error) {
	output, err := c.usecase.Update(ctx, input)
	if err != nil {
		return nil, err
	}

	return &dto.UpdateUserOutput{
		ID:        output.ID,
		Name:      output.Name,
		Username:  output.Username,
		Email:     output.Email,
		UpdatedAt: output.UpdatedAt,
	}, nil
}

func (c *UserController) Delete(ctx context.Context, input dto.DeleteUserInput) error {
	err := c.usecase.Delete(ctx, input)
	if err != nil {
		return err
	}

	return nil
}
