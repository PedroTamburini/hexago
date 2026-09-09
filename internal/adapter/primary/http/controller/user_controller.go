package controller

import (
	"context"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/response"
	"github.com/PedroTamburini/hexago/internal/domain/dto"
	"github.com/PedroTamburini/hexago/internal/domain/port"
)

type UserController struct {
	usecase port.UserUseCase
}

func NewUserController(usecase port.UserUseCase) *UserController {
	return &UserController{usecase: usecase}
}

func (c *UserController) Create(ctx context.Context, body request.CreateUserBodyRequest) (*response.CreateUserResponse, error) {
	input := dto.CreateUserInput{
		Name:     body.Name,
		Username: body.Username,
		Email:    body.Email,
		Password: body.Password,
	}

	output, err := c.usecase.Create(ctx, input)
	if err != nil {
		return nil, err
	}

	return &response.CreateUserResponse{
		ID:       output.ID,
		Name:     output.Name,
		Username: output.Username,
		Email:    output.Email,
	}, nil
}

func (c *UserController) FindByID(ctx context.Context, uri request.FindUserByIDUriRequest) (*response.FindUserByIDResponse, error) {
	input := dto.FindUserByIDInput{ID: uri.ID}

	output, err := c.usecase.FindByID(ctx, input)
	if err != nil {
		return nil, err
	}

	return &response.FindUserByIDResponse{
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

func (c *UserController) FindAll(ctx context.Context, query request.FindAllUsersQuery) (*response.FindAllUsersResponse, error) {
	input := dto.FindAllUsersInput{
		Limit:  query.Limit,
		Offset: query.Offset,
	}

	output, err := c.usecase.FindAll(ctx, input)
	if err != nil {
		return nil, err
	}

	users := make([]*response.UserResponse, len(output.Users))
	for i, user := range output.Users {
		users[i] = &response.UserResponse{
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

	return &response.FindAllUsersResponse{
		Users: users,
	}, nil
}

func (c *UserController) Update(ctx context.Context, uri request.UpdateUserUriRequest, body request.UpdateUserBodyRequest) (*response.UpdateUserResponse, error) {
	input := dto.UpdateUserInput{
		ID:       uri.ID,
		Name:     body.Name,
		Username: body.Username,
		Email:    body.Email,
	}

	output, err := c.usecase.Update(ctx, input)
	if err != nil {
		return nil, err
	}

	return &response.UpdateUserResponse{
		ID:        output.ID,
		Name:      output.Name,
		Username:  output.Username,
		Email:     output.Email,
		UpdatedAt: output.UpdatedAt,
	}, nil
}

func (c *UserController) Delete(ctx context.Context, uri request.DeleteUserUriRequest) error {
	input := dto.DeleteUserInput{ID: uri.ID}

	err := c.usecase.Delete(ctx, input)
	if err != nil {
		return err
	}

	return nil
}
