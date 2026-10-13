package dto

import "time"

type CreateUserInput struct {
	Name     string
	Username string
	Email    string
	Password string
}

type CreateUserOutput struct {
	ID       uint64
	Name     string
	Username string
	Email    string
}

type FindUserByIDInput struct {
	ID uint64
}

type FindUserByIDOutput struct {
	ID        uint64
	Name      string
	Username  string
	Email     string
	IsAdmin   bool
	IsActive  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type FindAllUsersInput struct {
	Limit  int
	Offset int
}

type UserOutput struct {
	ID        uint64
	Name      string
	Username  string
	Email     string
	IsAdmin   bool
	IsActive  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type FindAllUsersOutput struct {
	Users []*UserOutput
}

type UpdateUserInput struct {
	ID       uint64
	Name     string
	Username string
	Email    string
}

type UpdateUserOutput struct {
	ID        uint64
	Name      string
	Username  string
	Email     string
	UpdatedAt time.Time
}

type DeleteUserInput struct {
	ID uint64
}
