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
	// ActorID is the authenticated user performing the deletion, so the use
	// case can enforce the rules that depend on who is asking (for instance,
	// an admin deleting their own account).
	ActorID uint64
}

type SetUserStatusInput struct {
	ID       uint64
	ActorID  uint64
	IsActive bool
}

type SetUserStatusOutput struct {
	ID       uint64
	IsActive bool
}

type ResetPasswordInput struct {
	TargetID uint64
}

type ResetPasswordOutput struct {
	// TemporaryPassword is returned as plaintext so an administrator can hand it
	// to the user; only its hash is persisted.
	TemporaryPassword string
}

type AssignRoleInput struct {
	TargetID uint64
	RoleID   uint64
}

type RemoveRoleInput struct {
	TargetID uint64
	RoleID   uint64
}
