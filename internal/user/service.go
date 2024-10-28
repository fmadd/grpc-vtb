package user

import (
	"context"
)

type User struct {
	ID       int64
	Username string
	Email    string
}

type UserService interface {
	CreateUser(ctx context.Context, user User) (int64, error)
	GetUserByID(ctx context.Context, userID int64) (*User, error)
	UpdateUser(ctx context.Context, user User) error
	DeleteUser(ctx context.Context, userID int64) error
	AuthenticateUser(ctx context.Context, username, password string) (string, error)
}
