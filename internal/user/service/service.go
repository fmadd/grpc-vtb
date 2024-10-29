package service

import (
	"context"
	"github.com/grpc-vtb/internal/repository/models"
)

type UserService interface {
	CreateUser(ctx context.Context, user models.User) (int64, error)
	GetUserByID(ctx context.Context, userID int64) (*models.User, error)
	UpdateUser(ctx context.Context, user models.User) error
	DeleteUser(ctx context.Context, userID int64) error
	AuthenticateUser(ctx context.Context, username, password string) (string, error)
}
