package service

import (
	"context"
	"github.com/grpc-vtb/internal/user/proto"
)

type UserService interface {
	CreateUser(ctx context.Context, req *proto.CreateUserRequest) (*proto.CreateUserResponse, error)
	GetUserByID(ctx context.Context, req *proto.GetUserByIDRequest) (*proto.GetUserByIDResponse, error)
	UpdateUser(ctx context.Context, req *proto.UpdateUserRequest) (*proto.UpdateUserResponse, error)
	DeleteUser(ctx context.Context, req proto.DeleteUserRequest) (proto.DeleteUserResponse, error)
}
