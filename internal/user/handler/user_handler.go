package handler

import (
	"context"
	"fmt"
	"github.com/grpc-vtb/internal/auth/proto"
	userProto "github.com/grpc-vtb/internal/user/proto"
)

type UserHandler struct {
	AuthClient proto.AuthServiceClient
	userProto.UnimplementedUserServiceServer
	//userDB     UserDatabase
}

type UserDatabase interface {
	CreateUser(ctx context.Context, username, email string) (int64, error)
	GetUserByID(ctx context.Context, userID int64) (*userProto.User, error)
	UpdateUser(ctx context.Context, user *userProto.User) error
	DeleteUser(ctx context.Context, userID int64) error
}

func (h *UserHandler) CreateUser(ctx context.Context, req *userProto.CreateUserRequest) (*userProto.CreateUserResponse, error) {
	if req.Password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	tokenResponse, err := h.AuthClient.RegisterUser(ctx, &proto.RegisterUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("error with reg user in auth-service: %w", err)
	}

	//userID, err := h.userDB.CreateUser(ctx, req.Username, req.Email)
	//if err != nil {
	//	return nil, fmt.Errorf("error with create user in db user model: %w", err)
	//}

	var userID int64 = 1

	return &userProto.CreateUserResponse{
		Id:          userID,
		AccessToken: tokenResponse.AccessToken,
		ExpiresIn:   tokenResponse.ExpiresIn,
	}, nil
}

func (h *UserHandler) LoginUser(ctx context.Context, req *userProto.UserLoginRequest) (*userProto.UserLoginResponse, error) {
	tokenResponse, err := h.AuthClient.Login(ctx, &proto.UserAuth{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("error auth: %w", err)
	}

	return &userProto.UserLoginResponse{
		AccessToken: tokenResponse.AccessToken,
		ExpiresIn:   tokenResponse.ExpiresIn,
	}, nil
}

func (h *UserHandler) ValidateUser(ctx context.Context, req *userProto.TokenRequest) (*userProto.RoleResponse, error) {
	roleResponse, err := h.AuthClient.ValidateToken(ctx, &proto.TokenRequest{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("error with validate token: %w", err)
	}

	return &userProto.RoleResponse{
		Role: roleResponse.Role,
	}, nil
}
