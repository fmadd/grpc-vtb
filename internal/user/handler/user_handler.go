package handler

import (
	"context"
	"fmt"
	authProto "github.com/grpc-vtb/internal/auth/proto"
	userProto "github.com/grpc-vtb/internal/user/proto"
)

type UserHandler struct {
	authClient authProto.AuthServiceClient
	userDB     UserDatabase
}

type UserDatabase interface {
	CreateUser(ctx context.Context, username, email string) (int64, error)
	GetUserByID(ctx context.Context, userID int64) (*userProto.User, error)
	UpdateUser(ctx context.Context, user *userProto.User) error
	DeleteUser(ctx context.Context, userID int64) error
}

func (h *UserHandler) Register(ctx context.Context, req *userProto.CreateUserRequest) (*userProto.CreateUserResponse, error) {
	if req.Password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	tokenResponse, err := h.authClient.RegisterUser(ctx, &authProto.RegisterUserRequest{
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

func (h *UserHandler) Login(ctx context.Context, req *userProto.UserLoginRequest) (*userProto.UserLoginResponse, error) {
	tokenResponse, err := h.authClient.Login(ctx, &authProto.UserAuth{
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

func (h *UserHandler) ValidateToken(ctx context.Context, req *userProto.TokenRequest) (*userProto.RoleResponse, error) {
	roleResponse, err := h.authClient.ValidateToken(ctx, &authProto.TokenRequest{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("error with validate token: %w", err)
	}

	return &userProto.RoleResponse{
		Role: roleResponse.Role,
	}, nil
}
