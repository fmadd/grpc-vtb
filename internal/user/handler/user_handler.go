package handler

import (
	"context"
	"fmt"
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"go.uber.org/zap"
)

type UserHandler struct {
	AuthClient proto.AuthServiceClient
	userProto.UnimplementedUserServiceServer
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
		AccessToken:  tokenResponse.AccessToken,
		ExpiresIn:    tokenResponse.ExpiresIn,
		RefreshToken: tokenResponse.RefreshToken,
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

func (h *UserHandler) RefreshUserToken(ctx context.Context, req *userProto.RefreshUserTokenRequest) (*userProto.RefreshUserTokenResponse, error) {
	token, err := h.AuthClient.RefreshToken(ctx, &proto.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		logger.Logger.Error("Error refreshing token:", zap.Error(err))
		return nil, fmt.Errorf("failed to refresh token: %v clientToken: %s", err, req.RefreshToken)
	}

	return &userProto.RefreshUserTokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(token.ExpiresIn),
	}, nil
}
