package auth

import (
	"context"
	"github.com/grpc-vtb/internal/auth/proto"
)

type AuthService interface {
	Login(ctx context.Context, req *proto.UserAuth) (*proto.TokenResponse, error)
	ValidateToken(ctx context.Context, req *proto.TokenRequest) (*proto.RoleResponse, error)
}
