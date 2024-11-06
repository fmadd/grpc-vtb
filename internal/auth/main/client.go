package auth

import (
	"context"
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
	"time"

	"google.golang.org/grpc"
)

func startClient() {
	conn, err := grpc.Dial("localhost:8081", grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(5*time.Second))
	if err != nil {
		logger.Logger.Fatal("Did not connect", zap.Error(err))
	}
	defer conn.Close()

	client := proto.NewAuthServiceClient(conn)

	// Вызов метода RegisterUser
	resp, err := client.RegisterUser(context.Background(), &proto.RegisterUserRequest{
		Username: "pudge",
		Email:    "test123@example.com",
		Password: "securepassword",
	})
	if err != nil {
		logger.Logger.Fatal("Failed to register user", zap.Error(err))
	}

	logger.Logger.Info("Registration successful", zap.String("AccessToken", resp.AccessToken), zap.Int64("ExpiresIn", resp.ExpiresIn))

	// Логин для получения текущего токена доступа и токена обновления
	loginResp, err := client.Login(context.Background(), &proto.UserAuth{
		Username: "pudge",
		Password: "securepassword",
	})
	if err != nil {
		logger.Logger.Fatal("Failed to login user", zap.Error(err))
	}
	logger.Logger.Info("Current Access Token", zap.String("AccessToken", loginResp.AccessToken))
	logger.Logger.Info("Refresh Token", zap.String("RefreshToken", loginResp.RefreshToken))

	// Проверка текущего токена с помощью метода ValidateToken
	validateResp, err := client.ValidateToken(context.Background(), &proto.TokenRequest{
		AccessToken: loginResp.AccessToken,
	})
	if err != nil {
		logger.Logger.Fatal("Failed to validate token", zap.Error(err))
	} else {
		logger.Logger.Info("Role", zap.String("Role", validateResp.Role))
	}

	// Вызов метода RefreshToken для обновления токена
	refreshResp, err := client.RefreshToken(context.Background(), &proto.RefreshTokenRequest{
		RefreshToken: loginResp.RefreshToken, // Здесь используем текущий токен обновления
	})
	if err != nil {
		logger.Logger.Fatal("Failed to refresh token", zap.Error(err))
	}
	logger.Logger.Info("New Access Token", zap.String("AccessToken", refreshResp.AccessToken), zap.Int64("ExpiresIn", refreshResp.ExpiresIn))

	// Проверка нового токена после обновления
	newValidateResp, err := client.ValidateToken(context.Background(), &proto.TokenRequest{
		AccessToken: refreshResp.AccessToken,
	})
	if err != nil {
		logger.Logger.Fatal("Failed to validate new token", zap.Error(err))
	} else {
		logger.Logger.Info("Role after refresh", zap.String("Role", newValidateResp.Role))
	}
}
