package user

import (
	"context"
	"fmt"
	"github.com/grpc-vtb/internal/logger"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startClient() {
	conn, err := grpc.Dial("localhost:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Logger.Fatal("Failed to connect to the User server", zap.Error(err))
	}
	defer conn.Close()

	client := userProto.NewUserServiceClient(conn)

	registerResponse, err := client.CreateUser(context.Background(), &userProto.CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		logger.Logger.Fatal("Registration error", zap.Error(err))
	}
	fmt.Printf("Register response: %v\n", registerResponse)

	// Тестирование Login
	loginResponse, err := client.LoginUser(context.Background(), &userProto.UserLoginRequest{
		Username: "testuser",
		Password: "password123",
	})
	if err != nil {
		logger.Logger.Fatal("Login error", zap.Error(err))
	}
	fmt.Printf("Login response: %v\n", loginResponse)

	// Тестирование ValidateToken
	validateResponse, err := client.ValidateUser(context.Background(), &userProto.TokenRequest{
		AccessToken: loginResponse.AccessToken,
	})
	if err != nil {
		logger.Logger.Fatal("Error checking the token", zap.Error(err))
	}
	fmt.Printf("ValidateToken response: %v\n", validateResponse)
}
