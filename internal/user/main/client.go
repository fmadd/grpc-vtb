package main

import (
	"context"
	"fmt"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
)

func main() {
	conn, err := grpc.Dial("localhost:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Не удалось подключиться к User-серверу: %v", err)
	}
	defer conn.Close()

	client := userProto.NewUserServiceClient(conn)

	registerResponse, err := client.CreateUser(context.Background(), &userProto.CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		log.Fatalf("Ошибка при регистрации: %v", err)
	}
	fmt.Printf("Register response: %v\n", registerResponse)

	// Тестирование Login
	loginResponse, err := client.LoginUser(context.Background(), &userProto.UserLoginRequest{
		Username: "testuser",
		Password: "password123",
	})
	if err != nil {
		log.Fatalf("Ошибка при входе: %v", err)
	}
	fmt.Printf("Login response: %v\n", loginResponse)

	// Тестирование ValidateToken
	validateResponse, err := client.ValidateUser(context.Background(), &userProto.TokenRequest{
		AccessToken: loginResponse.AccessToken,
	})
	if err != nil {
		log.Fatalf("Ошибка при проверке токена: %v", err)
	}
	fmt.Printf("ValidateToken response: %v\n", validateResponse)
}
