package main

import (
	"context"
	"github.com/grpc-vtb/internal/auth/proto"
	"log"
	"time"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:8081", grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(5*time.Second))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
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
		log.Fatalf("Failed to register user: %v", err)
	}

	log.Printf("Registration successful: AccessToken=%s, ExpiresIn=%d", resp.AccessToken, resp.ExpiresIn)

	// Логин для получения текущего токена доступа и токена обновления
	loginResp, err := client.Login(context.Background(), &proto.UserAuth{
		Username: "pudge",
		Password: "securepassword",
	})
	if err != nil {
		log.Fatalf("Failed to login user: %v", err)
	}
	log.Printf("Current Access Token: %s", loginResp.AccessToken)
	log.Printf("Refresh Token: %s", loginResp.RefreshToken)

	// Проверка текущего токена с помощью метода ValidateToken
	validateResp, err := client.ValidateToken(context.Background(), &proto.TokenRequest{
		AccessToken: loginResp.AccessToken,
	})
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	} else {
		log.Printf("Role: %v", validateResp.Role)

	}

	// Вызов метода RefreshToken для обновления токена
	refreshResp, err := client.RefreshToken(context.Background(), &proto.RefreshTokenRequest{
		RefreshToken: loginResp.RefreshToken, // Здесь используем текущий токен обновления
	})
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	log.Printf("New Access Token: %s, Expires In: %d", refreshResp.AccessToken, refreshResp.ExpiresIn)

	// Проверка нового токена после обновления
	newValidateResp, err := client.ValidateToken(context.Background(), &proto.TokenRequest{
		AccessToken: refreshResp.AccessToken,
	})
	if err != nil {
		log.Fatalf("Failed to validate new token: %v", err)
	} else {
		log.Printf("Role after refresh: %v", newValidateResp.Role)
	}
}
