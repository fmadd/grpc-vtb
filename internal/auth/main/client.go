package main

import (
	"context"
	"log"
	"time"

	authProto "github.com/grpc-vtb/internal/auth/proto"
	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:8081", grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(5*time.Second))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	client := authProto.NewAuthServiceClient(conn)

	// Вызов метода RegisterUser
	resp, err := client.RegisterUser(context.Background(), &authProto.RegisterUserRequest{
		Username: "pudge",
		Email:    "test@example.com",
		Password: "securepassword",
	})
	if err != nil {
		log.Fatalf("Failed to register user: %v", err)
	}

	log.Printf("Registration successful: AccessToken=%s, ExpiresIn=%d", resp.AccessToken, resp.ExpiresIn)

	resp2, err := client.Login(context.Background(), &authProto.UserAuth{
		Username: "pudge",
		Email:    "test@example.com",
		Password: "securepassword",
	})
	if err != nil {
		log.Fatalf("Failed to login user: %v", err)
	} else {
		log.Printf("token: %v", resp2.AccessToken)
	}

	resp3, err := client.ValidateToken(context.Background(), &authProto.TokenRequest{
		AccessToken: resp2.AccessToken,
	})
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	} else {
		log.Fatalf("Role: %v", resp3.Role)
	}

}
