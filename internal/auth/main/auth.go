package main

import (
	"log"
	"net"

	"github.com/Nerzal/gocloak/v13"
	"github.com/grpc-vtb/internal/auth/handler"
	authProto "github.com/grpc-vtb/internal/auth/proto"
	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	client := gocloak.NewClient("http://localhost:8080")
	authService := handler.NewAuthHandler(client, "your_realm", "your_client_id", "your_client_secret")

	grpcServer := grpc.NewServer()
	authProto.RegisterAuthServiceServer(grpcServer, authService)

	log.Println("Starting auth server on :8081...")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
