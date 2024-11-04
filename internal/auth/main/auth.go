package main

import (
	"github.com/grpc-vtb/internal/auth/proto"
	"log"
	"net"

	"github.com/Nerzal/gocloak/v13"
	"github.com/grpc-vtb/internal/auth/handler"
	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	client := gocloak.NewClient("http://localhost:8080")
	authService := handler.NewAuthHandler(client, "realm", "clientid", "clientsecret")

	grpcServer := grpc.NewServer()
	proto.RegisterAuthServiceServer(grpcServer, authService)

	log.Println("Starting auth server on :8081...")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
