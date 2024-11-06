package auth

import (
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
	"net"

	"github.com/Nerzal/gocloak/v13"
	"github.com/grpc-vtb/internal/auth/handler"
	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", ":8081")
	if err != nil {
		logger.Logger.Fatal("Failed to listen", zap.Error(err))
	}

	client := gocloak.NewClient("http://localhost:8080")
	authService := handler.NewAuthHandler(client, "realm", "clientid", "clientsecret")

	grpcServer := grpc.NewServer()
	proto.RegisterAuthServiceServer(grpcServer, authService)

	logger.Logger.Info("Starting auth server on :8081...")
	if err := grpcServer.Serve(lis); err != nil {
		logger.Logger.Fatal("Failed to serve", zap.Error(err))
	}
}
