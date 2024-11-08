package auth

import (
	"github.com/Nerzal/gocloak/v13"
	"github.com/grpc-vtb/internal/auth/handler"
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

const (
	serverCertFile = "./cert/server/server-cert.pem"
	serverKeyFile  = "./cert/server/server-key.pem"
)

func main() {
	// Настройка прослушивания порта
	lis, err := net.Listen("tcp", ":8081")
	if err != nil {
		logger.Logger.Fatal("Couldn't start listening", zap.Error(err))
	}

	// Загрузка серверных TLS-учетных данных
	serverCreds, err := cert.LoadServerTLSCredentials(serverCertFile, serverKeyFile)
	if err != nil {
		logger.Logger.Fatal("Failed to load TLS server credits", zap.Error(err))
	}

	// Инициализация клиента Keycloak для AuthHandler
	client := gocloak.NewClient("http://localhost:8080")
	authService := handler.NewAuthHandler(client, "realm", "clientid", "clientsecret")

	// Создание gRPC-сервера с использованием серверных учетных данных для TLS
	grpcServer := grpc.NewServer(grpc.Creds(serverCreds))

	// Регистрация AuthService на gRPC-сервере
	proto.RegisterAuthServiceServer(grpcServer, authService)

	logger.Logger.Info("Running an auth server with TLS on port :8081...")
	if err := grpcServer.Serve(lis); err != nil {
		logger.Logger.Fatal("The server could not be started", zap.Error(err))
	}
}
