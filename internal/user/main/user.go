package user

import (
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/internal/user/handler"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
)

func main() {
	// Подключаемся к auth gRPC-серверу
	authConn, err := grpc.Dial("localhost:8081", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Logger.Fatal("Failed to connect to the auth server", zap.Error(err))
	}
	defer authConn.Close()

	authClient := proto.NewAuthServiceClient(authConn)

	// Создаем gRPC сервер для UserHandler
	srv := grpc.NewServer()

	userHandler := &handler.UserHandler{
		AuthClient: authClient,
	}

	// Регистрируем UserService в gRPC сервере
	userProto.RegisterUserServiceServer(srv, userHandler)

	// Запускаем gRPC сервер
	lis, err := net.Listen("tcp", ":50053") // Порт для UserService
	if err != nil {
		logger.Logger.Fatal("Failed to start listening", zap.Error(err))
	}

	logger.Logger.Info("Starting the User gRPC server on port 50051...")
	if err := srv.Serve(lis); err != nil {
		logger.Logger.Fatal("The server could not be started", zap.Error(err))
	}
}
