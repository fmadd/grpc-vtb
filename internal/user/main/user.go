package user

import (
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/internal/user/handler"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

const (
	clientCertFile = "./cert/client/certFile.pem"
	clientKeyFile  = "./cert/client/keyFile.pem"
	serverCertFile = "./cert/server/server-cert.pem"
	serverKeyFile  = "./cert/server/server-key.pem"
)

func main() {
	// Подключение к auth-серверу с клиентскими сертификатами
	clientCreds, err := cert.LoadClientTLSCredentials(clientCertFile, clientKeyFile)
	if err != nil {
		logger.Logger.Fatal("Client TLS cards could not be loaded to connect to the auto-server", zap.Error(err))
	}

	// Указываем префикс dns для URI
	authConn, err := grpc.NewClient("dns:///localhost:8081", grpc.WithTransportCredentials(clientCreds))
	if err != nil {
		logger.Logger.Fatal("Failed to connect to the auth server", zap.Error(err))
	}
	defer authConn.Close()

	authClient := proto.NewAuthServiceClient(authConn)

	// Создаем gRPC-сервер для UserHandler с серверными сертификатами
	serverCreds, err := cert.LoadServerTLSCredentials(serverCertFile, serverKeyFile)
	if err != nil {
		logger.Logger.Fatal("Failed to load TLS server credits for the user server", zap.Error(err))
	}

	srv := grpc.NewServer(grpc.Creds(serverCreds))

	userHandler := &handler.UserHandler{
		AuthClient: authClient,
	}

	// Регистрируем UserService в gRPC-сервере
	userProto.RegisterUserServiceServer(srv, userHandler)

	// Запуск gRPC-сервера с прослушиванием защищенного соединения
	lis, err := net.Listen("tcp", ":50053") // Порт для UserService
	if err != nil {
		logger.Logger.Fatal("Couldn't start listening", zap.Error(err))
	}

	logger.Logger.Info("Running a User gRPC server with TLS on port 50053...")
	if err := srv.Serve(lis); err != nil {
		logger.Logger.Fatal("The server cannot be started", zap.Error(err))
	}
}
