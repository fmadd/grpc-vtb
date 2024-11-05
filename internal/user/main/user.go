package user

import (
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/user/handler"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"net"
)

func main() {
	// Подключаемся к auth gRPC-серверу
	authConn, err := grpc.Dial("localhost:8081", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Не удалось подключиться к auth-серверу: %v", err)
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
		log.Fatalf("Не удалось начать прослушивание: %v", err)
	}

	log.Println("Запуск User gRPC сервера на порту 50051...")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("Не удалось запустить сервер: %v", err)
	}
}
