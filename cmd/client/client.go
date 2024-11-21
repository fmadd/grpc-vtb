package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	pb "github.com/grpc-vtb/api/proto/gen"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	clientCertFile = "./cert/client/certFile.pem"
	clientKeyFile  = "./cert/client/keyFile.pem"
)

func main() {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()

	var creds credentials.TransportCredentials
	var err error

	if *tlsEnabled {
		err = cert.GenerateCertificate(clientCertFile, clientKeyFile, "localhost")
		if err != nil {
			logger.Logger.Fatal("error generating certificate", zap.Error(err))
		}
		creds, err = cert.LoadClientTLSCredentials(clientCertFile, clientKeyFile)
		if err != nil {
			logger.Logger.Fatal("failed to create TLS credentials", zap.Error(err))
		}
	}

	var conn *grpc.ClientConn
	if *tlsEnabled {
		conn, err = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	} else {
		conn, err = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if err != nil {
		logger.Logger.Fatal("did not connect", zap.Error(err))
	}
	defer conn.Close()

	client := pb.NewUserServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	createUserRequest := &pb.CreateUserRequest{
		Username: "testuser",
		Email:    "testuser@example.com",
		Password: "securepassword",
	}
	createUserResponse, err := client.CreateUser(ctx, createUserRequest)
	if err != nil {
		logger.Logger.Fatal("Ошибка при создании пользователя", zap.Error(err))
	}
	logger.Logger.Info("Пользователь успешно создан",
		zap.Int64("ID", createUserResponse.Id),
		zap.String("AccessToken", createUserResponse.AccessToken),
		zap.Int64("ExpiresIn", createUserResponse.ExpiresIn),
	)

	loginUserRequest := &pb.UserLoginRequest{
		Username: "testuser",
		Password: "securepassword",
	}
	loginUserResponse, err := client.LoginUser(ctx, loginUserRequest)
	if err != nil {
		logger.Logger.Fatal("Ошибка при авторизации пользователя", zap.Error(err))
	}
	logger.Logger.Info("Пользователь успешно авторизован",
		zap.String("AccessToken", loginUserResponse.AccessToken),
		zap.Int64("ExpiresIn", loginUserResponse.ExpiresIn),
		zap.String("RefreshToken", loginUserResponse.RefreshToken),
	)

	RefreshUserRequest := &pb.RefreshGrpcTokenRequest{
		RefreshToken: loginUserResponse.RefreshToken,
	}
	RefreshUserResponse, err := client.RefreshGrpcToken(ctx, RefreshUserRequest)

	if err != nil {
		logger.Logger.Fatal("Ошибка при обновлении токена", zap.Error(err))
	} else {
		logger.Logger.Info("Токен успешно обновлён:",
			zap.String("AccessToken", RefreshUserResponse.AccessToken),
			zap.Int64("ExpiresIn", RefreshUserResponse.ExpiresIn),
			zap.String("RefreshToken", loginUserResponse.RefreshToken),
		)
	}

	TokenRequest := &pb.TokenRequest{
		AccessToken: RefreshUserResponse.AccessToken,
	}
	role, err := client.ValidateUser(ctx, TokenRequest)

	if err != nil {
		logger.Logger.Fatal("Ошибка проверке токена", zap.String("AccessToken: ", RefreshUserResponse.AccessToken), zap.Error(err))
	} else {
		logger.Logger.Info("Токен успешно прошел проверку:",
			zap.String("AccessToken: ", RefreshUserResponse.AccessToken),
			zap.String("Role:", role.Role),
		)
	}

	TokenRequest = &pb.TokenRequest{
		AccessToken: loginUserResponse.AccessToken,
	}
	role, err = client.ValidateUser(ctx, TokenRequest)

	if err != nil {
		logger.Logger.Info("Ошибка проверке токена", zap.String("AccessToken: ", loginUserResponse.AccessToken), zap.Error(err))

	} else {
		logger.Logger.Info("Токен успешно прошел проверку:",
			zap.String("AccessToken: ", loginUserResponse.AccessToken),
			zap.String("Role:", role.Role),
		)
	}

	delay := 1 * time.Second
	logger.Logger.Info(fmt.Sprintf("Ожидание %v до начала теста на анти-DDoS...", delay))
	time.Sleep(delay)

	numRequests := 100
	interval := 10 * time.Millisecond

	startTime := time.Now()

	for i := 0; i < numRequests; i++ {
		loginUserResponse, err := client.LoginUser(ctx, loginUserRequest)
		if err != nil {
			logger.Logger.Info("Ошибка при авторизации пользователя", zap.Error(err))
		} else {
			logger.Logger.Info("Пользователь успешно авторизован",
				zap.String("AccessToken", loginUserResponse.AccessToken),
				zap.Int64("ExpiresIn", loginUserResponse.ExpiresIn),
				zap.String("RefreshToken", loginUserResponse.RefreshToken),
			)
		}

		if i%100 == 0 && i != 0 {
			logger.Logger.Info(fmt.Sprintf("Отправлено %d запросов", i))
		}
		time.Sleep(interval)
	}

	elapsedTime := time.Since(startTime)
	logger.Logger.Info(fmt.Sprintf("Отправлено %d запросов за %v", numRequests, elapsedTime))

}
