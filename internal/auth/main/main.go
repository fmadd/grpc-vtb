package main

import (
	"flag"
	"github.com/Nerzal/gocloak/v13"
	"github.com/grpc-vtb/internal/auth/handler"
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"net"
)

const (
	serverCertFile = "./cert/auth/certFile.pem"
	serverKeyFile  = "./cert/auth/keyFile.pem"
	keycloakURL    = "http://localhost:8080"
	realmName      = "master" // Имя вашего realm в Keycloak
)

func main() {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()

	var creds credentials.TransportCredentials
	var err error

	// Генерация сертификатов для TLS
	if *tlsEnabled {
		err = cert.GenerateCertificate(serverCertFile, serverKeyFile, "auth")
		if err != nil {
			logger.Logger.Fatal("error generating certificate", zap.Error(err))
		}
		creds, err = cert.NewServerTLS(serverCertFile, serverKeyFile)
		if err != nil {
			logger.Logger.Fatal("failed to load key pair", zap.Error(err))
		}
	}

	// Настройки для gRPC сервера
	serverOpts := []grpc.ServerOption{}
	if *tlsEnabled {
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}

	// Создаем новый gRPC сервер
	srv := grpc.NewServer(serverOpts...)

	// Создаем клиента для Keycloak
	client := gocloak.NewClient("http://host.docker.internal:8080")

	authService := handler.NewAuthHandler(client, "realm", "client", "secret")

	// Регистрируем сервисы
	proto.RegisterAuthServiceServer(srv, authService)
	reflection.Register(srv)

	// Настройка listener'а для сервера
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		logger.Logger.Fatal("failed to listen", zap.Error(err))
	}

	logger.Logger.Info("Starting user server on port :8081... (TLS enabled:", zap.Bool("tlsEnabled", *tlsEnabled))
	if err := srv.Serve(listener); err != nil {
		logger.Logger.Fatal("failed to server", zap.Error(err))
	}

}
