package main

import (
	"flag"
	"github.com/grpc-vtb/internal/auth/proto"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/internal/user/handler"
	userProto "github.com/grpc-vtb/internal/user/proto"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"net"
)

const (
	serverCertFile = "./cert/user/certFile.pem"
	serverKeyFile  = "./cert/user/keyFile.pem"
	CACertFile     = "./cert/ca-cert.pem"
	CACertKey      = "./cert/ca-key.pem"
	secretKey      = "key"
)

func main() {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()

	var creds credentials.TransportCredentials
	var err error

	if *tlsEnabled {
		err = cert.GenerateCertificate(serverCertFile, serverKeyFile)
		if err != nil {
			logger.Logger.Fatal("error generating certificate", zap.Error(err))
		}
		creds, err = cert.LoadServerTLSCredentials(serverCertFile, serverKeyFile)
		if err != nil {
			logger.Logger.Fatal("failed to load key pair", zap.Error(err))
		}
	}

	serverOpts := []grpc.ServerOption{}

	authConn, err := grpc.NewClient("dns:///localhost:8081", grpc.WithTransportCredentials(creds))
	if err != nil {
		logger.Logger.Fatal("did not connect", zap.Error(err))
	}
	defer authConn.Close()

	authClient := proto.NewAuthServiceClient(authConn)

	if *tlsEnabled {
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}
	userHandler := &handler.UserHandler{
		AuthClient: authClient,
	}

	srv := grpc.NewServer(serverOpts...)
	userProto.RegisterUserServiceServer(srv, userHandler)

	reflection.Register(srv)

	listener, err := net.Listen("tcp", ":50053")
	if err != nil {
		logger.Logger.Fatal("failed to listen", zap.Error(err))
	}

	logger.Logger.Info("Starting user server on port :50053... (TLS enabled:", zap.Bool("tlsEnabled", *tlsEnabled))
	if err := srv.Serve(listener); err != nil {
		logger.Logger.Fatal("failed to serve", zap.Error(err))
	}
}
