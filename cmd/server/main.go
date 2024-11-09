package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	_ "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	pb "github.com/grpc-vtb/api/proto/gen"
	userPb "github.com/grpc-vtb/internal/user/proto"
	"github.com/grpc-vtb/pkg/cert"
)


type server struct {
	pb.UnimplementedUserServiceServer
	userClient userPb.UserServiceClient
}


func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
    // Пересылаем запрос на другой сервер
    tokenResponse, err := s.userClient.CreateUser(ctx, &userPb.CreateUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("error with reg user in auth-service: %w", err)
	}

	var userID int64 = 1

	return &pb.CreateUserResponse{
		Id:          userID,
		AccessToken: tokenResponse.AccessToken,
		ExpiresIn:   tokenResponse.ExpiresIn,
	}, nil
}

func (s *server) LoginUser(ctx context.Context, req *pb.UserLoginRequest) (*pb.UserLoginResponse, error) {
    tokenResponse, err := s.userClient.LoginUser(ctx, &userPb.UserLoginRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("error auth: %w", err)
	}

	return &pb.UserLoginResponse{
		AccessToken: tokenResponse.AccessToken,
		ExpiresIn:   tokenResponse.ExpiresIn,
	}, nil
}

func (s *server) ValidateUser(ctx context.Context, req *pb.TokenRequest) (*pb.RoleResponse, error) {
    roleResponse, err := s.userClient.ValidateUser(ctx, &userPb.TokenRequest{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("error with validate token: %w", err)
	}

	return &pb.RoleResponse{
		Role: roleResponse.Role,
	}, nil
}


const (
	serverCertFile = "./cert/gatewayService/certFile.pem"
	serverKeyFile  = "./cert/gatewayService/keyFile.pem"
	CACertFile     = "./cert/ca-cert.pem"
	CACertKey      = "./cert/ca-key.pem"
	secretKey      = "key"
)

func main() {
	tlsEnabled := flag.Bool("tls", false, "Enable TLS (default: false)")
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



	userConn, err := grpc.Dial("localhost:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
	    logger.Logger.Fatal("did not connect", zap.Error(err))
	}
	defer userConn.Close()
	userClient := userPb.NewUserServiceClient(userConn)

	if *tlsEnabled {
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}


	srv := grpc.NewServer(serverOpts...)
	//pb.RegisterQuoteServiceServer(srv, &server{})
	pb.RegisterUserServiceServer(srv, &server{userClient: userClient,})

	reflection.Register(srv)

	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		logger.Logger.Fatal("failed to listen", zap.Error(err))
	}

	logger.Logger.Info("Starting gRPC server on port :50051... (TLS enabled:", zap.Bool("tlsEnabled", *tlsEnabled))
	if err := srv.Serve(listener); err != nil {
		logger.Logger.Fatal("failed to serve", zap.Error(err))
	}
}
