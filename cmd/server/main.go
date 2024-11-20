package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/grpc-vtb/cmd/ratelimiter"
	"net"

	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
)

func main() {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()
	

	var serverCreds, creds credentials.TransportCredentials
	var err error
	err = cert.GenerateCACert("localhost")
	if err != nil {
		logger.Logger.Fatal("error generating ca certificate", zap.Error(err))
	}
	if *tlsEnabled {
		//err = cert.GenerateCertificate(serverCertFile, serverKeyFile, "localhost")

		err = cert.GenerateCSR("gatewayService", "localhost")

		if err != nil {
			logger.Logger.Fatal("!!error generating certificate", zap.Error(err))
		}

		err = cert.SignCert("gatewayService")
		if err != nil {
			logger.Logger.Fatal("error sign certificate", zap.Error(err))
		}

		serverCreds, err = cert.NewServerTLS(serverCertFile, serverKeyFile)
		if err != nil {
			logger.Logger.Fatal("!!failed to load key pair", zap.Error(err))
		}
	}

	creds, err = cert.NewClientTLS(serverCertFile, serverKeyFile)
	if err != nil {
		logger.Logger.Fatal("failed to load key pair", zap.Error(err))
	}
	userConn, err := grpc.Dial("user:50053", grpc.WithTransportCredentials(creds))
	if err != nil {
		logger.Logger.Fatal("did not connect", zap.Error(err))
	}
	defer userConn.Close()

	userClient := userPb.NewUserServiceClient(userConn)

	serverOpts := []grpc.ServerOption{}
	if *tlsEnabled {
		serverOpts = append(serverOpts, grpc.Creds(serverCreds))
	}

	serverOpts = append(serverOpts, grpc.UnaryInterceptor(ratelimiter.RateLimitInterceptor))

	srv := grpc.NewServer(serverOpts...)
	pb.RegisterUserServiceServer(srv, &server{userClient: userClient})

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
