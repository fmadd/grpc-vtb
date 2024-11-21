package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net"

	 _"github.com/grpc-vtb/cmd/ratelimiter"

	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/proto"

	pb "github.com/grpc-vtb/api/proto/gen"
	userPb "github.com/grpc-vtb/internal/user/proto"
	"github.com/grpc-vtb/pkg/cert"
)

type server struct {
	pb.UnimplementedUserServiceServer
	userClient userPb.UserServiceClient
}

func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	ans := &userPb.CreateUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}
	
	tokenResponse, err := s.userClient.CreateUser(ctx, ans)
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
		AccessToken:  tokenResponse.AccessToken,
		ExpiresIn:    tokenResponse.ExpiresIn,
		RefreshToken: tokenResponse.RefreshToken,
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

func (s *server) RefreshGrpcToken(ctx context.Context, req *pb.RefreshGrpcTokenRequest) (*pb.RefreshGrpcTokenResponse, error) {
	token, err := s.userClient.RefreshUserToken(ctx, &userPb.RefreshUserTokenRequest{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		logger.Logger.Error("Error refreshing token:", zap.Error(err))
		return nil, fmt.Errorf("failed to refresh token: %v clientToken: %s", err, req.RefreshToken)
	}

	return &pb.RefreshGrpcTokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int64(token.ExpiresIn),
	}, nil
}

func main() {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()

	var serverCreds, creds credentials.TransportCredentials
	var err error
	err = cert.GenerateCACert("localhost")
	err = cert.GenerateCA("./cert/ca-cert.pem", "./cert/ca-key.pem")

	if err != nil {
		logger.Logger.Fatal("error generating ca certificate", zap.Error(err))
	}
	if *tlsEnabled {
		err = cert.GenerateCertificate(serverCertFile, serverKeyFile, "localhost")
		
		//err = cert.GenerateCSR("gatewayService", "localhost")

		if err != nil {
			logger.Logger.Fatal("!!error generating certificate", zap.Error(err))
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

	serverOpts := []grpc.ServerOption{grpc.UnaryInterceptor(SignatureValidationInterceptor)}
	if *tlsEnabled {
		serverOpts = append(serverOpts, grpc.Creds(serverCreds))
	}

	//serverOpts = append(serverOpts, grpc.UnaryInterceptor(ratelimiter.RateLimitInterceptor))

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


func SignatureValidationInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
	message, ok := req.(proto.Message) // Попробуем привести request к proto.Message
    if !ok {
        return nil, grpc.Errorf(codes.Internal, "request does not implement proto.Message")
    }
    // Извлекаем метаданные
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, grpc.Errorf(codes.Unauthenticated, "missing metadata")
    }

    signatureEncoded := md["signature"][0] // Получаем подпись из метаданных

    // Преобразуем запрос в байты (можно использовать любую сериализацию, которую вы используете)
    messageBytes, err := proto.Marshal(message) // Ваша логика сериализации
    if err != nil {
        return nil, grpc.Errorf(codes.Internal, "failed to marshal request")
    }
	//fmt.Println(messageBytes)
    signatureBytes, err := base64.StdEncoding.DecodeString(signatureEncoded)
    if err != nil {
        return nil, grpc.Errorf(codes.Unauthenticated, "invalid signature encoding")
    }
	//fmt.Println(signatureBytes)

   _ = signatureBytes
    isValid, err := cert.ValidateSign(messageBytes, []byte(signatureEncoded))
    if !isValid {
        return nil, grpc.Errorf(codes.Unauthenticated, "invalid signature")
    }

    // Вызовите следующий обработчик
    return handler(ctx, req)
}
