package main

import (
	"context"
	"flag"
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
	pb.UnimplementedQuoteServiceServer
	userClient userPb.UserServiceClient
}

// func (s *server) Authenticate(ctx context.Context, req *gateway.AuthRequest) (*gateway.AuthResponse, error) {
//     // Перенаправление запроса к AuthService
//     res, err := s.authClient.Login(ctx, &auth.LoginRequest{
//         Username: req.Username,
//         Password: req.Password,
//     })
//     if err != nil {
//         return nil, err
//     }
//     return &gateway.AuthResponse{Token: res.Token}, nil
// }

// func (s *server) FetchUser(ctx context.Context, req *gateway.UserRequest) (*gateway.UserResponse, error) {
//     // Перенаправление запроса к UserService
//     res, err := s.userClient.GetUser(ctx, &user.GetUserRequest{UserId: req.UserId})
//     if err != nil {
//         return nil, err
//     }
//     return &gateway.UserResponse{
//         Username: res.Username,
//         Email:    res.Email,
//     }, nil
// }

func (s *server) GetQuote(ctx context.Context, req *pb.QuoteRequest) (*pb.QuoteResponse, error) {
	quote := "Success! Example quote for category: " + req.Category
	return &pb.QuoteResponse{Quote: quote}, nil
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

	pb.RegisterQuoteServiceServer(srv, &server{})
	gateway.RegisterGatewayServiceServer(srv, &server{            //Это будет иметь смысл когда появятся коннекты с модулями
	    userClient: userClient,
	})

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
