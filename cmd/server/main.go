package main

import (
	"context"
	"flag"
	"github.com/grpc-vtb/internal/auth/proto"
	"log"
	"net"
	_ "github.com/grpc-vtb/internal/Interceptors/jwtInterceptor"
	_ "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	pb "github.com/grpc-vtb/api/proto/gen"
	userPb "github.com/grpc-vtb/internal/user/proto"
	"github.com/grpc-vtb/pkg/cert"
)

// TODO: Вынести в конфиги

// const (
//     keycloakPublicKey = 'keycloakKey' TODO: Вынести в конфиги
// )

type server struct {
	pb.UnimplementedQuoteServiceServer
	authClient proto.AuthServiceClient
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
			log.Fatalf("error generating certificate: %s", err)
		}
		creds, err = cert.LoadServerTLSCredentials(serverCertFile, serverKeyFile)
		if err != nil {
			log.Fatalf("failed to load key pair: %v", err)
		}
	}

	serverOpts := []grpc.ServerOption{}

	// Вот эта вся конструкция должна будет норм работать когда будет имплементация с кейклоком

	//Здесь создайте gRPC клиентов для AuthService и UserService
	// authConn, err := grpc.Dial("localhost:50052", grpc.WithTransportCredentials(insecure.NewCredentials()))
	// if err != nil {
	//     log.Fatalf("did not connect: %v", err)
	// }
	// defer authConn.Close()
	// authClient := authPb.NewAuthServiceClient(authConn)

	// А вот эту я пока не трогала

	// userConn, err := grpc.Dial("localhost:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
	// if err != nil {
	//     log.Fatalf("did not connect: %v", err)
	// }
	// defer userConn.Close()
	// userClient := user.NewUserServiceClient(userConn)

	if *tlsEnabled {
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}

	//Это будет иметь смысл когда появятся коннекты с модулями проверки токенов

	// serverOpts = append(serverOpts, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
	//     jwtInterceptor.JWTInterceptor(authClient),
	// )))

	srv := grpc.NewServer(serverOpts...)

	pb.RegisterQuoteServiceServer(srv, &server{})
	// gateway.RegisterGatewayServiceServer(srv, &server{            //Это будет иметь смысл когда появятся коннекты с модулями
	//     authClient: authClient,
	//     userClient: userClient,
	// })

	reflection.Register(srv)

	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("Starting gRPC server on port :50051... (TLS enabled:", *tlsEnabled, ")")
	if err := srv.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
