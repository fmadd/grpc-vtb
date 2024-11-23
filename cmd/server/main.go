package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/grpc-vtb/cmd/ratelimiter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"net/http"
	"time"

	pb "github.com/grpc-vtb/api/proto/gen"
	"github.com/grpc-vtb/internal/logger"
	userPb "github.com/grpc-vtb/internal/user/proto"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_server_requests_total",
			Help: "Total number of gRPC requests received.",
		},
		[]string{"method"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_server_request_duration_seconds",
			Help:    "Histogram of response times for gRPC requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(requestDuration)
}

type server struct {
	pb.UnimplementedUserServiceServer
	userClient userPb.UserServiceClient
}

func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	start := time.Now()
	requestsTotal.WithLabelValues("CreateUser").Inc()

	tokenResponse, err := s.userClient.CreateUser(ctx, &userPb.CreateUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})

	duration := time.Since(start).Seconds()
	requestDuration.WithLabelValues("CreateUser").Observe(duration)

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
	start := time.Now()
	requestsTotal.WithLabelValues("LoginUser").Inc()

	tokenResponse, err := s.userClient.LoginUser(ctx, &userPb.UserLoginRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})

	duration := time.Since(start).Seconds()
	requestDuration.WithLabelValues("LoginUser").Observe(duration)

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
	start := time.Now()
	requestsTotal.WithLabelValues("ValidateUser").Inc()

	roleResponse, err := s.userClient.ValidateUser(ctx, &userPb.TokenRequest{
		AccessToken: req.AccessToken,
	})

	duration := time.Since(start).Seconds()
	requestDuration.WithLabelValues("ValidateUser").Observe(duration)

	if err != nil {
		return nil, fmt.Errorf("error with validate token: %w", err)
	}

	return &pb.RoleResponse{
		Role: roleResponse.Role,
	}, nil
}

const (
	serverCertFile  = "./cert/gatewayService/certFile.pem"
	serverKeyFile   = "./cert/gatewayService/keyFile.pem"
	metricsCertFile = "./cert/metrics/certFile.pem"
	metricsKeyFile  = "./cert/metrics/keyFile.pem"
)

func (s *server) RefreshGrpcToken(ctx context.Context, req *pb.RefreshGrpcTokenRequest) (*pb.RefreshGrpcTokenResponse, error) {
	start := time.Now()
	requestsTotal.WithLabelValues("RefreshToken").Inc()

	token, err := s.userClient.RefreshUserToken(ctx, &userPb.RefreshUserTokenRequest{
		RefreshToken: req.RefreshToken,
	})

	duration := time.Since(start).Seconds()
	requestDuration.WithLabelValues("RefreshToken").Observe(duration)

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

func startTLSMetricsServer(certFile, keyFile string) {
	err := cert.GenerateCertificate(certFile, keyFile, "localhost")
	if err != nil {
		logger.Logger.Fatal("error generating certificate", zap.Error(err))
	}
	tlsConfig, err := cert.NewHTTPServerTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load TLS certificate for metrics server: %v", err)
	}

	server := &http.Server{
		Addr:      ":8010",
		Handler:   promhttp.Handler(),
		TLSConfig: tlsConfig,
	}

	log.Println("Starting Prometheus metrics server on https://localhost:8010/metrics")
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("Failed to start HTTPS metrics server: %v", err)
	}
}

func main() {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()

	var serverCreds, creds credentials.TransportCredentials
	var err error

	if *tlsEnabled {
		err = cert.GenerateCertificate(serverCertFile, serverKeyFile, "central-grpc-server")
		if err != nil {
			logger.Logger.Fatal("error generating certificate", zap.Error(err))
		}
		serverCreds, err = cert.NewServerTLS(serverCertFile, serverKeyFile)
		if err != nil {
			logger.Logger.Fatal("failed to load key pair", zap.Error(err))
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
	go startTLSMetricsServer(metricsCertFile, metricsKeyFile)
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
