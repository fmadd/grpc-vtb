package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	_ "fmt"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

    _ "github.com/grpc-vtb/internal/middleware/jwtmiddleware"
	pb "github.com/grpc-vtb/api/proto/gen"
)
const (
	serverCertFile   = "cert/server-cert.pem"
	serverKeyFile    = "cert/server-key.pem"
	clientCACertFile = "cert/ca-cert.pem"
    secretKey = "secret"
)

type server struct {
    pb.UnimplementedQuoteServiceServer
}

func (s *server) GetQuote(ctx context.Context, req *pb.QuoteRequest) (*pb.QuoteResponse, error) {
    quote := "Example quote for category: " + req.Category
    return &pb.QuoteResponse{Quote: quote}, nil
}

func loadTLSCredentials(certFile string, keyFile string) (credentials.TransportCredentials, error) {
    pemClientCA, err := os.ReadFile(clientCACertFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemClientCA) {
		return nil, fmt.Errorf("failed to add client CA's certificate")
	}

    // Load server's certificate and private key
    serverCert, err :=  tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
   
    // Create the credentials and return it
    config := &tls.Config{
        Certificates: []tls.Certificate{tls.Certificate(serverCert)},
        ClientAuth:  tls.RequireAndVerifyClientCert,
        ClientCAs: certPool,
    }
   
    return credentials.NewTLS(config), nil
}

func loggingInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    start := time.Now()

    log.Printf("Received request: %s, with payload: %v", info.FullMethod, req)

    resp, err := handler(ctx, req)

    log.Printf("Response for request: %s, duration: %s, error: %v", info.FullMethod, time.Since(start), err)

    return resp, err
}

func main() {
    // Adding command line flags
    tlsEnabled := flag.Bool("tls", false, "Enable TLS (default: false)")
    flag.Parse()

    certFile := serverCertFile
    keyFile := serverKeyFile

    var creds credentials.TransportCredentials
    var err error

    // Load TLS credentials if enabled
    if *tlsEnabled {
        creds, err = loadTLSCredentials(certFile, keyFile)
        if err != nil {
            log.Fatalf("failed to load key pair: %v", err)
        }
    }

    serverOpts := []grpc.ServerOption{
        // Add credentials or empty if TLS is not enabled
    }
    if *tlsEnabled {
        serverOpts = append(serverOpts, grpc.Creds(creds))
    }

    serverOpts = append(serverOpts, grpc.UnaryInterceptor(loggingInterceptor))
    //serverOpts = append(serverOpts, grpc.UnaryInterceptor(jwtmiddleware.JWTMiddleware(secretKey)))

    srv := grpc.NewServer(serverOpts...)

    pb.RegisterQuoteServiceServer(srv, &server{})
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