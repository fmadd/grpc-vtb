package main

import (
	"context"
	"crypto/tls"
	_ "fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	pb "github.com/grpc-vtb/api/proto/gen"
)

type server struct {
    pb.UnimplementedQuoteServiceServer
}

func (s *server) GetQuote(ctx context.Context, req *pb.QuoteRequest) (*pb.QuoteResponse, error) {
    quote := "Example quote for category: " + req.Category
    return &pb.QuoteResponse{Quote: quote}, nil
}

func loadTLSCredentials(certFile string, keyFile string) (credentials.TransportCredentials, error) {
    // Load server's certificate and private key
    serverCert, err :=  tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
   
    // Create the credentials and return it
    config := &tls.Config{
        Certificates: []tls.Certificate{tls.Certificate(serverCert)},
        ClientAuth:  tls.NoClientCert,
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

    // Логирование запроса
    log.Printf("Received request: %s, with payload: %v", info.FullMethod, req)

    // Вызов следующего обработчика
    resp, err := handler(ctx, req)

    // Логирование ответа
    log.Printf("Response for request: %s, duration: %s, error: %v", info.FullMethod, time.Since(start), err)

    return resp, err
}
func main() {
    certFile := "cert/server-cert.pem"
    keyFile :=  "cert/server-key.pem"  


    creds, err := loadTLSCredentials(certFile, keyFile)
    if err != nil {
        log.Fatalf("failed to load key pair: %v", err)
    }

    serverOpts := []grpc.ServerOption{
        grpc.Creds(creds),
        grpc.UnaryInterceptor(loggingInterceptor),
    }
    srv := grpc.NewServer(serverOpts...)

    pb.RegisterQuoteServiceServer(srv, &server{})
    reflection.Register(srv)

    listener, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    log.Println("Starting gRPC server on port :50051...")
    if err := srv.Serve(listener); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}