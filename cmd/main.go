package main

import (
	"context"
	"crypto/tls"
	_ "fmt"
	"log"
	"net"

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

func main() {
    certFile := "crt_storage/certs/server.crt" 
    keyFile := "crt_storage/private/server.key"   

    creds, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Fatalf("failed to load key pair: %v", err)
    }

    serverOpts := []grpc.ServerOption{
        grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{creds}})),
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