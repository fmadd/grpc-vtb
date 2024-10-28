package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	_ "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	pb "github.com/grpc-vtb/api/proto/gen"
	_ "github.com/grpc-vtb/internal/interceptors/jwtInterceptor"
)
// TODO: Вынести в конфиги
const (
	serverCertFile   = "cert/server-cert.pem"
	serverKeyFile    = "cert/server-key.pem"
	clientCACertFile = "cert/ca-cert.pem"
    secretKey = "secret"
)

// const (
//     keycloakPublicKey = 'keycloakKey' TODO: Вынести в конфиги
// )


type server struct {
    pb.UnimplementedQuoteServiceServer
}

func (s *server) GetQuote(ctx context.Context, req *pb.QuoteRequest) (*pb.QuoteResponse, error) {
    quote := "Success! Example quote for category: " + req.Category
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

    serverCert, err :=  tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
   
    config := &tls.Config{
        Certificates: []tls.Certificate{tls.Certificate(serverCert)},
        ClientAuth:  tls.RequireAndVerifyClientCert,
        ClientCAs: certPool,
    }
   
    return credentials.NewTLS(config), nil
}



func main() {
    tlsEnabled := flag.Bool("tls", false, "Enable TLS (default: false)")
    flag.Parse()

    certFile := serverCertFile
    keyFile := serverKeyFile

    var creds credentials.TransportCredentials
    var err error

    if *tlsEnabled {
        creds, err = loadTLSCredentials(certFile, keyFile)
        if err != nil {
            log.Fatalf("failed to load key pair: %v", err)
        }
    }

    serverOpts := []grpc.ServerOption{}
    
    if *tlsEnabled {
        serverOpts = append(serverOpts, grpc.Creds(creds))
    }

    // Задел для проверки jwt
    // serverOpts = append(serverOpts, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
    //     jwtInterceptor.JWTInterceptor(secretKey),
    // )))
  

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