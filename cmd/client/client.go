package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/grpc-vtb/api/proto/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/metadata"
)
const (
	clientCertFile   = "cert/client-cert.pem"
	clientKeyFile    = "cert/client-key.pem"
	clientCACertFile = "cert/ca-cert.pem"
    JwtToken = "token_example"
)

func loadTLSCredentials(certFile string) (credentials.TransportCredentials, error) {
	pemServerCA, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

    clientCert, err :=  tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
    if err != nil {
        return nil, err
    }

	config := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}

func main() {
    tlsEnabled := flag.Bool("tls", false, "Enable TLS (default: false)")
    flag.Parse()

    var creds credentials.TransportCredentials
    var err error

    if *tlsEnabled {
        certFile := clientCACertFile
        creds, err = loadTLSCredentials(certFile)
        if err != nil {
            log.Fatalf("failed to create TLS credentials: %v", err)
        }
    }

    var conn *grpc.ClientConn
    if *tlsEnabled {
        conn, err = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
    } else {
        conn, err = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
    }

    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()

    client := pb.NewQuoteServiceClient(conn)

    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()

    // Задел для использования jwt токенов от клиента
    // ctx = metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+ JwtToken ))

    req := &pb.QuoteRequest{Category: "inspiration"}
    res, err := client.GetQuote(ctx, req)
    if err != nil {
        log.Fatalf("could not get quote: %v", err)
    }

    log.Printf("Quote: %s", res.Quote)
}