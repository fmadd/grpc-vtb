package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/grpc-vtb/api/proto/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

	config := &tls.Config{

		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}

func main() {
	// Настройка TLS
	certFile := "cert/ca-cert.pem" // Путь к вашему SSL сертификату

	// Создаем TLS конфигурацию
	creds, err := loadTLSCredentials(certFile)
	if err != nil {
		log.Fatalf("failed to create TLS credentials: %v", err)
	}

	// Подключаемся к gRPC серверу
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewQuoteServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := &pb.QuoteRequest{Category: "inspiration"}
	res, err := client.GetQuote(ctx, req)
	if err != nil {
		log.Fatalf("could not get quote: %v", err)
	}

	log.Printf("Quote: %s", res.Quote)
}
