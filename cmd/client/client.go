package main

import (
	"context"
	"flag"
	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
	"time"

	pb "github.com/grpc-vtb/api/proto/gen"
	"github.com/grpc-vtb/pkg/cert"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/metadata"
)

const (
	CACertFile = "./cert/ca-cert.pem"
	CACertKey  = "./cert/ca-key.pem"
	JwtToken   = "token_example"
)
const (
	clientCertFile = "./cert/client/certFile.pem"
	clientKeyFile  = "./cert/client/keyFile.pem"
)

func main() {

	tlsEnabled := flag.Bool("tls", false, "Enable TLS (default: false)")
	flag.Parse()

	var creds credentials.TransportCredentials
	var err error

	if *tlsEnabled {
		cert.GenerateCertificate(clientCertFile, clientKeyFile)
		creds, err = cert.LoadClientTLSCredentials(clientCertFile, clientKeyFile)
		if err != nil {
			logger.Logger.Fatal("failed to create TLS credentials", zap.Error(err))
		}
	}

	var conn *grpc.ClientConn
	if *tlsEnabled {
		conn, err = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	} else {
		conn, err = grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if err != nil {
		logger.Logger.Fatal("did not connect", zap.Error(err))
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
		logger.Logger.Fatal("could not get quote", zap.Error(err))
	}

	logger.Logger.Info("Quote", zap.String("Quote", res.Quote))
}
