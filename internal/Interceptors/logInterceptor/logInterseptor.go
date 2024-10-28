package logInterceptor

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func LogInterceptor(
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