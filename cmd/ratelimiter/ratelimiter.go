package ratelimiter

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"time"
)

var limiter = rate.NewLimiter(rate.Every(time.Second), 5)

func RateLimitInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata")
	}
	clientID := md.Get("client-id")

	if !limiter.Allow() {
		return nil, fmt.Errorf("too many requests from client %s", clientID)
	}

	return handler(ctx, req)
}
