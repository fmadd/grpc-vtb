package logInterceptor

import (
	"context"
	"github.com/grpc-vtb/internal/logger"
	"go.uber.org/zap"
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

	logger.Logger.Info("Received request", zap.String("method", info.FullMethod), zap.Any("payload", req))

	resp, err := handler(ctx, req)

	logger.Logger.Info("Response for request",
		zap.String("method", info.FullMethod),
		zap.Duration("duration", time.Since(start)),
		zap.Error(err))
	return resp, err
}
