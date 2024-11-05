package jwtInterceptor

import (
	"context"

	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"github.com/grpc-vtb/internal/auth/proto"
)

// JWT интерсептор с валидацией токенов
func JWTInterceptor(authClient proto.AuthServiceClient) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Проверка, является ли это методом аутентификации или регистрации
		if isPublicEndpoint(info.FullMethod) {
			// Пропускаем проверку токена для публичных точек
			return handler(ctx, req)
		}

		// Извлечение токена из метаданных
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}

		token := md["authorization"]
		if len(token) == 0 || !strings.HasPrefix(token[0], "Bearer ") {
			return nil, status.Errorf(codes.Unauthenticated, "authorization token is not supplied")
		}
		tokenString := token[0][7:]

		request := &proto.TokenRequest{AccessToken: tokenString}
		// Проверка валидности токена
		isValid, err := authClient.ValidateToken(context.Background(), request)
		if err != nil || !isValid.Authorized {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		// Вызов обработчика
		return handler(ctx, req)
	}
}

// Функция для определения, является ли метод публичным
func isPublicEndpoint(fullMethod string) bool {
	publicEndpoints := []string{
		"/auth.AuthService/ValidateToken",
		"/auth.AuthService/Login",
		"/user.UserService/CreateUser",
	}

	for _, endpoint := range publicEndpoints {
		if strings.EqualFold(fullMethod, endpoint) {
			return true
		}
	}
	return false
}
