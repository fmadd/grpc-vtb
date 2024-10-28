package jwtmiddleware

import (
	"context"
	"fmt"


	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dgrijalva/jwt-go"
)

// JWTMiddleware - перехватчик для проверки JWT токенов
func JWTMiddleware(secret string) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{},
        info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {

        // Извлечение токена из метаданных
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "no metadata in context")
        }

        // Извлечение токена
        tokens := md["authorization"]
        if len(tokens) == 0 {
            return nil, status.Error(codes.Unauthenticated, "missing authorization token")
        }
        tokenString := tokens[0][7:] // Убираем 'Bearer ' в начале

        // Проверка JWT токена
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return []byte(secret), nil // Здесь используйте ваш секрет или публичный ключ
        })

        if err != nil || !token.Valid {
            return nil, status.Error(codes.Unauthenticated, "invalid token")
        }

        // Вызов обработчика
        return handler(ctx, req)
    }
}

