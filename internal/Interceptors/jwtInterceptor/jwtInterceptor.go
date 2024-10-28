package jwtInterceptor

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dgrijalva/jwt-go"
)

// перехватчик для проверки JWT токенов
func JWTInterceptor(secret string) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{},
        info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {

        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "no metadata in context")
        }

        tokens := md["authorization"]
        if len(tokens) == 0 {
            return nil, status.Error(codes.Unauthenticated, "missing authorization token")
        }
        tokenString := tokens[0][7:] 

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return []byte(secret), nil 
        })

        if err != nil || !token.Valid {
            return nil, status.Error(codes.Unauthenticated, "invalid token")
        }
        return handler(ctx, req)
    }
}
