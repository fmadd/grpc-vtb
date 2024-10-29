package auth

import (
	"context"
)

// UserAuth - структура для представления аутентификационных данных пользователя.
type UserAuth struct {
	Username string
	Password string
}

// TokenResponse - структура для представления ответа с токеном.
type TokenResponse struct {
	AccessToken string
	ExpiresIn   int64
}

// AuthService - интерфейс для взаимодействия с модулем аутентификации.
type AuthService interface {
	// Login - метод для получения токена с использованием данных пользователя.
	Login(ctx context.Context, auth UserAuth) (TokenResponse, error)

	// ValidateToken - метод для проверки валидности JWT токена.
	ValidateToken(ctx context.Context, token string) (bool, error)
}
