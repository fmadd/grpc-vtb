package handler

import (
	"context"
	"errors"
	"fmt"
	"github.com/Nerzal/gocloak/v13"
	"github.com/grpc-vtb/internal/auth/proto"
	"log"
)

type AuthHandler struct {
	client       *gocloak.GoCloak
	realm        string
	clientID     string
	clientSecret string
	proto.UnimplementedAuthServiceServer
}

func NewAuthHandler(client *gocloak.GoCloak, realm, clientID, clientSecret string) *AuthHandler {
	return &AuthHandler{
		client:       client,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

func (h *AuthHandler) Login(ctx context.Context, req *proto.UserAuth) (*proto.TokenResponse, error) {
	token, err := h.client.Login(ctx, h.clientID, h.clientSecret, h.realm, req.Username, req.Password)
	if err != nil {
		log.Println("Error logging in:", err)
		return nil, err
	}

	return &proto.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   int64(token.ExpiresIn),
	}, nil
}

func (h *AuthHandler) ValidateToken(ctx context.Context, req *proto.TokenRequest) (*proto.RoleResponse, error) {
	isValid, err := h.client.RetrospectToken(ctx, req.AccessToken, h.clientID, h.clientSecret, h.realm)
	if err != nil {
		return nil, fmt.Errorf("error validating token: %v", err)
	}

	if isValid == nil || !*isValid.Active {
		return nil, fmt.Errorf("invalid token")
	}

	userInfo, err := h.client.GetUserInfo(ctx, req.AccessToken, h.realm)
	if err != nil {
		log.Println("Error validate token:", err)
		return nil, err
	}

	role := *userInfo.PreferredUsername
	if role == "" {
		return nil, errors.New("role not found")
	}

	return &proto.RoleResponse{Role: role}, nil
}

func (h *AuthHandler) RegisterUser(ctx context.Context, req *proto.RegisterUserRequest) (*proto.TokenResponse, error) {
	log.Printf("Attempting to login as clientID: %s, clientSecret: %s, realm: %s", h.clientID, h.clientSecret, h.realm)
	adminToken, err := h.client.LoginClient(ctx, h.clientID, h.clientSecret, h.realm)
	log.Printf("admin token: %s", adminToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("error to get admin token: %v", err)
	}

	user := gocloak.User{
		Username: &req.Username,
		Email:    &req.Email,
		Enabled:  gocloak.BoolP(true),
	}

	userID, err := h.client.CreateUser(ctx, adminToken.AccessToken, h.realm, user)
	if err != nil {
		return nil, fmt.Errorf("error to register user: %v", err)
	}
	log.Printf("Setting password for realm: %s", h.realm)

	err = h.client.SetPassword(ctx, adminToken.AccessToken, userID, h.realm, req.Password, false)
	if err != nil {
		return nil, fmt.Errorf("error to set pass: %v", err)
	}

	userToken, err := h.client.Login(ctx, h.clientID, h.clientSecret, h.realm, req.Username, req.Password)
	if err != nil {
		return nil, fmt.Errorf("error to get user token: %v", err)
	}

	return &proto.TokenResponse{
		AccessToken: userToken.AccessToken,
		ExpiresIn:   int64(userToken.ExpiresIn),
	}, nil
}
