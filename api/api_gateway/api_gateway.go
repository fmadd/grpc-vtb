package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/grpc-vtb/internal/logger"
	"github.com/grpc-vtb/pkg/cert"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
	pb "github.com/grpc-vtb/api/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	serverAddr     = "central-grpc-server:50051"
	clientCertFile = "./cert/client/certFile.pem"
	clientKeyFile  = "./cert/client/keyFile.pem"
)

type apiServer struct {
	client pb.UserServiceClient
}

func newClientConnection() pb.UserServiceClient {
	tlsEnabled := flag.Bool("tls", true, "Enable TLS (default: false)")
	flag.Parse()

	var creds credentials.TransportCredentials
	var err error

	if *tlsEnabled {
		err = cert.GenerateCertificate(clientCertFile, clientKeyFile, "localhost")
		if err != nil {
			logger.Logger.Fatal("error generating certificate", zap.Error(err))
		}
		creds, err = cert.LoadClientTLSCredentials(clientCertFile, clientKeyFile)
		if err != nil {
			logger.Logger.Fatal("failed to create TLS credentials", zap.Error(err))
		}
	}

	var conn *grpc.ClientConn
	if *tlsEnabled {
		conn, err = grpc.Dial(serverAddr, grpc.WithTransportCredentials(creds))
	} else {
		conn, err = grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if err != nil {
		logger.Logger.Fatal("did not connect", zap.Error(err))
	}

	return pb.NewUserServiceClient(conn)
}

func sanitizeInput(input string) (string, bool) {
	original := input
	input = strings.TrimSpace(input)

	invalidPatterns := []string{
		"(?i)<script.*?>.*?</script>",
		"(?i)javascript:",
		"(?i)data:text/html",
		"(?i)union.*select",
		"(?i)drop.*table",
		"(?i)insert.*into",
		"(?i)select.*from",
		"(?i)update.*set",
		"(?i)--",
		"(?i);",
		"(?i)\\*",
		"(?i)\\|\\|",
	}

	for _, pattern := range invalidPatterns {
		re := regexp.MustCompile(pattern)
		input = re.ReplaceAllString(input, "")
	}

	disallowedChars := []string{"<", ">", "'", "\"", "`", ";", "\\", "--", "|", "%"}
	for _, char := range disallowedChars {
		input = strings.ReplaceAll(input, char, "")
	}

	return input, input != original
}

func (s *apiServer) createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req pb.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	username, usernameChanged := sanitizeInput(req.Username)
	email, emailChanged := sanitizeInput(req.Email)
	password, passwordChanged := sanitizeInput(req.Password)

	if usernameChanged {
		http.Error(w, "error-username-invalid-character", http.StatusBadRequest)
		return
	}
	if emailChanged {
		http.Error(w, "error-email-invalid-character", http.StatusBadRequest)
		return
	}
	if passwordChanged {
		http.Error(w, "error-password-invalid-character", http.StatusBadRequest)
		return
	}

	req.Username = username
	req.Email = email
	req.Password = password

	resp, err := s.client.CreateUser(context.Background(), &req)
	if err != nil {
		http.Error(w, "Error creating user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (s *apiServer) loginUserHandler(w http.ResponseWriter, r *http.Request) {
	var req pb.UserLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	username, usernameChanged := sanitizeInput(req.Username)
	email, emailChanged := sanitizeInput(req.Email)
	password, passwordChanged := sanitizeInput(req.Password)

	if usernameChanged {
		http.Error(w, "error-username-invalid-character", http.StatusBadRequest)
		return
	}
	if emailChanged {
		http.Error(w, "error-email-invalid-character", http.StatusBadRequest)
		return
	}
	if passwordChanged {
		http.Error(w, "error-password-invalid-character", http.StatusBadRequest)
		return
	}

	req.Username = username
	req.Email = email
	req.Password = password
	resp, err := s.client.LoginUser(context.Background(), &req)
	if err != nil {
		http.Error(w, "Error logging in: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (s *apiServer) validateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req pb.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	AccessToken, AccessTokenChanged := sanitizeInput(req.AccessToken)
	if AccessTokenChanged {
		http.Error(w, "error-token-invalid-character", http.StatusBadRequest)
		return
	}
	req.AccessToken = AccessToken
	resp, err := s.client.ValidateUser(context.Background(), &req)
	if err != nil {
		http.Error(w, "Error validating user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (s *apiServer) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req pb.RefreshGrpcTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	RefreshToken, AccessTokenChanged := sanitizeInput(req.RefreshToken)
	if AccessTokenChanged {
		http.Error(w, "error-token-invalid-character", http.StatusBadRequest)
		return
	}
	req.RefreshToken = RefreshToken
	resp, err := s.client.RefreshGrpcToken(context.Background(), &req)
	if err != nil {
		http.Error(w, "Error refreshing token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func main() {
	client := newClientConnection()
	server := &apiServer{client: client}

	router := mux.NewRouter()
	router.HandleFunc("/api/createUser", server.createUserHandler).Methods("POST")
	router.HandleFunc("/api/loginUser", server.loginUserHandler).Methods("POST")
	router.HandleFunc("/api/validateUser", server.validateUserHandler).Methods("POST")
	router.HandleFunc("/api/refreshToken", server.refreshTokenHandler).Methods("POST")

	log.Println("API server is running on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}
