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

	"github.com/gorilla/mux"
	pb "github.com/grpc-vtb/api/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	serverAddr     = "localhost:50051"
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
	//defer conn.Close()

	return pb.NewUserServiceClient(conn)
}

// HTTP Handlers

func (s *apiServer) createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req pb.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

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
