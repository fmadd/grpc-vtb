package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/credentials"
)

const (
	CACertFile = "./cert/ca-cert.pem"
	CAKeyFile  = "./cert/ca-key.pem"
)

func NewClientTLS(certFile, keyFile string) (credentials.TransportCredentials, error) {
	pemServerCA, err := os.ReadFile(CACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate to cert pool")
	}

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}
func NewServerTLS(certFile, keyFile string) (credentials.TransportCredentials, error) {
	pemClientCA, err := os.ReadFile(CACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemClientCA) {
		return nil, errors.New("failed to add client CA's certificate to cert pool")
	}

	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return credentials.NewTLS(config), nil
}

func LoadClientTLSCredentials(certFile string, keyFile string) (credentials.TransportCredentials, error) {
	pemServerCA, err := os.ReadFile(CACertFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}
func GenerateCertificate(certFile, keyFile, hostname string) error {
	caCertPEM, err := os.ReadFile(CACertFile)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(CAKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to parse CA certificate")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return errors.New("failed to parse CA private key")
	}

	var caKey *rsa.PrivateKey
	caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return errors.New("failed to parse CA private key: " + err.Error())
		}
		var ok bool
		caKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("private key is not RSA")
		}
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:            []string{"RU"},
			Province:           []string{"MO"},
			Locality:           []string{"Moscow"},
			Organization:       []string{"Company"},
			OrganizationalUnit: []string{"Department"},
			CommonName:         hostname, // Здесь используется параметр hostname
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 год
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{hostname}, // Использование hostname для DNSNames
	}

	certDER, err := x509.CreateCertificate(rand.Reader, cert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	certDir := filepath.Dir(certFile)
	keyDir := filepath.Dir(keyFile)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	certFileHandle, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certFileHandle.Close()

	if err := pem.Encode(certFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return err
	}

	keyFileHandle, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyFileHandle.Close()

	if err := pem.Encode(keyFileHandle, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}); err != nil {
		return err
	}

	return nil
}

func GenerateCA(caFile, caKeyFile string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	caCert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	certDir := filepath.Dir(caFile)
	keyDir := filepath.Dir(caKeyFile)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}
	caFileHandle, err := os.Create(caFile)
	if err != nil {
		return err
	}
	defer caFileHandle.Close()

	if err := pem.Encode(caFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		return err
	}

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return err
	}

	caKeyFileHandle, err := os.Create(caKeyFile)
	if err != nil {
		return err
	}
	defer caKeyFileHandle.Close()

	if err := pem.Encode(caKeyFileHandle, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return err
	}

	return nil
}
