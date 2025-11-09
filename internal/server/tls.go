package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultKeySize is the default RSA key size for TLS certificates
	DefaultKeySize = 2048
	
	// DefaultCertValidityDuration is the default validity period for certificates
	DefaultCertValidityDuration = 365 * 24 * time.Hour // 1 year
)

// TLSConfig holds TLS configuration options
type TLSConfig struct {
	// CertFile is the path to the certificate file
	CertFile string
	
	// KeyFile is the path to the private key file
	KeyFile string
	
	// CAFile is the path to the CA certificate file (for mutual TLS)
	CAFile string
	
	// ServerName is the expected server name for client connections
	ServerName string
	
	// RequireClientCert indicates whether client certificates are required
	RequireClientCert bool
	
	// InsecureSkipVerify disables certificate verification (for testing only)
	InsecureSkipVerify bool
}

// CertificateInfo contains information for generating certificates
type CertificateInfo struct {
	// Organization is the organization name
	Organization string
	
	// OrganizationalUnit is the organizational unit
	OrganizationalUnit string
	
	// Country is the country code
	Country string
	
	// Province is the province or state
	Province string
	
	// Locality is the city or locality
	Locality string
	
	// CommonName is the common name (usually the hostname)
	CommonName string
	
	// DNSNames are additional DNS names for the certificate
	DNSNames []string
	
	// IPAddresses are additional IP addresses for the certificate
	IPAddresses []net.IP
	
	// ValidityDuration is how long the certificate should be valid
	ValidityDuration time.Duration
	
	// KeySize is the RSA key size
	KeySize int
}

// DefaultCertificateInfo returns default certificate information
func DefaultCertificateInfo() *CertificateInfo {
	return &CertificateInfo{
		Organization:       "Nef Vault",
		OrganizationalUnit: "Security",
		Country:            "US",
		Province:           "CA",
		Locality:           "San Francisco",
		CommonName:         "localhost",
		DNSNames:           []string{"localhost", "*.localhost"},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ValidityDuration:   DefaultCertValidityDuration,
		KeySize:            DefaultKeySize,
	}
}

// GenerateSelfSignedCertificate generates a self-signed certificate and private key
func GenerateSelfSignedCertificate(info *CertificateInfo) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, info.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{info.Organization},
			OrganizationalUnit: []string{info.OrganizationalUnit},
			Country:            []string{info.Country},
			Province:           []string{info.Province},
			Locality:           []string{info.Locality},
			CommonName:         info.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(info.ValidityDuration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              info.DNSNames,
		IPAddresses:           info.IPAddresses,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return certificate, privateKey, nil
}

// SaveCertificateAndKey saves a certificate and private key to PEM files
func SaveCertificateAndKey(cert *x509.Certificate, key *rsa.PrivateKey, certFile, keyFile string) error {
	// Create directories if they don't exist
	if err := os.MkdirAll(filepath.Dir(certFile), 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// LoadTLSConfig loads TLS configuration from certificate and key files
func LoadTLSConfig(config *TLSConfig) (*tls.Config, error) {
	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   config.ServerName,
	}

	// Configure client certificate verification
	if config.RequireClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		
		// Load CA certificate if provided
		if config.CAFile != "" {
			caCert, err := os.ReadFile(config.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}
			
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			
			tlsConfig.ClientCAs = caCertPool
		}
	}

	// For testing purposes only
	if config.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	return tlsConfig, nil
}

// EnsureCertificates generates certificates if they don't exist
func EnsureCertificates(certFile, keyFile string, info *CertificateInfo) error {
	// Check if certificates already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			// Both files exist, verify they're valid
			if _, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
				return nil // Valid certificates exist
			}
		}
	}

	// Generate new certificates
	cert, key, err := GenerateSelfSignedCertificate(info)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Save certificates
	if err := SaveCertificateAndKey(cert, key, certFile, keyFile); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	return nil
}

// GetDefaultTLSConfig returns a default TLS configuration for the vault server
func GetDefaultTLSConfig(dataDir string) *TLSConfig {
	return &TLSConfig{
		CertFile:           filepath.Join(dataDir, "certs", "server.crt"),
		KeyFile:            filepath.Join(dataDir, "certs", "server.key"),
		ServerName:         "localhost",
		RequireClientCert:  false,
		InsecureSkipVerify: false,
	}
}

// SetupTLS sets up TLS configuration and generates certificates if needed
func SetupTLS(config *TLSConfig, certInfo *CertificateInfo) (*tls.Config, error) {
	// Ensure certificates exist
	if err := EnsureCertificates(config.CertFile, config.KeyFile, certInfo); err != nil {
		return nil, fmt.Errorf("failed to ensure certificates: %w", err)
	}

	// Load TLS configuration
	tlsConfig, err := LoadTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	return tlsConfig, nil
}