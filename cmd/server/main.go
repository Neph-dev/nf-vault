// Package main implements the Nef Vault gRPC server.
// The server provides secure secret management with encrypted storage,
// JWT-based authentication, and comprehensive audit logging.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	vault "github.com/Neph-dev/nef-vault/gen/vault/v1"
	"github.com/Neph-dev/nef-vault/internal/server"
	"github.com/Neph-dev/nef-vault/pkg/store"
)

// Config holds server configuration
type Config struct {
	// Server configuration
	Address         string
	Port            int
	EnableTLS       bool
	DataDir         string
	LogLevel        string
	
	// Database configuration
	DBType          string
	DBPath          string
	DBHost          string
	DBPort          int
	DBName          string
	DBUser          string
	DBPassword      string
	
	// TLS configuration
	CertFile        string
	KeyFile         string
	CAFile          string
	
	// JWT configuration
	JWTSecret       string
	JWTExpiration   time.Duration
	
	// Security configuration
	RequireClientCert bool
	InsecureMode      bool
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	defaultDataDir := filepath.Join(homeDir, ".nef-vault")
	
	return &Config{
		Address:           "0.0.0.0",
		Port:              9090,
		EnableTLS:         true,
		DataDir:           defaultDataDir,
		LogLevel:          "info",
		DBType:            "sqlite",
		DBPath:            filepath.Join(defaultDataDir, "vault.db"),
		JWTExpiration:     24 * time.Hour,
		RequireClientCert: false,
		InsecureMode:      false,
	}
}

// parseFlags parses command line flags and environment variables
func parseFlags() *Config {
	config := DefaultConfig()
	
	// Define flags
	flag.StringVar(&config.Address, "address", config.Address, "Server address to bind to")
	flag.IntVar(&config.Port, "port", config.Port, "Server port to bind to")
	flag.BoolVar(&config.EnableTLS, "tls", config.EnableTLS, "Enable TLS encryption")
	flag.StringVar(&config.DataDir, "data-dir", config.DataDir, "Data directory for storage and certificates")
	flag.StringVar(&config.LogLevel, "log-level", config.LogLevel, "Log level (debug, info, warn, error)")
	
	// Database flags
	flag.StringVar(&config.DBType, "db-type", config.DBType, "Database type (sqlite, postgres)")
	flag.StringVar(&config.DBPath, "db-path", config.DBPath, "SQLite database file path")
	flag.StringVar(&config.DBHost, "db-host", config.DBHost, "Database host (for postgres)")
	flag.IntVar(&config.DBPort, "db-port", config.DBPort, "Database port (for postgres)")
	flag.StringVar(&config.DBName, "db-name", config.DBName, "Database name (for postgres)")
	flag.StringVar(&config.DBUser, "db-user", config.DBUser, "Database user (for postgres)")
	flag.StringVar(&config.DBPassword, "db-password", config.DBPassword, "Database password (for postgres)")
	
	// TLS flags
	flag.StringVar(&config.CertFile, "cert-file", config.CertFile, "TLS certificate file")
	flag.StringVar(&config.KeyFile, "key-file", config.KeyFile, "TLS private key file")
	flag.StringVar(&config.CAFile, "ca-file", config.CAFile, "CA certificate file (for mutual TLS)")
	
	// JWT flags
	flag.StringVar(&config.JWTSecret, "jwt-secret", config.JWTSecret, "JWT signing secret")
	flag.DurationVar(&config.JWTExpiration, "jwt-expiration", config.JWTExpiration, "JWT token expiration duration")
	
	// Security flags
	flag.BoolVar(&config.RequireClientCert, "require-client-cert", config.RequireClientCert, "Require client certificates")
	flag.BoolVar(&config.InsecureMode, "insecure", config.InsecureMode, "Disable TLS (for development only)")
	
	flag.Parse()
	
	// Override with environment variables if set
	if addr := os.Getenv("VAULT_ADDRESS"); addr != "" {
		config.Address = addr
	}
	if port := os.Getenv("VAULT_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &config.Port)
	}
	if dataDir := os.Getenv("VAULT_DATA_DIR"); dataDir != "" {
		config.DataDir = dataDir
	}
	if dbPath := os.Getenv("VAULT_DB_PATH"); dbPath != "" {
		config.DBPath = dbPath
	}
	if jwtSecret := os.Getenv("VAULT_JWT_SECRET"); jwtSecret != "" {
		config.JWTSecret = jwtSecret
	}
	
	// Set default paths if not specified
	if config.CertFile == "" {
		config.CertFile = filepath.Join(config.DataDir, "certs", "server.crt")
	}
	if config.KeyFile == "" {
		config.KeyFile = filepath.Join(config.DataDir, "certs", "server.key")
	}
	
	return config
}

// initializeStore creates and initializes the storage backend
func initializeStore(config *Config) (store.Store, error) {
	switch config.DBType {
	case "sqlite":
		// Ensure data directory exists
		if err := os.MkdirAll(filepath.Dir(config.DBPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create data directory: %w", err)
		}
		
		// For SQLite, we need to provide the migration directory
		migrationDir := filepath.Join(config.DataDir, "migrations")
		sqliteStore, err := store.NewSQLiteStore(config.DBPath, migrationDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create SQLite store: %w", err)
		}
		
		return sqliteStore, nil
		
	default:
		return nil, fmt.Errorf("unsupported database type: %s (currently only sqlite is supported)", config.DBType)
	}
}

// setupTLS configures TLS for the gRPC server
func setupTLS(config *Config) (*tls.Config, error) {
	if config.InsecureMode {
		log.Println("WARNING: Running in insecure mode (TLS disabled)")
		return nil, nil
	}
	
	if !config.EnableTLS {
		return nil, nil
	}
	
	// Create TLS configuration
	tlsConfig := &server.TLSConfig{
		CertFile:           config.CertFile,
		KeyFile:            config.KeyFile,
		CAFile:             config.CAFile,
		ServerName:         "localhost",
		RequireClientCert:  config.RequireClientCert,
		InsecureSkipVerify: false,
	}
	
	// Generate default certificate info
	certInfo := server.DefaultCertificateInfo()
	
	// Setup TLS with certificate generation
	return server.SetupTLS(tlsConfig, certInfo)
}

// createGRPCServer creates and configures the gRPC server
func createGRPCServer(config *Config, storeInstance store.Store, tlsConfig *tls.Config) (*grpc.Server, error) {
	var opts []grpc.ServerOption
	
	// Add TLS credentials if enabled
	if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	}
	
	// Create auth service
	authConfig := server.AuthServiceConfig{
		Store:           storeInstance,
		JWTSecret:       []byte(config.JWTSecret),
		TokenLifetime:   config.JWTExpiration,
		RefreshLifetime: config.JWTExpiration * 2,
	}
	authService := server.NewAuthService(authConfig)
	
	// Create interceptors
	authInterceptor := server.NewAuthInterceptor(authService)
	loggingInterceptor := server.NewLoggingInterceptor(log.Default())
	errorInterceptor := server.NewErrorHandlingInterceptor()
	
	// Chain interceptors
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			loggingInterceptor.UnaryInterceptor,
			authInterceptor.UnaryInterceptor,
			errorInterceptor.UnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			loggingInterceptor.StreamInterceptor,
			authInterceptor.StreamInterceptor,
			errorInterceptor.StreamInterceptor,
		),
	)
	
	// Create gRPC server
	grpcServer := grpc.NewServer(opts...)
	
	// Create and register vault service
	vaultService := server.NewVaultServiceServer(storeInstance, authService)
	vault.RegisterVaultServiceServer(grpcServer, vaultService)
	
	// Enable gRPC reflection for development
	if config.LogLevel == "debug" {
		reflection.Register(grpcServer)
	}
	
	return grpcServer, nil
}

// runServer starts the gRPC server and handles graceful shutdown
func runServer(config *Config) error {
	// Initialize storage
	log.Printf("Initializing %s storage...", config.DBType)
	storeInstance, err := initializeStore(config)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() {
		if err := storeInstance.Close(); err != nil {
			log.Printf("Error closing store: %v", err)
		}
	}()
	
	// Test storage connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := storeInstance.Ping(ctx); err != nil {
		return fmt.Errorf("failed to connect to storage: %w", err)
	}
	log.Println("Storage connection successful")
	
	// Setup TLS
	log.Println("Setting up TLS configuration...")
	tlsConfig, err := setupTLS(config)
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}
	
	if tlsConfig != nil {
		log.Printf("TLS enabled with certificate: %s", config.CertFile)
	} else {
		log.Println("TLS disabled")
	}
	
	// Create gRPC server
	log.Println("Creating gRPC server...")
	grpcServer, err := createGRPCServer(config, storeInstance, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}
	
	// Create listener
	address := fmt.Sprintf("%s:%d", config.Address, config.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	
	// Setup graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	
	// Start server in goroutine
	go func() {
		log.Printf("Starting Nef Vault server on %s (TLS: %v)", address, tlsConfig != nil)
		if err := grpcServer.Serve(listener); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()
	
	// Wait for shutdown signal
	<-shutdown
	log.Println("Shutting down server...")
	
	// Graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()
	
	select {
	case <-done:
		log.Println("Server stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Shutdown timeout, forcing stop")
		grpcServer.Stop()
	}
	
	return nil
}

// validateConfig validates the server configuration
func validateConfig(config *Config) error {
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}
	
	if config.DataDir == "" {
		return fmt.Errorf("data directory is required")
	}
	
	if config.EnableTLS && !config.InsecureMode {
		if config.CertFile == "" || config.KeyFile == "" {
			return fmt.Errorf("certificate and key files are required for TLS")
		}
	}
	
	if config.JWTSecret == "" {
		log.Println("WARNING: No JWT secret provided, generating random secret")
		// This is acceptable as we'll generate one, but warn the user
	}
	
	return nil
}

// generateSecureSecret generates a random hex-encoded secret
func generateSecureSecret(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate secure secret: %v", err))
	}
	return hex.EncodeToString(bytes)
}

func main() {
	// Parse configuration
	config := parseFlags()
	
	// Validate configuration
	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	
	// Generate JWT secret if not provided
	if config.JWTSecret == "" {
		config.JWTSecret = generateSecureSecret(32)
		log.Println("Generated random JWT secret (will not persist across restarts)")
	}
	
	// Run server
	if err := runServer(config); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}