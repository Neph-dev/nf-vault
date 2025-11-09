# Nef-Vault Makefile
# Provides targets for building, testing, and code generation

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Binary names
CLI_BINARY_NAME=nef-vault-cli
SERVER_BINARY_NAME=nef-vault-server

# Directories
BUILD_DIR=build
PROTO_DIR=proto
GEN_DIR=gen
PKG_DIR=pkg
CMD_DIR=cmd

# Protocol buffer settings
PROTOC=protoc
PROTO_INCLUDE_PATH=/usr/local/include:/opt/homebrew/include
PROTO_SRC_DIR=$(PROTO_DIR)/vault/v1
PROTO_GEN_DIR=$(GEN_DIR)/proto/vault/v1

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
BLUE=\033[0;34m
NC=\033[0m # No Color

.PHONY: all build clean test coverage proto install-tools help cli server

# Default target
all: clean proto test build

# Help target
help: ## Show this help message
	@echo "$(BLUE)Nef-Vault Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Install required tools
install-tools: ## Install required development tools
	@echo "$(BLUE)Installing development tools...$(NC)"
	@echo "Installing protobuf compiler..."
	@if ! command -v protoc >/dev/null 2>&1; then \
		echo "$(RED)Error: protoc not found. Please install Protocol Buffers compiler.$(NC)"; \
		echo "$(YELLOW)On macOS: brew install protobuf$(NC)"; \
		echo "$(YELLOW)On Linux: apt-get install protobuf-compiler$(NC)"; \
		exit 1; \
	fi
	@echo "Installing Go protobuf plugins..."
	$(GOGET) google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GOGET) google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Installing linting tools..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Installing testing tools..."
	$(GOGET) github.com/stretchr/testify@latest
	@echo "$(GREEN)Tools installed successfully!$(NC)"

# Generate Go code from protobuf files
proto: ## Generate Go code from protobuf definitions
	@echo "$(BLUE)Generating Go code from protobuf files...$(NC)"
	@echo "Checking for protoc..."
	@if ! command -v protoc >/dev/null 2>&1; then \
		echo "$(RED)Error: protoc not found. Run 'make install-tools' first.$(NC)"; \
		exit 1; \
	fi
	@echo "Checking for protoc-gen-go..."
	@if ! PATH="$(HOME)/go/bin:$(PATH)" command -v protoc-gen-go >/dev/null 2>&1; then \
		echo "$(RED)Error: protoc-gen-go not found. Run 'make install-tools' first.$(NC)"; \
		exit 1; \
	fi
	@echo "Checking for protoc-gen-go-grpc..."
	@if ! PATH="$(HOME)/go/bin:$(PATH)" command -v protoc-gen-go-grpc >/dev/null 2>&1; then \
		echo "$(RED)Error: protoc-gen-go-grpc not found. Run 'make install-tools' first.$(NC)"; \
		exit 1; \
	fi
	@echo "Creating output directory..."
	@mkdir -p $(PROTO_GEN_DIR)
	@echo "Generating Go protobuf code..."
	PATH="$(HOME)/go/bin:$(PATH)" $(PROTOC) \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_SRC_DIR)/*.proto
	@echo "$(GREEN)Protobuf code generation completed successfully!$(NC)"
	@echo "Generated files:"
	@find $(GEN_DIR) -name "*.go" -type f | sed 's/^/  /'

# Clean generated protobuf code
proto-clean: ## Clean generated protobuf Go code
	@echo "$(BLUE)Cleaning generated protobuf code...$(NC)"
	@rm -rf $(GEN_DIR)
	@echo "$(GREEN)Protobuf generated code cleaned!$(NC)"

# Build targets
build: cli server ## Build all binaries

cli: proto ## Build CLI client
	@echo "$(BLUE)Building CLI client...$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(CLI_BINARY_NAME) ./$(CMD_DIR)/cli
	@echo "$(GREEN)CLI client built: $(BUILD_DIR)/$(CLI_BINARY_NAME)$(NC)"

server: proto ## Build gRPC server
	@echo "$(BLUE)Building gRPC server...$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(SERVER_BINARY_NAME) ./$(CMD_DIR)/server
	@echo "$(GREEN)gRPC server built: $(BUILD_DIR)/$(SERVER_BINARY_NAME)$(NC)"

# Testing targets
test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(GOTEST) -v ./...
	@echo "$(GREEN)All tests passed!$(NC)"

test-crypto: ## Run cryptography tests only
	@echo "$(BLUE)Running cryptography tests...$(NC)"
	$(GOTEST) -v ./$(PKG_DIR)/crypto/...
	@echo "$(GREEN)Cryptography tests passed!$(NC)"

test-auth: ## Run authentication tests only
	@echo "$(BLUE)Running authentication tests...$(NC)"
	$(GOTEST) -v ./$(PKG_DIR)/auth/...
	@echo "$(GREEN)Authentication tests passed!$(NC)"

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

# Fuzzing targets
fuzz: ## Run fuzz tests for crypto package
	@echo "$(BLUE)Running fuzz tests...$(NC)"
	$(GOTEST) -fuzz=FuzzDeriveKey -fuzztime=30s ./$(PKG_DIR)/crypto
	$(GOTEST) -fuzz=FuzzEncryptSecret -fuzztime=30s ./$(PKG_DIR)/crypto
	$(GOTEST) -fuzz=FuzzGenerateRandomBytes -fuzztime=30s ./$(PKG_DIR)/crypto
	@echo "$(GREEN)Fuzz tests completed!$(NC)"

# Code quality targets
fmt: ## Format Go code
	@echo "$(BLUE)Formatting Go code...$(NC)"
	$(GOFMT) -w -s .
	@echo "$(GREEN)Code formatted!$(NC)"

lint: ## Run linters
	@echo "$(BLUE)Running linters...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)golangci-lint not found, running go vet instead...$(NC)"; \
		$(GOCMD) vet ./...; \
	fi
	@echo "$(GREEN)Linting completed!$(NC)"

vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(NC)"
	$(GOCMD) vet ./...
	@echo "$(GREEN)go vet passed!$(NC)"

# Dependency management
deps: ## Download and tidy dependencies
	@echo "$(BLUE)Managing dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "$(GREEN)Dependencies updated!$(NC)"

deps-update: ## Update all dependencies
	@echo "$(BLUE)Updating dependencies...$(NC)"
	$(GOGET) -u ./...
	$(GOMOD) tidy
	@echo "$(GREEN)Dependencies updated!$(NC)"

# Development targets
dev-setup: install-tools deps proto ## Set up development environment
	@echo "$(GREEN)Development environment set up successfully!$(NC)"

# Security targets
security-scan: ## Run security scans
	@echo "$(BLUE)Running security scans...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "$(YELLOW)gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest$(NC)"; \
	fi

# Clean targets
clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "$(GREEN)Build artifacts cleaned!$(NC)"

clean-all: clean proto-clean ## Clean everything including generated code
	@echo "$(GREEN)All artifacts cleaned!$(NC)"

# Docker targets (for future use)
docker-build: ## Build Docker images
	@echo "$(BLUE)Building Docker images...$(NC)"
	@echo "$(YELLOW)Docker build not implemented yet$(NC)"

docker-run: ## Run application in Docker
	@echo "$(BLUE)Running in Docker...$(NC)"
	@echo "$(YELLOW)Docker run not implemented yet$(NC)"

# Deployment targets (for future use)
deploy-local: build ## Deploy locally for testing
	@echo "$(BLUE)Deploying locally...$(NC)"
	@echo "$(YELLOW)Local deployment not implemented yet$(NC)"

# Benchmark targets
bench: ## Run benchmarks
	@echo "$(BLUE)Running benchmarks...$(NC)"
	$(GOTEST) -bench=. -benchmem ./$(PKG_DIR)/crypto/...
	@echo "$(GREEN)Benchmarks completed!$(NC)"

# Documentation targets
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@echo "$(YELLOW)Documentation generation not implemented yet$(NC)"

# Version and release targets
version: ## Show version information
	@echo "$(BLUE)Version Information:$(NC)"
	@echo "Go version: $$($(GOCMD) version)"
	@echo "Protoc version: $$(protoc --version 2>/dev/null || echo 'not installed')"
	@echo "Git commit: $$(git rev-parse --short HEAD 2>/dev/null || echo 'not a git repo')"

# Check everything before commit
check: fmt vet lint test ## Run all checks (format, vet, lint, test)
	@echo "$(GREEN)All checks passed! Ready to commit.$(NC)"

# CI/CD targets
ci: deps proto lint test ## CI pipeline target
	@echo "$(GREEN)CI pipeline completed successfully!$(NC)"