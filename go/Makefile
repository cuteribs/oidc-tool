# Makefile for Go OIDC Tool

BINARY_NAME=oidc-tool
MAIN_PACKAGE=.

# Build variables
VERSION ?= 1.0.0
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS = -ldflags="-s -w -X main.Version=$(VERSION) -X main.CommitHash=$(COMMIT_HASH) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.PHONY: all
all: build

# Build the application
.PHONY: build
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PACKAGE)

# Run the application
.PHONY: run
run:
	go run $(MAIN_PACKAGE)

# Test the application
.PHONY: test
test:
	go test -v ./...

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f $(BINARY_NAME)-windows-amd64.exe
	rm -f $(BINARY_NAME)-darwin-amd64
	rm -f $(BINARY_NAME)-linux-amd64

# Download dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	go vet ./...

# Build for multiple platforms
.PHONY: build-all
build-all: build-windows build-darwin build-linux

.PHONY: build-windows
build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)

.PHONY: build-darwin
build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)

# Install the application
.PHONY: install
install:
	go install $(LDFLAGS) $(MAIN_PACKAGE)

# Display help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build       - Build the application for current platform"
	@echo "  build-all   - Build for Windows, macOS, and Linux"
	@echo "  run         - Run the application without building"
	@echo "  test        - Run tests"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Download and tidy dependencies"
	@echo "  fmt         - Format source code"
	@echo "  lint        - Run static analysis"
	@echo "  install     - Install the application to GOPATH/bin"
	@echo "  help        - Show this help message"
