.PHONY: build test test-unit test-integration clean install help

# Build configuration
BINARY_NAME=wg-quick
BUILD_DIR=build
VERSION?=$(shell git describe --tags --always --dirty)

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Build targets
build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) wg-quick.go

build-all: ## Build for all supported platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 wg-quick.go
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 wg-quick.go
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 wg-quick.go
	GOOS=freebsd GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64 wg-quick.go
	GOOS=openbsd GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-amd64 wg-quick.go

# Test targets
test: test-unit test-integration ## Run all tests

test-unit: ## Run unit tests (no root required)
	@echo "Running unit tests..."
	go test -v ./test/ -run 'TestPlatformInterfaceMapping|TestPlatformMethodsExist|TestWireGuardCommandGeneration|TestIntegration_ConfigValidation'

test-integration: ## Run integration tests (requires root)
	@echo "Running integration tests..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Integration tests require root privileges. Run with: sudo make test-integration"; \
		exit 1; \
	fi
	@if ! command -v wg >/dev/null 2>&1; then \
		echo "WireGuard tools not found. Please install wireguard-tools."; \
		exit 1; \
	fi
	go test -v ./test/

test-connectivity: ## Run only connectivity tests (requires root)
	@echo "Running connectivity tests..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Connectivity tests require root privileges. Run with: sudo make test-connectivity"; \
		exit 1; \
	fi
	go test -v ./test/ -run TestIntegration_PeerToPeerConnectivity

test-validation: ## Run validation tests (no root required)
	@echo "Running validation tests..."
	go test -v ./test/ -run TestIntegration_ConfigValidation

test-cleanup: ## Run cleanup tests (requires root)
	@echo "Running cleanup tests..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Cleanup tests require root privileges. Run with: sudo make test-cleanup"; \
		exit 1; \
	fi
	go test -v ./test/ -run TestIntegration_CleanupScenarios

# Development targets
lint: ## Run linter
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		go vet ./...; \
	fi

fmt: ## Format code
	go fmt ./...

deps: ## Download dependencies
	go mod download
	go mod tidy

# Installation targets
install: build ## Install binary to /usr/local/bin
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Installation requires root privileges. Run with: sudo make install"; \
		exit 1; \
	fi
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	chmod +x /usr/local/bin/$(BINARY_NAME)

uninstall: ## Remove binary from /usr/local/bin
	@echo "Removing $(BINARY_NAME) from /usr/local/bin..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Uninstallation requires root privileges. Run with: sudo make uninstall"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/$(BINARY_NAME)

# Cleanup targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean

clean-test: ## Clean test artifacts and interfaces
	@echo "Cleaning test artifacts..."
	@if [ "$$(id -u)" = "0" ]; then \
		echo "Cleaning test WireGuard interfaces..."; \
		case "$$(uname -s)" in \
		Linux) \
			ip link delete wg-test1 2>/dev/null || true; \
			ip link delete wg-test2 2>/dev/null || true; \
			;; \
		Darwin) \
			rm -f /var/run/wireguard/wg-test*.sock 2>/dev/null || true; \
			rm -f /var/run/wireguard/wg-test*.name 2>/dev/null || true; \
			;; \
		*) \
			ifconfig wg-test1 destroy 2>/dev/null || true; \
			ifconfig wg-test2 destroy 2>/dev/null || true; \
			;; \
		esac; \
		rm -rf /tmp/wg-*test*; \
	else \
		echo "Root privileges required for interface cleanup. Run: sudo make clean-test"; \
	fi

# Platform-specific targets
check-linux: ## Check Linux-specific requirements
	@echo "Checking Linux requirements..."
	@command -v ip >/dev/null 2>&1 || (echo "ip command not found" && exit 1)
	@command -v wg >/dev/null 2>&1 || (echo "wg command not found" && exit 1)
	@if [ -f /proc/modules ]; then \
		if ! lsmod | grep -q wireguard; then \
			echo "WireGuard kernel module not loaded. Checking for userspace..."; \
			command -v wireguard-go >/dev/null 2>&1 || (echo "Neither kernel module nor userspace implementation found" && exit 1); \
		fi; \
	fi
	@echo "Linux requirements satisfied"

check-macos: ## Check macOS-specific requirements
	@echo "Checking macOS requirements..."
	@command -v ifconfig >/dev/null 2>&1 || (echo "ifconfig command not found" && exit 1)
	@command -v route >/dev/null 2>&1 || (echo "route command not found" && exit 1)
	@command -v networksetup >/dev/null 2>&1 || (echo "networksetup command not found" && exit 1)
	@command -v wg >/dev/null 2>&1 || (echo "wg command not found" && exit 1)
	@command -v wireguard-go >/dev/null 2>&1 || (echo "wireguard-go not found" && exit 1)
	@echo "macOS requirements satisfied"

check-freebsd: ## Check FreeBSD-specific requirements
	@echo "Checking FreeBSD requirements..."
	@command -v ifconfig >/dev/null 2>&1 || (echo "ifconfig command not found" && exit 1)
	@command -v route >/dev/null 2>&1 || (echo "route command not found" && exit 1)
	@command -v wg >/dev/null 2>&1 || (echo "wg command not found" && exit 1)
	@echo "FreeBSD requirements satisfied"

check-openbsd: ## Check OpenBSD-specific requirements
	@echo "Checking OpenBSD requirements..."
	@command -v ifconfig >/dev/null 2>&1 || (echo "ifconfig command not found" && exit 1)
	@command -v route >/dev/null 2>&1 || (echo "route command not found" && exit 1)
	@command -v wg >/dev/null 2>&1 || (echo "wg command not found" && exit 1)
	@command -v wireguard-go >/dev/null 2>&1 || (echo "wireguard-go not found" && exit 1)
	@echo "OpenBSD requirements satisfied"

# Example usage targets
demo: build ## Run a demo configuration (requires root)
	@echo "Running demo..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Demo requires root privileges. Run with: sudo make demo"; \
		exit 1; \
	fi
	@if [ ! -f example.conf ]; then \
		echo "Creating example configuration..."; \
		echo "[Interface]" > example.conf; \
		echo "PrivateKey = $$(wg genkey)" >> example.conf; \
		echo "Address = 10.0.0.1/24" >> example.conf; \
		echo "ListenPort = 51820" >> example.conf; \
		chmod 600 example.conf; \
		echo "Created example.conf"; \
	fi
	./$(BUILD_DIR)/$(BINARY_NAME) up example.conf
	@echo "Demo interface created. Use 'sudo make demo-down' to remove."

demo-down: ## Bring down demo configuration
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Demo cleanup requires root privileges. Run with: sudo make demo-down"; \
		exit 1; \
	fi
	./$(BUILD_DIR)/$(BINARY_NAME) down example.conf || true
	rm -f example.conf

# Release targets
release: clean build-all ## Create release artifacts
	@echo "Creating release..."
	@mkdir -p $(BUILD_DIR)/release
	@for binary in $(BUILD_DIR)/$(BINARY_NAME)-*; do \
		if [ -f "$$binary" ]; then \
			platform=$$(basename "$$binary" | sed 's/$(BINARY_NAME)-//'); \
			tar -czf "$(BUILD_DIR)/release/$(BINARY_NAME)-$(VERSION)-$$platform.tar.gz" -C $(BUILD_DIR) "$$(basename "$$binary")"; \
		fi; \
	done
	@echo "Release artifacts created in $(BUILD_DIR)/release/"

# Development helpers
dev-setup: ## Set up development environment
	@echo "Setting up development environment..."
	go mod download
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "Development environment ready"

# Show system info
info: ## Show system and build information
	@echo "System Information:"
	@echo "  OS: $$(uname -s)"
	@echo "  Architecture: $$(uname -m)"
	@echo "  Go version: $$(go version)"
	@echo "  Git version: $(VERSION)"
	@echo ""
	@echo "WireGuard Tools:"
	@echo "  wg: $$(command -v wg 2>/dev/null || echo 'not found')"
	@echo "  wireguard-go: $$(command -v wireguard-go 2>/dev/null || echo 'not found')"
	@echo ""
	@echo "Platform Tools:"
	@if [ "$$(uname -s)" = "Linux" ]; then \
		echo "  ip: $$(command -v ip 2>/dev/null || echo 'not found')"; \
		echo "  iptables: $$(command -v iptables 2>/dev/null || echo 'not found')"; \
		echo "  nftables: $$(command -v nft 2>/dev/null || echo 'not found')"; \
	elif [ "$$(uname -s)" = "Darwin" ]; then \
		echo "  ifconfig: $$(command -v ifconfig 2>/dev/null || echo 'not found')"; \
		echo "  route: $$(command -v route 2>/dev/null || echo 'not found')"; \
		echo "  networksetup: $$(command -v networksetup 2>/dev/null || echo 'not found')"; \
	else \
		echo "  ifconfig: $$(command -v ifconfig 2>/dev/null || echo 'not found')"; \
		echo "  route: $$(command -v route 2>/dev/null || echo 'not found')"; \
	fi
