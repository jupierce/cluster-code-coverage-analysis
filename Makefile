.PHONY: all build build-cli test clean help

# Default target
all: build

# Build everything
build: build-cli

# Build the CLI tool
build-cli:
	@echo "Building coverage-collector CLI tool..."
	@mkdir -p bin
	@go build -o bin/coverage-collector ./cmd/coverage-collector
	@echo "✅ Built: bin/coverage-collector"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -rf coverage-output/
	@echo "✅ Clean complete"

# Display help
help:
	@echo "Available targets:"
	@echo "  build-cli  - Build the coverage-collector CLI tool"
	@echo "  test       - Run all tests"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"
