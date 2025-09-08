.PHONY: build test clean install

BINARY_NAME=process-throttler
BUILD_DIR=build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/process-throttler

test:
	@echo "Running tests..."
	@go test -v ./...

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)

install: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

run: build
	@$(BUILD_DIR)/$(BINARY_NAME)

deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go mod download

lint:
	@echo "Running linter..."
	@golangci-lint run

format:
	@echo "Formatting code..."
	@go fmt ./...
