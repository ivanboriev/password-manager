BINARY_NAME=pm
BUILD_DIR=build

.PHONY: all build run clean fmt lint test

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/pm

run: build
	@./$(BUILD_DIR)/$(BINARY_NAME)

clean:
	@rm -rf $(BUILD_DIR)
	@rm -f passwords.dat

fmt:
	go fmt ./...

lint:
	go vet ./...
