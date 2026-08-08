.PHONY: build run clean test

OS := $(shell uname -s)
APP_EXECUTABLE = jwto
OUT_DIR = .out
OS ?= $(shell uname -s)
GOARCH ?= amd64

ifeq ($(OS),Darwin)
    GOOS := darwin
    EXECUTABLE := $(OUT_DIR)/$(APP_EXECUTABLE)
else ifeq ($(OS),Linux)
    GOOS := linux
    EXECUTABLE := $(OUT_DIR)/$(APP_EXECUTABLE)
else
    GOOS := windows
    EXECUTABLE := $(OUT_DIR)/$(APP_EXECUTABLE).exe
endif

$(shell if [ ! -d "$(OUT_DIR)" ]; then mkdir -p $(OUT_DIR); fi)

VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)

build:
	@echo "Building for $(OS) ($(GOOS)/$(GOARCH)) $(VERSION)"
	@mkdir -p $(OUT_DIR)
	GOARCH=$(GOARCH) GOOS=$(GOOS) go build -ldflags="-s -w -X main.version=$(VERSION)" -o $(EXECUTABLE) ./cmd/jwto

test:
	go vet ./...
	go test ./... -race -count=1

clean:
	@echo "Cleaning up"
	go clean
	rm -rf $(OUT_DIR)/$(APP_EXECUTABLE)*
