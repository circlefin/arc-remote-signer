PROTOC_GO_VERSION=v1.36.6
PROTOC_GRPC_GO_VERSION=v1.5.1
BUF_VERSION=v1.50.0
GO_BIN=$(shell go env GOPATH)/bin
BUF_BIN=$(shell command -v buf 2>/dev/null || echo "$(GO_BIN)/buf")

.PHONY: proto lint clean install-deps

install-deps:
	@command -v buf >/dev/null 2>&1 || go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GO_VERSION)
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GRPC_GO_VERSION)

# Generate protocol buffer code
proto: install-deps clean
	@echo "Generating protobuf code with buf..."
	@mkdir -p ./pb
	@PATH="$(GO_BIN):$$PATH" $(BUF_BIN) generate
	@echo "Done generating protobuf code"

# Lint protocol buffer definitions
lint: install-deps
	@echo "Linting protobuf definitions with buf..."
	@$(BUF_BIN) lint
	@echo "Done linting protobuf definitions"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -rf ./pb
	@echo "Done cleaning"
