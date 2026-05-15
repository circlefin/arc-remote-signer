# Configuration
SCRIPTS := ./scripts
ENCLAVE_NAME := nitro-enclave-signer-internal

.DEFAULT_GOAL := help
.PHONY: proto build local-enclave-docker test test-it test-all smoke test-reproducibility dev up down help

#------------------------------------------------------------------------------
# Build
#------------------------------------------------------------------------------

proto: ## Generate protocol buffers
	@cd proto && $(MAKE) proto

build: proto ## Build application binary
	@$(SCRIPTS)/build.sh

local-enclave-docker: build ## Build local enclave docker image
	@docker buildx bake --set "*.tags=$(ENCLAVE_NAME):local" signer

#------------------------------------------------------------------------------
# Test
#------------------------------------------------------------------------------

test: build ## Run unit tests and linting
	@$(SCRIPTS)/test.sh

test-it: up ## Run integration tests
	@RUN_IT_TESTS=true $(SCRIPTS)/test.sh

test-all: test-it smoke ## Run all tests

smoke: up ## Run smoke tests only
	@$(SCRIPTS)/smoke.sh

test-reproducibility: ## Verify enclave build reproducibility
	@$(SCRIPTS)/test-build-enclave.sh

#------------------------------------------------------------------------------
# Development
#------------------------------------------------------------------------------

dev: up ## Start local development
	@$(SCRIPTS)/dev.sh

up: local-enclave-docker ## Start dependencies
	@$(SCRIPTS)/up.sh

down: ## Stop dependencies
	@$(SCRIPTS)/down.sh

#------------------------------------------------------------------------------
# Help
#------------------------------------------------------------------------------

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
