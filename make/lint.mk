### Quality
.PHONY: fmt vet lint lint-fix install-lint install-staticcheck staticcheck check-all

# Check formatting of Go code
fmt: ## Format Go source files in cmd and pkg
	@echo "Checking code formatting..."
	@echo "Formatting pkg directory..."
	@go fmt -x ./pkg/...
	@echo "Formatting cmd directory..."
	@go fmt -x ./cmd/...

vet: ## Run go vet checks
	@echo "Running go vet..."
	go vet ./...

# Install golangci-lint
install-lint: ## Install golangci-lint pinned version
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Install staticcheck
install-staticcheck: ## Install staticcheck pinned version
	@echo "Installing staticcheck $(STATICCHECK_VERSION)..."
	@go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

# Run linter
lint: ## Run golangci-lint across all packages
	@echo "Running linter..."
	@if [ ! -x "$(GOLANGCI_LINT_BIN)" ]; then \
		echo "golangci-lint not found, installing $(GOLANGCI_LINT_VERSION)..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi; \
	"$(GOLANGCI_LINT_BIN)" run ./...

# Run staticcheck tool
staticcheck: ## Run staticcheck across all packages
	@echo "Running staticcheck..."
	@if [ ! -x "$(STATICCHECK_BIN)" ]; then \
		echo "staticcheck not found, installing $(STATICCHECK_VERSION)..."; \
		go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION); \
	fi; \
	GOFLAGS="-buildvcs=false" "$(STATICCHECK_BIN)" ./...
	@echo "Staticcheck passed!"

# Run all checks (linter and staticcheck)
check-all: lint staticcheck ## Run all code quality checks
	@echo "All checks completed."

# Run linter with auto-fix
lint-fix: ## Run golangci-lint with auto-fixes
	@echo "Running linter with auto-fix..."
	@if [ ! -x "$(GOLANGCI_LINT_BIN)" ]; then \
		echo "golangci-lint not found, installing $(GOLANGCI_LINT_VERSION)..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi; \
	"$(GOLANGCI_LINT_BIN)" run --fix ./...
