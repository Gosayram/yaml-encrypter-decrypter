# Ensure the output directory exists
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

### Build
.PHONY: default ci-test ci-lint ci-build ci-package ci-all release-snapshot changelog tag push-tag release
default: fmt vet lint staticcheck build quicktest check-config ## Run formatting, checks, build, quick tests, and config validation

### CI
ci-test: ## Run CI tests with race detector and coverage
	@echo "Running CI tests (race + coverage)..."
	go test -v -race -coverprofile=coverage.out ./...

ci-lint: lint staticcheck ## Run CI lint stage
	@echo "CI lint stage completed."

ci-build: build-cross ## Run CI build stage
	@echo "CI build stage completed."

ci-package: ci-build ## Generate checksums for build artifacts
	@echo "Generating checksums for build artifacts..."
	@shasum -a 256 $(OUTPUT_DIR)/* > checksums.txt
	@echo "Checksums generated: checksums.txt"

ci-all: ci-lint ci-test ci-package ## Run all CI stages locally
	@echo "All CI stages completed successfully."

### GitHub Actions
.PHONY: update-github-actions check-github-actions check-github-actions-debug

update-github-actions: ## Update GitHub Actions dependencies to latest commit SHAs
	@echo "Updating GitHub Actions dependencies..."
	@python3 scripts/update-github-actions.py
	@echo "GitHub Actions dependencies updated."

check-github-actions: ## Check for GitHub Actions updates without modifying files
	@echo "Checking GitHub Actions for updates..."
	@python3 scripts/update-github-actions.py --check

check-github-actions-debug: ## Check for GitHub Actions updates with debug output
	@echo "Checking GitHub Actions for updates (debug mode)..."
	@python3 scripts/update-github-actions.py --check --debug

### Release
release-snapshot: ## Build snapshot release with GoReleaser
	@echo "Running GoReleaser snapshot build..."
	@RELEASE_VERSION=$(VERSION) goreleaser release --snapshot --clean

changelog: ## Generate changelog from git history
	@./hack/generate-changelog.sh

tag: ## Create annotated git tag from VERSION file
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "Error: $(VERSION_FILE) not found"; \
		exit 1; \
	fi
	@if git rev-parse "$(TAG_NAME)" >/dev/null 2>&1; then \
		echo "Error: tag $(TAG_NAME) already exists"; \
		exit 1; \
	fi
	git tag -a "$(TAG_NAME)" -m "Release $(TAG_NAME)"
	@echo "Created tag $(TAG_NAME)"

push-tag: tag ## Push created git tag to origin
	git push origin "$(TAG_NAME)"
	@echo "Pushed tag $(TAG_NAME)"

release: push-tag ## Create and push release tag
	@echo "Release $(TAG_NAME) created and pushed."

### Build
.PHONY: run
run: ## Run the application locally
	@echo "Running $(BINARY_NAME)..."
	go run main.go

### Dependencies
.PHONY: install-deps
install-deps: ## Tidy modules and vendor dependencies
	@echo "Installing dependencies..."
	go mod tidy
	go mod vendor

# Upgrade all project dependencies to their latest versions
.PHONY: upgrade-deps
upgrade-deps: ## Upgrade Go dependencies, tidy and vendor
	@echo "Upgrading all dependencies to latest versions..."
	go get -u ./...
	go mod tidy
	go mod vendor
	@echo "Dependencies upgraded. Please test thoroughly before committing!"

# Clean up dependencies
.PHONY: clean-deps
clean-deps: ## Remove vendored dependencies directory
	@echo "Cleaning up vendor dependencies..."
	rm -rf vendor

### Build
.PHONY: build
build: $(OUTPUT_DIR) ## Build binary for current OS/ARCH
	@echo "Building $(BINARY_NAME) with version $(VERSION)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Build binaries for multiple platforms
.PHONY: build-cross
build-cross: $(OUTPUT_DIR) ## Build binaries for Linux, macOS, and Windows
	@echo "Building cross-platform binaries..."
	GOOS=linux   GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	@echo "Cross-platform binaries are available in $(OUTPUT_DIR):"
	@ls -1 $(OUTPUT_DIR)

# Clean build artifacts
.PHONY: clean
clean: ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)

### Benchmark
.PHONY: benchmark benchmark-all benchmark-encryption benchmark-argon2 benchmark-long

# Run all basic benchmarks
benchmark: ## Run basic benchmarks for encryption package
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./pkg/encryption

# Run comprehensive benchmarks with longer duration (5s per benchmark)
benchmark-long: ## Run extended benchmark suite (benchtime=5s)
	@echo "Running comprehensive benchmarks (longer duration)..."
	go test -v -bench=. -benchmem -benchtime=5s ./pkg/encryption

# Run only encryption/decryption benchmarks
benchmark-encryption: ## Run only encryption/decryption benchmarks
	@echo "Running encryption/decryption benchmarks..."
	go test -v -bench="BenchmarkEncrypt|BenchmarkDecrypt|BenchmarkEncryptionWithAlgorithms|BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption

# Run key derivation algorithm comparison benchmarks
benchmark-algorithms: ## Compare key-derivation algorithms
	@echo "Running key derivation algorithm benchmarks..."
	go test -v -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption

# Run Argon2 configuration comparison benchmarks
benchmark-argon2: ## Compare Argon2 configurations
	@echo "Running Argon2 configuration benchmarks..."
	go test -v -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption

# Keep long report-generation recipe separate for maintainability.
include make/benchmark-report.mk

# Keep testing targets separate for maintainability.
include make/testing.mk

# Keep lint/quality targets separate for maintainability.
include make/lint.mk

### Docker
.PHONY: build-image run-image

build-image: ## Build Docker image tagged with TAG_NAME
	docker build \
	-t yed:$(TAG_NAME) \
	-f Dockerfile .
	@echo "Image built successfully."

run-image: ## Run built Docker image interactively
	docker run -it --rm yed:$(TAG_NAME)
	@echo "Image run successfully."
