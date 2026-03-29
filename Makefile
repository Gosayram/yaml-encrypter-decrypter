# Project-specific variables
BINARY_NAME := yed
OUTPUT_DIR := bin
CMD_DIR := cmd/yaml-encrypter-decrypter
VERSION_FILE := .release-version
VERSION := $(shell if [ -f $(VERSION_FILE) ]; then head -n 1 $(VERSION_FILE) | tr -d '[:space:]'; else echo "v0.0.0"; fi)
TAG_NAME ?= $(VERSION)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X 'main.Version=$(VERSION)' -s -w
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_FILES := $(wildcard $(CMD_DIR)/*.go)

# Tooling versions (pinned for reproducible CI/local checks)
GOLANGCI_LINT_VERSION ?= v2.11.4
STATICCHECK_VERSION ?= v0.7.0

# Ensure the output directory exists
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Default target
.PHONY: default ci-test ci-lint ci-build ci-package ci-all release-snapshot changelog tag push-tag release
default: fmt vet lint staticcheck build quicktest check-config

# Modern CI targets inspired by openkms pipeline style
ci-test:
	@echo "Running CI tests (race + coverage)..."
	go test -v -race -coverprofile=coverage.out ./...

ci-lint: lint staticcheck
	@echo "CI lint stage completed."

ci-build: build-cross
	@echo "CI build stage completed."

ci-package: ci-build
	@echo "Generating checksums for build artifacts..."
	@shasum -a 256 $(OUTPUT_DIR)/* > checksums.txt
	@echo "Checksums generated: checksums.txt"

ci-all: ci-lint ci-test ci-package
	@echo "All CI stages completed successfully."

release-snapshot:
	@echo "Running GoReleaser snapshot build..."
	@RELEASE_VERSION=$(VERSION) goreleaser release --snapshot --clean

changelog:
	@./hack/generate-changelog.sh

tag:
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

push-tag: tag
	git push origin "$(TAG_NAME)"
	@echo "Pushed tag $(TAG_NAME)"

release: push-tag
	@echo "Release $(TAG_NAME) created and pushed."

# Build and run the application locally
.PHONY: run
run:
	@echo "Running $(BINARY_NAME)..."
	go run main.go

# Run all tests with coverage and race detection
.PHONY: test-with-race
test-with-race:
	@echo "Running all tests with race detection and coverage..."
	go test -v -race -cover ./...

# Run all tests with basic testing
.PHONY: test
test: lint
	go test -v ./... -cover

# Manual testing target
.PHONY: test-manual
test-manual: build test-manual-check-original

# Original manual testing target
.PHONY: test-manual-check-original
test-manual-check-original:
	@echo "Running manual tests for cert-test.yml..."
	@echo "Creating a copy of the test file for safe testing..."
	@cp -f .test/cert-test.yml .test/cert-test-copy.yml
	@cp -f .test/variables.yml .test/variables-copy.yml
	@cp -f .test/variables.yml .test/variables-pb-copy.yml
	@cp -f .test/variables.yml .test/variables-pb2-copy.yml
	@echo "Step 1: Testing with dry-run mode on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=encrypt
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --config=.test/.yed_config.yml --file=.test/variables-copy.yml --operation=encrypt
	@echo "Step 2: Testing in debug mode without dry-run on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=encrypt
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/variables-copy.yml --operation=encrypt
	@echo "Step 3: Testing decrypt operation on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=decrypt
	@echo "Step 4: Testing with PBKDF algorithm on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/variables-pb-copy.yml --operation=encrypt --algorithm=pbkdf2-sha256
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/variables-pb2-copy.yml --operation=encrypt --algorithm=pbkdf2-sha512
	@echo "Tests completed."

# Install project dependencies
.PHONY: install-deps
install-deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod vendor

# Upgrade all project dependencies to their latest versions
.PHONY: upgrade-deps
upgrade-deps:
	@echo "Upgrading all dependencies to latest versions..."
	go get -u ./...
	go mod tidy
	go mod vendor
	@echo "Dependencies upgraded. Please test thoroughly before committing!"

# Clean up dependencies
.PHONY: clean-deps
clean-deps:
	@echo "Cleaning up vendor dependencies..."
	rm -rf vendor

# Build the project for the current OS/architecture
.PHONY: build
build: $(OUTPUT_DIR)
	@echo "Building $(BINARY_NAME) with version $(VERSION)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Build binaries for multiple platforms
.PHONY: build-cross
build-cross: $(OUTPUT_DIR)
	@echo "Building cross-platform binaries..."
	GOOS=linux   GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="$(LDFLAGS)" -trimpath -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	@echo "Cross-platform binaries are available in $(OUTPUT_DIR):"
	@ls -1 $(OUTPUT_DIR)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)

# Run quick tests without additional checks
.PHONY: quicktest
quicktest:
	@echo "Running quick tests..."
	go test ./...

# Run tests with coverage report
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage report..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	go test -v -race ./...

# Benchmark targets
.PHONY: benchmark benchmark-all benchmark-encryption benchmark-argon2 benchmark-long

# Run all basic benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./pkg/encryption

# Run comprehensive benchmarks with longer duration (5s per benchmark)
benchmark-long:
	@echo "Running comprehensive benchmarks (longer duration)..."
	go test -v -bench=. -benchmem -benchtime=5s ./pkg/encryption

# Run only encryption/decryption benchmarks
benchmark-encryption:
	@echo "Running encryption/decryption benchmarks..."
	go test -v -bench="BenchmarkEncrypt|BenchmarkDecrypt|BenchmarkEncryptionWithAlgorithms|BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption

# Run key derivation algorithm comparison benchmarks
benchmark-algorithms:
	@echo "Running key derivation algorithm benchmarks..."
	go test -v -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption

# Run Argon2 configuration comparison benchmarks
benchmark-argon2:
	@echo "Running Argon2 configuration benchmarks..."
	go test -v -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption

# Generate a benchmark report in Markdown format
benchmark-report:
	@echo "Generating benchmark report..."
	@echo "# Benchmark Results" > benchmark-report.md
	@echo "\nGenerated on \`$$(date)\`\n" >> benchmark-report.md
	
	@echo "## Key Derivation Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | grep -v "\[DEBUG" | sed 's/BenchmarkKeyDerivationAlgorithms\///g' | sed 's/\-[0-9]*//g' | sed 's/PBKDF2SHA256/pbkdf2sha256/g' | sed 's/PBKDF2SHA512/pbkdf2sha512/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Argon2 Configurations" >> benchmark-report.md
	@echo "| Configuration | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|--------------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption 2>/dev/null | grep "Benchmark" | grep -v "\[DEBUG" | sed 's/BenchmarkArgon2Configs\///g' | sed 's/\-[0-9]*//g' | sed 's/OWASPcurrent/OWASP-1-current/g' | sed 's/OWASP-2-12/OWASP-2/g' | sed 's/OWASP-3-12/OWASP-3/g' | sed 's/PreviousConfig/Previous-Config/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Basic Encryption and Decryption" >> benchmark-report.md
	@echo "| Operation | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Directly extract results from test benchmarks and format them properly
	@go test -bench="^BenchmarkEncrypt$$" -benchmem ./pkg/encryption 2>/dev/null | grep -v "\[DEBUG" | grep "BenchmarkEncrypt-" | awk '{print "| Encrypt | " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " | " $$8 " " $$9 " |"}' >> benchmark-report.md
	@go test -bench="^BenchmarkDecrypt$$" -benchmem ./pkg/encryption 2>/dev/null | grep -v "\[DEBUG" | grep "BenchmarkDecrypt-" | awk '{print "| Decrypt | " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " | " $$8 " " $$9 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Encryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Create a temporary file for results
	@go test -bench="BenchmarkEncryptionWithAlgorithms/" -benchmem ./pkg/encryption 2>/dev/null > tmp_bench_encrypt.txt
	@# Extract results for argon2id
	@cat tmp_bench_encrypt.txt | grep "BenchmarkEncryptionWithAlgorithms/argon2id" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(argon2id\)[^ ]*/\1/' | awk '{print "| argon2id | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha256
	@cat tmp_bench_encrypt.txt | grep "BenchmarkEncryptionWithAlgorithms/pbkdf2-sha256" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(pbkdf2-sha256\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha256 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha512
	@cat tmp_bench_encrypt.txt | grep "BenchmarkEncryptionWithAlgorithms/pbkdf2-sha512" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(pbkdf2-sha512\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha512 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@rm tmp_bench_encrypt.txt
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Create a temporary file for results
	@go test -bench="BenchmarkDecryptionWithAlgorithms/" -benchmem ./pkg/encryption 2>/dev/null > tmp_bench_decrypt.txt
	@# Extract results for argon2id
	@cat tmp_bench_decrypt.txt | grep "BenchmarkDecryptionWithAlgorithms/argon2id" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(argon2id\)[^ ]*/\1/' | awk '{print "| argon2id | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha256
	@cat tmp_bench_decrypt.txt | grep "BenchmarkDecryptionWithAlgorithms/pbkdf2-sha256" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(pbkdf2-sha256\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha256 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha512
	@cat tmp_bench_decrypt.txt | grep "BenchmarkDecryptionWithAlgorithms/pbkdf2-sha512" | grep -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(pbkdf2-sha512\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha512 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@rm tmp_bench_decrypt.txt
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption Algorithm Failures" >> benchmark-report.md
	@echo "| Algorithm | Status | Error |" >> benchmark-report.md
	@echo "|-----------|--------|-------|" >> benchmark-report.md
	@go test -bench="BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption 2>&1 | grep "benchmark_test.go" | grep -A1 "failed:" | sed 's/.*Decryption with \(.*\) failed: \(.*\)/| \1 | Failed | \2 |/g' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "Benchmark report generated: benchmark-report.md"

# Run all benchmarks and tests
.PHONY: test-all
test-all: test-coverage test-race benchmark

# Clean coverage files
.PHONY: clean-coverage
clean-coverage:
	@echo "Cleaning coverage files..."
	rm -f coverage.out coverage.html benchmark-report.md

# Check formatting of Go code
.PHONY: fmt
fmt:
	@echo "Checking code formatting..."
	@echo "Formatting pkg directory..."
	@go fmt -x ./pkg/...
	@echo "Formatting cmd directory..."
	@go fmt -x ./cmd/...

# Run go vet to analyze code
.PHONY: vet
vet:
	@echo "Running go vet..."
	go vet ./...

.PHONY: test lint lint-fix install-lint

# Install golangci-lint
install-lint:
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Install staticcheck
.PHONY: install-staticcheck
install-staticcheck:
	@echo "Installing staticcheck $(STATICCHECK_VERSION)..."
	@go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

# Run linter
lint:
	@echo "Running linter..."
	@~/go/bin/golangci-lint run ./...

# Run staticcheck tool
.PHONY: staticcheck
staticcheck:
	@echo "Running staticcheck..."
	@~/go/bin/staticcheck ./...
	@echo "Staticcheck passed!"

# Check rule configurations by validating against config files
.PHONY: check-config
check-config: build prepare-test-examples
	@echo "Validating configuration..."
	@# Test main configuration
	@echo "=== Testing main configuration ==="
	$(OUTPUT_DIR)/$(BINARY_NAME) -validate -debug
	@# Test with custom rules in test directory
	@echo "=== Testing rules in .test directory ==="
	$(OUTPUT_DIR)/$(BINARY_NAME) -validate -config .test/.yed_config.yml -debug
	@# Test with invalid config
	@echo "=== Testing invalid configuration ==="
	@echo "encryption:\n  rules:\n    - name: \"invalid_rule\"\n      pattern: \"test\"\n      # Missing block field\n      description: \"This rule is invalid\"" > .test/invalid_config.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) -validate -config .test/invalid_config.yml -debug || echo "Validation correctly failed for invalid configuration (as expected)"
	@rm -f .test/invalid_config.yml
	@# Test with no rules
	@echo "=== Testing configuration with no rules ==="
	@echo "encryption:\n  unsecure_diff: true\n  validate_rules: true" > .test/empty_rules_config.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) -validate -config .test/empty_rules_config.yml -debug
	@rm -f .test/empty_rules_config.yml
	@# Test with non-existent config
	@echo "=== Testing non-existent config ==="
	$(OUTPUT_DIR)/$(BINARY_NAME) -validate -config .test/non_existent_config.yml -debug || echo "Validation correctly failed for non-existent file (as expected)"
	@echo "Configuration validation completed"

# Test rules against example files (without modifying original files)
.PHONY: check-rules
check-rules: build prepare-test-examples
	@echo "Testing encryption rules against example files..."
	@echo "==== Database rules ===="
	@cp -f .test/examples/database_example.yml .test/examples/database_example_copy.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --debug --config=.test/.yed_config.yml --file=.test/examples/database_example_copy.yml --operation=encrypt
	@echo "\n==== API rules ===="
	@cp -f .test/examples/api_example.yml .test/examples/api_example_copy.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --debug --config=.test/.yed_config.yml --file=.test/examples/api_example_copy.yml --operation=encrypt
	@echo "\n==== AWS rules ===="
	@cp -f .test/examples/aws_example.yml .test/examples/aws_example_copy.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --debug --config=.test/.yed_config.yml --file=.test/examples/aws_example_copy.yml --operation=encrypt
	@echo "\n==== Secrets rules ===="
	@cp -f .test/examples/secrets_example.yml .test/examples/secrets_example_copy.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --debug --config=.test/.yed_config.yml --file=.test/examples/secrets_example_copy.yml --operation=encrypt
	@echo "\nAll rule tests completed"
	@echo "Cleaning up test files..."
	@rm -f .test/examples/*_copy.yml
	@echo "Done"

# Prepare test directory and example files
.PHONY: prepare-test-examples
prepare-test-examples:
	@echo "Preparing test examples..."
	@mkdir -p .test/examples
	@# Check if example files exist, if not create them
	@if [ ! -f .test/examples/database_example.yml ]; then \
		echo "Creating database example file..."; \
		touch .test/examples/database_example.yml; \
	fi
	@if [ ! -f .test/examples/api_example.yml ]; then \
		echo "Creating API example file..."; \
		touch .test/examples/api_example.yml; \
	fi
	@if [ ! -f .test/examples/aws_example.yml ]; then \
		echo "Creating AWS example file..."; \
		touch .test/examples/aws_example.yml; \
	fi
	@if [ ! -f .test/examples/secrets_example.yml ]; then \
		echo "Creating secrets example file..."; \
		touch .test/examples/secrets_example.yml; \
	fi

# Test all rule configurations together
.PHONY: test-rules
test-rules: check-config check-rules

# Run all checks (linter and staticcheck)
.PHONY: check-all
check-all: lint staticcheck
	@echo "All checks completed."

# Run linter with auto-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	@~/go/bin/golangci-lint run --fix ./...

# Build and run the application in a container
.PHONY: build-image run-image

build-image:
	docker build \
	-t yed:$(TAG_NAME) \
	-f Dockerfile .
	@echo "Image built successfully."

run-image:
	docker run -it --rm yed:$(TAG_NAME)
	@echo "Image run successfully."

# Testing targets
test-conflicts-detection: build
	@echo "Testing rule conflicts detection..."
	@if ./bin/yed --dry-run --config=.test/.yed_config.yml --file=.test/cert-test.yml --include-rules=conflicts1.yml,conflicts2.yml --operation=encrypt 2>&1 | grep -q "rule conflict detected"; then \
		echo "✅ Conflict detected as expected"; \
	else \
		echo "❌ Error: Conflict was not detected"; \
		exit 1; \
	fi

custom-test-manual: build
	@echo "Running manual tests for cert-test.yml..."
	@echo "Creating a copy of the test file for safe testing..."
	@cp .test/cert-test.yml .test/cert-test-copy.yml
	@echo "Step 1: Testing with dry-run mode on the copy..."
	bin/yed --dry-run --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=encrypt

# Run the application in manual check mode
.PHONY: test-manual-check
test-manual-check: build
	@cp .test/variables.yml .test/variables-copy.yml
	@cp .test/variables.yml .test/variables-pb-copy.yml
	@cp .test/variables.yml .test/variables-pb2-copy.yml
	bin/yed --debug --config=.test/.yed_config.yml --file=.test/variables-pb2-copy.yml --operation=encrypt --algorithm=pbkdf2-sha512

# Check all rule configurations and conflicts
.PHONY: check-all-rules
check-all-rules: check-config check-rules test-conflicts-detection

# Display help information
.PHONY: help
help:
	@echo "YAML Encrypter/Decrypter (yed) - Tool for encrypting and decrypting YAML files"
	@echo ""
	@echo "Available targets:"
	@echo "  Building and Running:"
	@echo "  ===================="
	@echo "  default         		- Run formatting, vetting, linting, staticcheck, build, quick tests, and config validation"
	@echo "  run             		- Run the application locally"
	@echo "  build           		- Build the application for the current OS/architecture"
	@echo "  build-cross     		- Build binaries for multiple platforms (Linux, macOS, Windows)"
	@echo "  build-image     		- Build Docker image"
	@echo "  run-image       		- Run Docker image with --version flag"
	@echo ""
	@echo "  Testing and Validation:"
	@echo "  ======================"
	@echo "  test            		- Run all tests with standard coverage"
	@echo "  test-with-race  		- Run all tests with race detection and coverage"
	@echo "  quicktest       		- Run quick tests without additional checks"
	@echo "  test-coverage   		- Run tests with coverage report"
	@echo "  test-race       		- Run tests with race detection"
	@echo "  test-manual    		- Run manual tests using test files"
	@echo "  custom-test-manual		- Run simplified manual tests for cert-test.yml"
	@echo "  test-manual-check		- Run manual check for variables.yml with encryption"
	@echo "  test-conflicts-detection	- Test rule conflicts detection mechanism"
	@echo "  test-all        		- Run all tests and benchmarks"
	@echo "  check-config    		- Validate configuration files and rule definitions"
	@echo "  check-rules     		- Test encryption rules against example files (non-destructive)"
	@echo "  check-all-rules 		- Run config check, rules check and conflicts detection"
	@echo "  test-rules      		- Run both check-config and check-rules"
	@echo "  prepare-test-examples  	- Prepare test example files in .test/examples directory"
	@echo ""
	@echo "  Benchmarking:"
	@echo "  ============="
	@echo "  benchmark       		- Run basic benchmarks"
	@echo "  benchmark-long  		- Run comprehensive benchmarks with longer duration"
	@echo "  benchmark-encryption 		- Run only encryption/decryption benchmarks"
	@echo "  benchmark-algorithms 		- Run key derivation algorithm comparison benchmarks"
	@echo "  benchmark-argon2 		- Run Argon2 configuration comparison benchmarks"
	@echo "  benchmark-report 		- Generate a markdown report of all benchmarks"
	@echo ""
	@echo "  Code Quality:"
	@echo "  ============"
	@echo "  fmt             		- Check and format code"
	@echo "  vet             		- Analyze code with go vet"
	@echo "  lint            		- Run golangci-lint on the codebase"
	@echo "  lint-fix        		- Run golangci-lint with auto-fix"
	@echo "  staticcheck     		- Run staticcheck static analyzer on the codebase"
	@echo "  check-all       		- Run all code quality checks (lint and staticcheck)"
	@echo ""
	@echo "  Dependencies:"
	@echo "  ============="
	@echo "  install-deps    		- Install project dependencies"
	@echo "  upgrade-deps    		- Upgrade all project dependencies to their latest versions"
	@echo "  clean-deps      		- Clean up vendor dependencies"
	@echo "  install-lint    		- Install golangci-lint"
	@echo "  install-staticcheck 		- Install staticcheck"
	@echo ""
	@echo "  Cleanup:"
	@echo "  ========"
	@echo "  clean           		- Clean build artifacts"
	@echo "  clean-coverage  		- Clean coverage and benchmark files"
	@echo ""
	@echo "Examples:"
	@echo "  make build               	- Build the binary"
	@echo "  make check-config        	- Validate configuration and rules"
	@echo "  make check-rules         	- Test encryption rules against example files"
	@echo "  make check-all-rules     	- Run all rule validation tests including conflict detection"
	@echo "  make test                	- Run all tests"
	@echo "  make build-cross         	- Build for multiple platforms"
	@echo ""
	@echo "For CLI usage instructions, run: ./bin/yed --help"
