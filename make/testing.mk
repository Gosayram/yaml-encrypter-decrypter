### Testing
.PHONY: test-with-race test test-manual test-manual-check-original quicktest test-coverage test-race test-all clean-coverage check-config check-rules prepare-test-examples test-rules test-conflicts-detection custom-test-manual test-manual-check check-all-rules

# Run all tests with coverage and race detection
test-with-race: ## Run all tests with race detection and coverage
	@echo "Running all tests with race detection and coverage..."
	go test -v -race -cover ./...

# Run all tests with basic testing
test: lint ## Run tests with coverage
	go test -v ./... -cover

# Manual testing target
test-manual: build test-manual-check-original ## Run manual test scenario

# Original manual testing target
test-manual-check-original: ## Run original manual checks on test fixtures
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

# Run quick tests without additional checks
quicktest: ## Run quick test suite
	@echo "Running quick tests..."
	go test ./...

# Run tests with coverage report
test-coverage: ## Run tests and generate HTML coverage report
	@echo "Running tests with coverage report..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with race detection
test-race: ## Run tests with race detector
	@echo "Running tests with race detection..."
	go test -v -race ./...

# Run all benchmarks and tests
test-all: test-coverage test-race benchmark ## Run coverage, race tests, and benchmarks

# Clean coverage files
clean-coverage: ## Remove coverage and benchmark report files
	@echo "Cleaning coverage files..."
	rm -f coverage.out coverage.html benchmark-report.md

# Check rule configurations by validating against config files
check-config: build prepare-test-examples ## Validate configuration files and rule definitions
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
check-rules: build prepare-test-examples ## Test rules against example YAML files (dry-run)
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
prepare-test-examples: ## Create example files under .test/examples when missing
	@echo "Preparing test examples..."
	@mkdir -p .test/examples
	@# Check if example files exist, if not create valid YAML fixtures
	@if [ ! -f .test/examples/database_example.yml ]; then \
		echo "Creating database example file..."; \
		printf '%s\n' \
			'database:' \
			'  host: localhost' \
			'  port: 5432' \
			'  username: admin' \
			'  password: supersecret' \
			> .test/examples/database_example.yml; \
	fi
	@if [ ! -f .test/examples/api_example.yml ]; then \
		echo "Creating API example file..."; \
		printf '%s\n' \
			'api:' \
			'  endpoint: https://api.example.com' \
			'  token: my-token' \
			'  timeout: 30' \
			> .test/examples/api_example.yml; \
	fi
	@if [ ! -f .test/examples/aws_example.yml ]; then \
		echo "Creating AWS example file..."; \
		printf '%s\n' \
			'aws:' \
			'  access_key_id: AKIAEXAMPLE' \
			'  secret_access_key: supersecret' \
			'  region: us-east-1' \
			> .test/examples/aws_example.yml; \
	fi
	@if [ ! -f .test/examples/secrets_example.yml ]; then \
		echo "Creating secrets example file..."; \
		printf '%s\n' \
			'secrets:' \
			'  database_password: supersecret' \
			'  api_key: abc123' \
			'  token: my-token' \
			> .test/examples/secrets_example.yml; \
	fi

# Test all rule configurations together
test-rules: check-config check-rules ## Run config validation and rules checks

test-conflicts-detection: build ## Verify rule conflict detection flow
	@echo "Testing rule conflicts detection..."
	@if $(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --config=.test/.yed_config.yml --file=.test/cert-test.yml --include-rules=conflicts1.yml,conflicts2.yml --operation=encrypt 2>&1 | rg -q "rule conflict detected"; then \
		echo "✅ Conflict detected as expected"; \
	else \
		echo "❌ Error: Conflict was not detected"; \
		exit 1; \
	fi

custom-test-manual: build ## Run simplified manual encryption test
	@echo "Running manual tests for cert-test.yml..."
	@echo "Creating a copy of the test file for safe testing..."
	@cp .test/cert-test.yml .test/cert-test-copy.yml
	@echo "Step 1: Testing with dry-run mode on the copy..."
	$(OUTPUT_DIR)/$(BINARY_NAME) --dry-run --config=.test/.yed_config.yml --file=.test/cert-test-copy.yml --operation=encrypt

# Run the application in manual check mode
test-manual-check: build ## Run manual variable encryption check
	@cp .test/variables.yml .test/variables-copy.yml
	@cp .test/variables.yml .test/variables-pb-copy.yml
	@cp .test/variables.yml .test/variables-pb2-copy.yml
	$(OUTPUT_DIR)/$(BINARY_NAME) --debug --config=.test/.yed_config.yml --file=.test/variables-pb2-copy.yml --operation=encrypt --algorithm=pbkdf2-sha512

# Check all rule configurations and conflicts
check-all-rules: check-config check-rules test-conflicts-detection ## Run all rule/config/conflict checks
