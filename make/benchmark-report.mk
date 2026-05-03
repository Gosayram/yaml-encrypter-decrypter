### Benchmark
.PHONY: benchmark-report

# Generate a benchmark report in Markdown format
benchmark-report: ## Generate markdown benchmark report
	@echo "Generating benchmark report..."
	@command -v rg >/dev/null 2>&1 || { echo "Error: ripgrep (rg) is required for benchmark-report but not installed. Please install ripgrep to continue."; exit 1; }
	@echo "# Benchmark Results" > benchmark-report.md
	@printf '%s\n\n' "Generated on \`$$(date)\`" >> benchmark-report.md
	
	@echo "## Key Derivation Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=KeyDerivationAlgorithms -benchmem ./pkg/encryption 2>/dev/null | rg "Benchmark" | rg -v "\[DEBUG" | sed 's/BenchmarkKeyDerivationAlgorithms\///g' | sed 's/\-[0-9]*//g' | sed 's/PBKDF2SHA256/pbkdf2sha256/g' | sed 's/PBKDF2SHA512/pbkdf2sha512/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Argon2 Configurations" >> benchmark-report.md
	@echo "| Configuration | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|--------------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@go test -bench=BenchmarkArgon2Configs -benchmem ./pkg/encryption 2>/dev/null | rg "Benchmark" | rg -v "\[DEBUG" | sed 's/BenchmarkArgon2Configs\///g' | sed 's/\-[0-9]*//g' | sed 's/OWASPcurrent/OWASP-1-current/g' | sed 's/OWASP-2-12/OWASP-2/g' | sed 's/OWASP-3-12/OWASP-3/g' | sed 's/PreviousConfig/Previous-Config/g' | awk '{print "| " $$1 " | " $$2 " | " $$3 " " $$4 " | " $$5 " " $$6 " | " $$7 " " $$8 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Basic Encryption and Decryption" >> benchmark-report.md
	@echo "| Operation | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Directly extract results from test benchmarks and format them properly
	@go test -bench="^BenchmarkEncrypt$$" -benchmem ./pkg/encryption 2>/dev/null | rg -v "\[DEBUG" | rg "BenchmarkEncrypt-" | awk '{print "| Encrypt | " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " | " $$8 " " $$9 " |"}' >> benchmark-report.md
	@go test -bench="^BenchmarkDecrypt$$" -benchmem ./pkg/encryption 2>/dev/null | rg -v "\[DEBUG" | rg "BenchmarkDecrypt-" | awk '{print "| Decrypt | " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " | " $$8 " " $$9 " |"}' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "## Encryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Create a temporary file for results
	@go test -bench="BenchmarkEncryptionWithAlgorithms/" -benchmem ./pkg/encryption 2>/dev/null > tmp_bench_encrypt.txt
	@# Extract results for argon2id
	@cat tmp_bench_encrypt.txt | rg "BenchmarkEncryptionWithAlgorithms/argon2id" | rg -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(argon2id\)[^ ]*/\1/' | awk '{print "| argon2id | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha256
	@cat tmp_bench_encrypt.txt | rg "BenchmarkEncryptionWithAlgorithms/pbkdf2-sha256" | rg -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(pbkdf2-sha256\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha256 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha512
	@cat tmp_bench_encrypt.txt | rg "BenchmarkEncryptionWithAlgorithms/pbkdf2-sha512" | rg -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkEncryptionWithAlgorithms\/\(pbkdf2-sha512\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha512 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@rm tmp_bench_encrypt.txt
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption with Different Algorithms" >> benchmark-report.md
	@echo "| Algorithm | Operations/sec | Time (ns/op) | Memory (B/op) | Allocs/op |" >> benchmark-report.md
	@echo "|-----------|----------------|--------------|---------------|-----------|" >> benchmark-report.md
	@# Create a temporary file for results
	@go test -bench="BenchmarkDecryptionWithAlgorithms/" -benchmem ./pkg/encryption 2>/dev/null > tmp_bench_decrypt.txt
	@# Extract results for argon2id
	@cat tmp_bench_decrypt.txt | rg "BenchmarkDecryptionWithAlgorithms/argon2id" | rg -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(argon2id\)[^ ]*/\1/' | awk '{print "| argon2id | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha256
	@cat tmp_bench_decrypt.txt | rg "BenchmarkDecryptionWithAlgorithms/pbkdf2-sha256" | rg -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(pbkdf2-sha256\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha256 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@# Extract results for pbkdf2-sha512
	@cat tmp_bench_decrypt.txt | rg "BenchmarkDecryptionWithAlgorithms/pbkdf2-sha512" | rg -v "\[DEBUG" | tail -1 | sed 's/.*BenchmarkDecryptionWithAlgorithms\/\(pbkdf2-sha512\)[^ ]*/\1/' | awk '{print "| pbkdf2-sha512 | " $$1 " | " $$2 " " $$3 " | " $$4 " " $$5 " | " $$6 " " $$7 " |"}' >> benchmark-report.md
	@rm tmp_bench_decrypt.txt
	@echo "" >> benchmark-report.md
	
	@echo "## Decryption Algorithm Failures" >> benchmark-report.md
	@echo "| Algorithm | Status | Error |" >> benchmark-report.md
	@echo "|-----------|--------|-------|" >> benchmark-report.md
	@go test -bench="BenchmarkDecryptionWithAlgorithms" -benchmem ./pkg/encryption 2>&1 | rg "benchmark_test.go" | rg -A1 "failed:" | sed 's/.*Decryption with \(.*\) failed: \(.*\)/| \1 | Failed | \2 |/g' >> benchmark-report.md
	@echo "" >> benchmark-report.md
	
	@echo "Benchmark report generated: benchmark-report.md"
