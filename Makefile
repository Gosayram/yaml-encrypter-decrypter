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
GO_BIN_DIR := $(shell if [ -n "$$(go env GOBIN)" ]; then go env GOBIN; else echo "$$(go env GOPATH)/bin"; fi)
GOLANGCI_LINT_BIN := $(GO_BIN_DIR)/golangci-lint
STATICCHECK_BIN := $(GO_BIN_DIR)/staticcheck
GODOCLINT_BIN := $(GO_BIN_DIR)/godoclint

# Tooling versions (pinned for reproducible CI/local checks)
GOLANGCI_LINT_VERSION ?= v2.11.4
STATICCHECK_VERSION ?= v0.7.0
GODOCLINT_VERSION ?= latest

# Load application targets
include make/app.mk

### Other
.PHONY: help
help: ## Show this help (auto-generated from target comments)
	@sh -c '\
		if [ -t 1 ] && [ -z "$$NO_COLOR" ]; then \
			HDR="\033[1;36m"; CMD="\033[1;33m"; DESC="\033[0;37m"; TITLE="\033[1;32m"; RESET="\033[0m"; \
		else \
			HDR=""; CMD=""; DESC=""; TITLE=""; RESET=""; \
		fi; \
		printf "%bYAML Encrypter/Decrypter (yed)%b\n\n" "$$TITLE" "$$RESET"; \
		printf "%bUsage:%b make <target>\n" "$$HDR" "$$RESET"; \
		printf "%bTip:%b set NO_COLOR=1 to disable colors\n" "$$HDR" "$$RESET"; \
		awk -v hdr="$$HDR" -v cmd="$$CMD" -v desc="$$DESC" -v rst="$$RESET" '\'' \
			BEGIN { FS=":.*## "; section="General" } \
			/^### / { section=substr($$0, 5); next } \
			/^[a-zA-Z0-9_.-]+:.*## / { \
				target=$$1; info=$$2; \
				if (!(section in seen)) { seen[section]=1; order[++n]=section } \
				lines[section]=lines[section] sprintf("  %s%-32s%s %s%s%s\n", cmd, "make " target, rst, desc, info, rst); \
			} \
			END { \
				for (i=1; i<=n; i++) { \
					sec=order[i]; \
					printf "\n%s%s%s\n", hdr, sec, rst; \
					printf "%s", lines[sec]; \
				} \
			} \
		'\'' $(MAKEFILE_LIST); \
		printf "\n%bCLI help:%b $(OUTPUT_DIR)/$(BINARY_NAME) --help\n" "$$HDR" "$$RESET"; \
	'
