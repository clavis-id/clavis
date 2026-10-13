# Clavis development tasks. Run `make help` for the list of targets.
#
# Development tools are pinned in isolated modules under tools/ and run with
# `go tool`, so the only prerequisites are Go and, for PostgreSQL tests, Docker.

GO ?= go

# Clavis is CGo-free (ADR 0002). The race detector needs CGo on Linux only.
export CGO_ENABLED ?= 0
RACE_CGO := $(if $(filter Linux,$(shell uname -s)),1,$(CGO_ENABLED))

TOOL = $(GO) tool -modfile=tools/$(1)/go.mod $(1)
TOOL_MODULES = $(wildcard tools/*/go.mod)

COVER_PROFILE ?= coverage.out

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Compile every package
	$(GO) build ./...

.PHONY: test
test: ## Run tests with the race detector in random order
	CGO_ENABLED=$(RACE_CGO) $(GO) test -race -shuffle=on ./...

.PHONY: cover
cover: ## Run tests and write a coverage profile
	CGO_ENABLED=$(RACE_CGO) $(GO) test -race -shuffle=on -covermode=atomic -coverprofile=$(COVER_PROFILE) ./...
	$(GO) tool cover -func=$(COVER_PROFILE) | tail -n 1

.PHONY: lint
lint: ## Run golangci-lint and lint the GitHub Actions workflows
	$(call TOOL,golangci-lint) run ./...
	$(call TOOL,actionlint)

.PHONY: fmt
fmt: ## Format Go code
	$(call TOOL,golangci-lint) fmt ./...

.PHONY: vuln
vuln: ## Report known vulnerabilities in reachable code
	$(call TOOL,govulncheck) ./...

.PHONY: secrets
secrets: ## Scan the git history for committed secrets
	$(call TOOL,gitleaks) git --redact --no-banner

.PHONY: tidy
tidy: ## Tidy the main module and every tool module
	$(GO) mod tidy
	@for mod in $(TOOL_MODULES); do $(GO) -C $$(dirname $$mod) mod tidy || exit 1; done

.PHONY: tidy-check
tidy-check: ## Fail if any go.mod or go.sum is not tidy
	$(GO) mod tidy -diff
	@for mod in $(TOOL_MODULES); do $(GO) -C $$(dirname $$mod) mod tidy -diff || exit 1; done

.PHONY: check
check: tidy-check lint vuln test ## Run the checks that CI runs on every pull request

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -rf bin dist $(COVER_PROFILE)
