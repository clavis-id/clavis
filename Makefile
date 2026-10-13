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
# Security-critical packages must keep at least COVER_FLOOR percent coverage.
COVER_FLOOR ?= 80
COVER_FLOOR_PKGS = ./internal/issuer ./internal/keys ./kek
FUZZTIME ?= 30s

# Container images, pinned by digest. sqlc runs in Docker because its
# PostgreSQL parser needs CGo.
SQLC_IMAGE ?= sqlc/sqlc:1.31.1@sha256:70f53171d27b2424e9358869975455a6e955a5aa8e58a998a270a6e34e525537
POSTGRES_IMAGE ?= postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873
POSTGRES_CONTAINER ?= clavis-test-postgres
POSTGRES_PORT ?= 55432

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Compile every package and build bin/clavis
	$(GO) build ./...
	$(GO) build -trimpath -o bin/clavis ./cmd/clavis

.PHONY: run
run: ## Run the server with the local development configuration
	$(GO) run ./cmd/clavis serve --config deploy/dev/clavis.yaml

.PHONY: test
test: ## Run tests with the race detector in random order
	CGO_ENABLED=$(RACE_CGO) $(GO) test -race -shuffle=on ./...

.PHONY: test-store
test-store: ## Run the store tests (PostgreSQL included when CLAVIS_TEST_POSTGRES_DSN is set)
	CGO_ENABLED=$(RACE_CGO) $(GO) test -race -shuffle=on ./store/...

.PHONY: test-postgres
test-postgres: ## Run the store tests against a throwaway PostgreSQL container
	@docker rm -f $(POSTGRES_CONTAINER) >/dev/null 2>&1 || true
	@docker run -d --rm --name $(POSTGRES_CONTAINER) -e POSTGRES_PASSWORD=clavis \
		-p 127.0.0.1:$(POSTGRES_PORT):5432 --tmpfs /var/lib/postgresql $(POSTGRES_IMAGE) >/dev/null
	@trap 'docker rm -f $(POSTGRES_CONTAINER) >/dev/null' EXIT; \
	for i in $$(seq 1 150); do \
		docker exec $(POSTGRES_CONTAINER) pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; \
		sleep 0.2; \
	done; \
	CLAVIS_TEST_POSTGRES_DSN="postgres://postgres:clavis@127.0.0.1:$(POSTGRES_PORT)/postgres?sslmode=disable" \
		$(MAKE) --no-print-directory test-store

.PHONY: test-go-import
test-go-import: ## Test the Cloudflare Worker that serves the clavisid.org/clavis import path (needs Node.js)
	node --test deploy/cloudflare/go-import/index.test.mjs

.PHONY: cover
cover: ## Run tests and write a coverage profile
	CGO_ENABLED=$(RACE_CGO) $(GO) test -race -shuffle=on -covermode=atomic -coverprofile=$(COVER_PROFILE) ./...
	$(GO) tool cover -func=$(COVER_PROFILE) | tail -n 1

.PHONY: generate
generate: ## Regenerate code (sqlc runs in Docker)
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR)":/src -w /src $(SQLC_IMAGE) generate

.PHONY: generate-check
generate-check: generate ## Fail if generated code is out of date
	@test -z "$$(git status --porcelain -- store)" || \
		{ git status --porcelain -- store; echo "generated code is out of date: run make generate"; exit 1; }

.PHONY: cover-check
cover-check: ## Fail if a security-critical package is below the coverage floor
	@fail=0; for pkg in $(COVER_FLOOR_PKGS); do \
		pct=$$($(GO) test -count=1 -cover $$pkg | sed -nE 's/.*coverage: ([0-9.]+)% of statements.*/\1/p'); \
		echo "$$pkg: $${pct:-0}% (floor $(COVER_FLOOR)%)"; \
		awk -v p="$${pct:-0}" -v f="$(COVER_FLOOR)" 'BEGIN { exit !(p >= f) }' || fail=1; \
	done; exit $$fail

.PHONY: fuzz
fuzz: ## Run every fuzz target for FUZZTIME each (default 30s)
	@grep -rlE --include='*_test.go' '^func Fuzz' . | sort | while read -r file; do \
		dir=$$(dirname "$$file"); \
		for name in $$(sed -nE 's/^func (Fuzz[A-Za-z0-9_]+)\(.*/\1/p' "$$file"); do \
			echo "fuzzing $$name in $$dir for $(FUZZTIME)"; \
			$(GO) test -run='^$$' -fuzz="^$$name$$" -fuzztime=$(FUZZTIME) "./$$dir" || exit 1; \
		done; \
	done

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

.PHONY: release-snapshot
release-snapshot: ## Build release archives and images locally, without signing or publishing
	$(call TOOL,goreleaser) check
	$(call TOOL,goreleaser) release --snapshot --clean --skip=sign,sbom

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -rf bin dist $(COVER_PROFILE) clavis.db clavis.db-shm clavis.db-wal
