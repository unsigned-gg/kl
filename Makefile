# Makefile for unsigned-gg/kl (Kernel Layer Primitives)
# Shared workstations keep JOBS=2 to prevent CPU starvation and OOM.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

JOBS ?= 2
export JOBS

.PHONY: help default build fmt fmt-check clippy test doc-test check ci deny audit smoke doc

##@ Help

help: ## Display available Makefile targets
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[1mUsage:\033[0m\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1;33m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

default: help

##@ Build & Verification

build: ## Compile the workspace with host throttling (-j $(JOBS))
	cargo build --workspace -j $(JOBS)

fmt: ## Format all code
	cargo fmt --all

fmt-check: ## Check code formatting without modifying
	cargo fmt --all -- --check

clippy: ## Lint with clippy, warnings are errors (-j $(JOBS))
	cargo clippy --workspace --all-targets -j $(JOBS) -- -D warnings

test: ## Run unit and integration tests (-j $(JOBS))
	cargo test --workspace -j $(JOBS)

doc-test: ## Run doc tests (-j $(JOBS))
	cargo test --doc --workspace -j $(JOBS)

check: fmt-check clippy test doc-test ## Push gate: fmt-check, clippy, test, doc-test

ci: ## Run full CI Rust verification suite
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -j $(JOBS) -- -D warnings
	cargo test --workspace -j $(JOBS)
	cargo test --doc --workspace -j $(JOBS)

##@ Hygiene, Security & Docs

deny: ## Audit licenses, bans, and advisories
	cargo deny check

audit: ## Check dependencies for known advisories
	cargo audit

smoke: ## Build workspace and verify kl-domain has zero I/O
	cargo build --workspace -j $(JOBS)
	if grep -rnE 'std::net|std::fs|tokio|std::process' crates/kl-domain/src; then
		echo "smoke: kl-domain must not use I/O" >&2
		exit 1
	fi
	echo "smoke: ok"

doc: ## Build API docs
	cargo doc --workspace --no-deps -j $(JOBS)
