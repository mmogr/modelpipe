# Every target here is a command, not a file.
.PHONY: help version build check check-lib test fmt fmt-check lint doc doc-check lock-check package-check enforce workflow-yaml bump dev pre-commit clean

# Name rustup's shim explicitly rather than relying on PATH order. Sourcing
# ~/.cargo/env is not sufficient on its own: that script only prepends
# ~/.cargo/bin when it is *absent* from PATH, so if it is present but ranked
# below a standalone toolchain (Homebrew's `rust` formula installs one), the
# script is a silent no-op and the standalone compiler wins. Those do not
# honour rust-toolchain.toml, so the build quietly runs on an unpinned rustc.
CARGO_ENV := $(shell if [ -f "$$HOME/.cargo/env" ]; then echo ". $$HOME/.cargo/env &&"; fi)
CARGO_BIN := $(shell if [ -x "$$HOME/.cargo/bin/cargo" ]; then echo "$$HOME/.cargo/bin/cargo"; else echo cargo; fi)
CARGO := $(CARGO_ENV) $(CARGO_BIN)

help: ## Show this help
	@echo "modelpipe Makefile - Available targets:"
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Build

build: ## Build in release mode
	$(CARGO) build --release

check: ## Check without producing artifacts (fastest feedback loop)
	$(CARGO) check --workspace --all-targets

check-lib: ## Check the library alone, exactly as CI does
	@# Not redundant with `check`: --workspace unifies features across
	@# members, so a feature the library uses but does not declare is
	@# supplied by modelpipe-cli and the gap never shows. This is the only
	@# command that sees what a downstream user of `modelpipe` alone gets.
	$(CARGO) check -p modelpipe --locked

clean: ## Remove build artifacts
	$(CARGO) clean

##@ Quality

fmt: ## Format code
	$(CARGO) fmt --all

fmt-check: ## Check formatting without rewriting anything, exactly as CI does
	$(CARGO) fmt --all -- --check

lint: ## Run clippy with warnings denied
	@# `--all-targets --all-features`, matching ci.yml exactly. Without
	@# --all-targets clippy skips test code, so a lint error inside a
	@# `#[cfg(test)]` module would pass here and fail CI.
	$(CARGO) clippy --all-targets --all-features -- -D warnings

test: ## Run tests
	$(CARGO) test --workspace --no-fail-fast

doc: ## Build and open the library docs
	$(CARGO) doc -p modelpipe --no-deps --document-private-items --open

doc-check: export RUSTDOCFLAGS := -D warnings
doc-check: ## Build rustdoc with warnings denied, exactly as CI does
	@# `-p modelpipe` rather than `--workspace`: the CLI's bin target shares
	@# the library's name, so a workspace doc build collides on
	@# target/doc/modelpipe/index.html. See the note in ci.yml.
	$(CARGO) doc -p modelpipe --no-deps --document-private-items
	@# Again as docs.rs builds it. A link from a public item to a private
	@# one resolves above and 404s on the published page; only this run
	@# sees that.
	$(CARGO) doc -p modelpipe --no-deps

lock-check: ## Fail if Cargo.lock is stale or absent, exactly as CI does
	$(CARGO) metadata --locked --format-version 1 > /dev/null

package-check: ## Verify both crates still package for crates.io
	@# --workspace is required, not stylistic: modelpipe-cli depends on
	@# modelpipe by version, so packaging it alone resolves that against the
	@# registry and fails for any version not yet published. --locked and
	@# --allow-dirty are orthogonal: dirty covers uncommitted files, locked
	@# refuses a lockfile that disagrees with the manifests.
	$(CARGO) package --workspace --no-verify --locked --allow-dirty

enforce: ## Run the architecture gates (no toolchain needed)
	@./scripts/check_file_size.sh
	@python3 scripts/ticket_vectors.py --check

workflow-yaml: ## Validate .github/workflows for duplicate keys
	@# This one has to run locally to be worth anything: a duplicate key in
	@# ci.yml means GitHub starts no jobs at all, including the job that
	@# checks for duplicate keys.
	@./scripts/check_workflow_yaml.sh

##@ Release

bump: ## Bump the workspace version locally (make bump VERSION=0.1.0)
	@# Routine bumps belong to release-plz; this is the manual tool for the
	@# jumps it refuses to make (release-plz never turns 0.0.x into 0.1.0 on
	@# its own). It does not commit or tag.
	@test -n "$(VERSION)" || { echo "usage: make bump VERSION=0.1.0"; exit 1; }
	./scripts/bump_version.py "$(VERSION)"
	$(CARGO) update --workspace
	$(CARGO) metadata --locked --format-version 1 > /dev/null
	@echo "✓ bumped — review the diff, commit, and push a tag to release"

version: ## Print the current workspace version
	@./scripts/bump_version.py --check

##@ Workflows

dev: fmt lint test ## Format, lint and test

pre-commit: fmt-check lint check check-lib test doc-check lock-check package-check enforce workflow-yaml ## Run everything CI requires
	@# fmt-check, not fmt: a check must be able to fail, and must never
	@# rewrite the tree it is checking. `make dev` is the rewriting loop.
	@./scripts/bump_version.py --check > /dev/null
	@echo "✓ All pre-commit checks passed"
