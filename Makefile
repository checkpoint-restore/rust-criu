# SPDX-License-Identifier: Apache-2.0
#
# Makefile for rust-criu

CARGO ?= cargo
CRIU_PATH ?= $(shell command -v criu)

COVERAGE_PATH ?= $(shell pwd)/.coverage

# Coverage tool - uses cargo-llvm-cov for source-based coverage
LLVM_COV = $(CARGO) llvm-cov

# Default target
all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test -- --test-threads=1 --nocapture

clippy:
	$(CARGO) clippy --verbose --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --all -- --check

fmt-fix:
	$(CARGO) fmt --all

shellcheck:
	shellcheck -o all test/prepare-fedora-coverage-environment.sh

shfmt:
	shfmt -w test/prepare-fedora-coverage-environment.sh

# Integration test - requires root and CRIU
integration-test:
	sudo -E env PATH=$(PATH) CRIU_BINARY=$(CRIU_PATH) $(CARGO) test -- --test-threads=1

clean:
	rm -rf target
	rm -rf .coverage
	rm -rf test/images

# Coverage targets - requires cargo-llvm-cov: cargo install cargo-llvm-cov
#
# Coverage workflow:
# 1. Build instrumented binary with coverage
# 2. Run the test binary to collect coverage data
# 3. Generate reports from collected coverage data
#
# Usage:
#   make coverage CRIU_PATH=/path/to/criu  - Run all tests with coverage
#   make coverage-html CRIU_PATH=/path/to/criu - Generate HTML coverage report

# Run tests with coverage and generate LCOV report
coverage:
	mkdir -p $(COVERAGE_PATH)
	# Clean any previous coverage data
	$(LLVM_COV) clean --workspace
	# Build test processes (piggie, loop, loop_pts)
	GENERATE_TEST_PROCESS=1 $(CARGO) build
	# Run integration tests with coverage (requires root for CRIU)
	sudo -E env PATH=$(PATH) CRIU_BINARY=$(CRIU_PATH) \
		$(LLVM_COV) test \
		--lcov --output-path $(COVERAGE_PATH)/coverage.lcov \
		--ignore-filename-regex='\.cargo|rustc|rust_criu_protobuf/rpc\.rs' \
		-- --test-threads=1
	@echo ""
	@echo "Coverage data written to $(COVERAGE_PATH)/"
	@echo "  - LCOV format: $(COVERAGE_PATH)/coverage.lcov"

# Generate HTML coverage report
coverage-html:
	mkdir -p $(COVERAGE_PATH)
	# Clean any previous coverage data
	$(LLVM_COV) clean --workspace
	# Build test processes (piggie, loop, loop_pts)
	GENERATE_TEST_PROCESS=1 $(CARGO) build
	# Run integration tests with coverage (requires root for CRIU)
	sudo -E env PATH=$(PATH) CRIU_BINARY=$(CRIU_PATH) \
		$(LLVM_COV) test \
		--html --output-dir $(COVERAGE_PATH)/html \
		--ignore-filename-regex='\.cargo|rustc|rust_criu_protobuf/rpc\.rs' \
		-- --test-threads=1
	@echo ""
	@echo "HTML report: $(COVERAGE_PATH)/html/index.html"

.PHONY: all build release test clippy fmt fmt-fix shellcheck shfmt
.PHONY: integration-test clean coverage coverage-html
