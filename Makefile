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
integration-test: build
	sudo target/debug/rust-criu-test $(CRIU_PATH)

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
	# Build instrumented test binary (includes piggie test process)
	CARGO_INCREMENTAL=0 \
	RUSTFLAGS="-C instrument-coverage" \
	LLVM_PROFILE_FILE="$(COVERAGE_PATH)/rust-criu-%p-%m.profraw" \
	GENERATE_TEST_PROCESS=1 \
		$(CARGO) build
	# Run integration tests with instrumented binary (requires sudo)
	sudo LLVM_PROFILE_FILE="$(COVERAGE_PATH)/rust-criu-%p-%m.profraw" \
		target/debug/rust-criu-test $(CRIU_PATH)
	# Merge profraw files
	llvm-profdata merge -sparse $(COVERAGE_PATH)/rust-criu-*.profraw \
		-o $(COVERAGE_PATH)/rust-criu.profdata
	# Generate coverage report
	@echo ""
	@echo "=== Coverage Summary ==="
	llvm-cov report \
		--instr-profile=$(COVERAGE_PATH)/rust-criu.profdata \
		--object target/debug/rust-criu-test \
		--ignore-filename-regex='\.cargo|rustc|rust_criu_protobuf/rpc\.rs'
	# Generate LCOV format
	llvm-cov export \
		--format=lcov \
		--instr-profile=$(COVERAGE_PATH)/rust-criu.profdata \
		--object target/debug/rust-criu-test \
		--ignore-filename-regex='\.cargo|rustc|rust_criu_protobuf/rpc\.rs' \
		> $(COVERAGE_PATH)/coverage.lcov
	@echo ""
	@echo "Coverage data written to $(COVERAGE_PATH)/"
	@echo "  - LCOV format: $(COVERAGE_PATH)/coverage.lcov"

# Generate HTML coverage report
coverage-html:
	mkdir -p $(COVERAGE_PATH)
	# Clean any previous coverage data
	$(LLVM_COV) clean --workspace
	# Build instrumented test binary (includes piggie test process)
	CARGO_INCREMENTAL=0 \
	RUSTFLAGS="-C instrument-coverage" \
	LLVM_PROFILE_FILE="$(COVERAGE_PATH)/rust-criu-%p-%m.profraw" \
	GENERATE_TEST_PROCESS=1 \
		$(CARGO) build
	# Run integration tests with instrumented binary (requires sudo)
	sudo LLVM_PROFILE_FILE="$(COVERAGE_PATH)/rust-criu-%p-%m.profraw" \
		target/debug/rust-criu-test $(CRIU_PATH)
	# Merge profraw files
	llvm-profdata merge -sparse $(COVERAGE_PATH)/rust-criu-*.profraw \
		-o $(COVERAGE_PATH)/rust-criu.profdata
	# Generate HTML report
	llvm-cov show \
		--format=html \
		--instr-profile=$(COVERAGE_PATH)/rust-criu.profdata \
		--object target/debug/rust-criu-test \
		--ignore-filename-regex='\.cargo|rustc|rust_criu_protobuf/rpc\.rs' \
		--output-dir=$(COVERAGE_PATH)/html
	@echo ""
	@echo "HTML report: $(COVERAGE_PATH)/html/index.html"

.PHONY: all build release test clippy fmt fmt-fix shellcheck shfmt
.PHONY: integration-test clean coverage coverage-html
