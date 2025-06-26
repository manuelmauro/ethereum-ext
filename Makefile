.PHONY: all build test check fmt clippy clean doc audit

all: fmt clippy test

build:
	cargo build --all-features
	cargo build --no-default-features
	cargo build --target wasm32-unknown-unknown --no-default-features

test:
	cargo test --all-features
	cargo test --no-default-features

check:
	cargo check --all-features
	cargo check --no-default-features

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo clippy --all-targets --no-default-features -- -D warnings

clean:
	cargo clean

doc:
	cargo doc --no-deps --all-features --open

audit:
	cargo audit

# Install development dependencies
dev-deps:
	rustup component add rustfmt clippy
	rustup target add wasm32-unknown-unknown
	cargo install cargo-audit

# Run all CI checks locally
ci: fmt clippy test build
	@echo "All CI checks passed!"