.PHONY: build test lint clean coverage

build: clean
	cargo build

test:
	cargo test
	cargo test --tests

lint:
	cargo fmt --all
	cargo clippy --all-targets -- -D warnings

coverage:
	cargo llvm-cov --all-targets --summary-only

clean:
	cargo clean
