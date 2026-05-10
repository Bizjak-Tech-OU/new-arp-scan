.PHONY: build test lint clean

build: clean
	cargo build

test:
	cargo test
	cargo test --tests

lint:
	cargo fmt --all
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
