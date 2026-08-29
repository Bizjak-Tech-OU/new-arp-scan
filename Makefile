.PHONY: build test lint clean coverage fuzz

build: clean
	cargo build --release

test:
	cargo test
	cargo test --tests

lint:
	cargo fmt --all
	cargo clippy --all-targets -- -D warnings

coverage:
	cargo llvm-cov --all-targets --summary-only

# Manual, like privileged live ARP scans: needs `cargo install cargo-fuzz` and a nightly
# toolchain, neither of which the stable CI jobs have. FUZZ_SECONDS overrides the duration.
fuzz:
	mkdir -p fuzz/corpus/parse_ethernet_arp
	cp -n fuzz/seeds/parse_ethernet_arp/* fuzz/corpus/parse_ethernet_arp/ || true
	cargo +nightly fuzz run parse_ethernet_arp -- -max_total_time=$(or $(FUZZ_SECONDS),60)

clean:
	cargo clean

all: build test lint
