# Fuzzing

`fuzz_targets/parse_ethernet_arp.rs` drives the crate's untrusted-input boundary: the Ethernet
header, the IEEE 802.1Q tag stack (one customer tag, or an IEEE 802.1ad service tag wrapping one
customer tag), RFC 1042 LLC/SNAP, and the RFC 826 ARP PDU. Every octet the scanner parses comes
off the network, so this is the parser constitution section 9 requires a fuzz target for.

This package is a **separate workspace**. `cargo build`, `cargo test`, and
`cargo clippy --all-targets` in the crate root never build it, because libFuzzer needs a nightly
toolchain and a C++ sanitizer runtime that the stable CI jobs do not have. Fuzzing is therefore
**manual**, in the same spirit as privileged live ARP scans.

## Running

```sh
cargo install cargo-fuzz            # once per machine
rustup toolchain install nightly    # once per machine

# Seed the corpus from the checked-in cases, then fuzz.
mkdir -p fuzz/corpus/parse_ethernet_arp
cp fuzz/seeds/parse_ethernet_arp/* fuzz/corpus/parse_ethernet_arp/
cargo +nightly fuzz run parse_ethernet_arp -- -max_total_time=60
```

`make fuzz` from the crate root does all of the above.

A finding is written to `fuzz/artifacts/parse_ethernet_arp/`; reproduce it with
`cargo +nightly fuzz run parse_ethernet_arp fuzz/artifacts/parse_ethernet_arp/<file>`.

`corpus/`, `artifacts/`, `coverage/`, and `target/` are ignored. `seeds/` is checked in: twelve
hand-built cases covering each accepted framing (untagged, one customer tag, a service tag pair,
and RFC 1042 SNAP under those) and each rejection path (a lone service tag, three stacked tags,
the unofficial `0x9100` TPID, a truncated service tag, a truncated customer tag, an empty buffer,
and a frame shorter than the Ethernet header).
