# new-arp-scan

ARP scanning tool (Rust). This repository is bootstrapped; scanning behaviour is not implemented yet.

Copyright © Bizjak Tech OÜ.

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).

## Requirements

- Rust toolchain with Cargo (`rustc`, `cargo fmt`, `cargo clippy`)
- GNU Make (optional but recommended for the targets below)

## Local development

| Command | Description |
| ------- | ----------- |
| `make build` | `cargo clean` then `cargo build` |
| `make test` | `cargo test` then `cargo test --tests` |
| `make lint` | `cargo fmt --all` then `cargo clippy --all-targets -- -D warnings` |
| `make clean` | `cargo clean` |

Run the same commands manually if you prefer not to use Make.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

Additional notes live under [docs/](docs/).
