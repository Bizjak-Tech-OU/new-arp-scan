# new-arp-scan

ARP scanning tool (Rust). Socket initialization for Linux `AF_PACKET` / ARP is implemented; full scanning behaviour is not implemented yet.

Copyright © Bizjak Tech OÜ.

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).

## Usage

```text
new-arp-scan scan --interface <NAME>
```

- On Linux, `scan` validates the interface, opens a raw `AF_PACKET` / `SOCK_RAW` socket filtered to ARP (`ETH_P_ARP`), and binds it to the given interface. Successful initialization is followed by a clear **“scanning not implemented yet”** error until the scanner is finished.
- On non-Linux hosts, `scan` returns an unsupported-platform error without calling Linux-only APIs.

Creating the raw packet socket requires Linux capability **`CAP_NET_RAW`** (often available to the superuser). See Linux `packet(7)` and `capabilities(7)`.

Run `new-arp-scan --help` or `new-arp-scan scan --help` for built-in examples.

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
