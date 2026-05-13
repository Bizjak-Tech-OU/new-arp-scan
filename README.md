# new-arp-scan

ARP scanning tool (Rust). On Linux, `scan` performs address resolution protocol discovery across the selected interface’s IPv4 subnet using raw `AF_PACKET` / `SOCK_RAW` sockets.

Copyright © Bizjak Tech OÜ.

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).

## Usage

```text
new-arp-scan scan --interface <NAME>
```

- On Linux, `scan` reads the interface IPv4 address, netmask, and Ethernet hardware address via `ioctl`, opens a raw packet socket bound to ARP (`ETH_P_ARP`), sends one broadcast ARP request per target address in the subnet (excluding network and broadcast, but always including the interface’s own IPv4 address when it falls outside that open range), then collects replies for three seconds. Discovered hosts are printed as `<IPv4> <MAC>` on standard output; non-fatal issues (for example a failed send or a malformed frame) are reported as `warning: ...` lines on standard error. If nothing responds, the tool prints `no hosts found` and exits successfully.
- On non-Linux hosts, `scan` returns an unsupported-platform error without calling Linux-only APIs.

Creating the raw packet socket requires Linux capability **`CAP_NET_RAW`** (often available to the superuser). Permission denied when opening the socket is surfaced with an explicit `CAP_NET_RAW` hint. See Linux `packet(7)` and `capabilities(7)`.

To verify frames on the wire, run `tcpdump` or Wireshark on the same interface (for example `tcpdump -ni eth0 arp`) while scanning; this is optional manual validation and is not part of automated tests.

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
