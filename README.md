# new-arp-scan

ARP scanning tool (Rust). On Linux, `scan` performs address resolution protocol discovery across the selected interface’s IPv4 subnet using raw `AF_PACKET` / `SOCK_RAW` sockets.

Copyright © Bizjak Tech OÜ.

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).

## Usage

```text
new-arp-scan interfaces
new-arp-scan scan [--interface <NAME>] [--host <IPv4>] [--timeout-ms <MILLISECONDS>] [--pacing-ms <MILLISECONDS>] [--attempts <COUNT>]
```

- On Linux, `interfaces` lists interfaces that are usable for ARP scanning (Ethernet hardware type, administratively up, not loopback, not `NOARP`, with an IPv4 address, netmask, and a non-zero hardware address). Output is a plain aligned table; if none qualify, the tool prints `no usable interfaces found` and exits successfully.
- On Linux, `scan` reads the interface IPv4 address, netmask, and Ethernet hardware address via `ioctl`, opens a raw packet socket bound to ARP (`ETH_P_ARP`), then runs `--attempts` full rounds (default `1`). With `--host <IPv4>`, each round sends one broadcast ARP request for that address only; the address must be strictly interior on the interface subnet (not the network or broadcast address, and not off-subnet). Otherwise each round sends one broadcast ARP request per target address in the subnet (excluding network and broadcast, but always including the interface’s own IPv4 address when it falls outside that open range). Between rounds it sleeps `--pacing-ms` milliseconds after each round except the last (default `0`). After the last round it collects replies until `--timeout-ms` elapses (default `3000`). In single-host mode, only replies whose sender IPv4 equals `--host` are recorded; timing flags behave the same as for a full subnet scan. Values larger than Linux `poll(2)` accepts in milliseconds are clamped internally. Discovered hosts are printed as `<IPv4> <MAC>` on standard output in ascending IPv4 order; the library represents each MAC as `MacAddress` on `DiscoveredHost::media_access_control_address` (colon-separated lowercase hex, same as the binary). Non-fatal issues (for example a failed send, a malformed frame, or a conflicting duplicate address resolution reply for the same IPv4) are reported as `warning: ...` lines on standard error. After the scan’s standard output lines, the binary prints one timing summary line on standard error with the stable template `scan complete: interface <NAME>, <N> host(s), <R> round(s), <MS> ms` (singular `host` / `round` when the count is one). If nothing responds, the tool prints `no hosts found` on standard output, still prints the timing summary on standard error, and exits successfully. An invalid `--host` for the selected interface (for example the subnet network address) exits with an error before opening the socket.
- On Linux, when `scan` is run without `--interface` / `--iface`, the tool selects an interface automatically **only** when exactly one usable interface exists; otherwise it exits with an error that names the ambiguity or states that no usable interface was found.
- On non-Linux hosts, `scan` and `interfaces` return an unsupported-platform error without calling Linux-only APIs.

Creating the raw packet socket requires Linux capability **`CAP_NET_RAW`** (often available to the superuser). Permission denied when opening the socket is surfaced with an explicit `CAP_NET_RAW` hint. See Linux `packet(7)` and `capabilities(7)`.

To verify frames on the wire, run `tcpdump` or Wireshark on the same interface (for example `tcpdump -ni eth0 arp`) while scanning; this is optional manual validation and is not part of automated tests. For a full acceptance check on hardware you control, run a privileged scan (for example `sudo ./target/debug/new-arp-scan scan --interface eth0`) or a single-host probe (for example `sudo ./target/debug/new-arp-scan scan --interface eth0 --host 192.168.1.50`) and compare custom `--timeout-ms`, `--pacing-ms`, and `--attempts` values with the defaults documented above.

Run `new-arp-scan --help`, `new-arp-scan interfaces --help`, or `new-arp-scan scan --help` for built-in examples.

## Exit codes

The binary uses a minimal, deterministic exit code contract:

- `0` — successful command, including `no hosts found`, `no usable interfaces found`, printing help when invoked with no arguments, and successful `--help` invocations.
- `1` — any operational failure returned from the library (`AppError`), including unsupported platform, invalid interface or target, and raw socket errors (including missing `CAP_NET_RAW` when reported as permission denied).
- `2` — command-line usage or parse errors from the argument parser (typically unknown flags or invalid flag values).

## Requirements

- Rust toolchain with Cargo (`rustc`, `cargo fmt`, `cargo clippy`)
- GNU Make (optional but recommended for the targets below)

## Local development

| Command | Description |
| ------- | ----------- |
| `make build` | `cargo clean` then `cargo build` |
| `make test` | `cargo test` then `cargo test --tests` |
| `make lint` | `cargo fmt --all` then `cargo clippy --all-targets -- -D warnings` |
| `make coverage` | `cargo llvm-cov --all-targets --summary-only` (install once: `cargo install cargo-llvm-cov`; first run may need `rustup component add llvm-tools-preview`) |
| `make clean` | `cargo clean` |

Run the same commands manually if you prefer not to use Make.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

Additional notes live under [docs/](docs/):

| Guide | Audience |
|-------|----------|
| [Contributor onboarding](docs/contributor-onboarding.md) | First-time build, lint, test, and pull-request checklist |
| [Architecture overview](docs/architecture.md) | Module map, `unsafe` boundaries, packet flow, testing strategy |
| [Linux platform support](docs/linux-platform.md) | `AF_PACKET` / raw sockets, capabilities, CI vs local testing, namespaces |
| [Operator reference (HTML)](docs/docs.html) | CLI behavior, output, and library overview (static site) |
