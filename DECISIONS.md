# Decisions

Lightweight records of architectural choices. Each entry follows the same shape.

## 2026-05-10 — License: GNU Affero General Public License v3.0 only

**Decision:** Ship the project under `AGPL-3.0-only` (see `LICENSE` and `Cargo.toml`).

**Reason:** Network-facing tooling should preserve user freedom when deployed as a service; the Affero variant closes the “application service provider” loophole compared to the plain GNU General Public License. `AGPL-3.0-only` avoids implicitly licensing future Affero versions.

**Consequences:** Derivatives and hosted deployments must comply with Affero terms; compatibility reviews are required before linking with differently licensed code.

## 2026-05-10 — No dependencies until `std` is insufficient

**Decision:** Keep the crate free of external dependencies during bootstrap; remove unused crates rather than carrying speculative links.

**Reason:** Dependencies increase audit surface and build complexity. This entry described the earliest bootstrap; once Linux packet work landed, `libc` became required again (see the `libc` entry below).

**Consequences:** Any future crate addition must come with a fresh `DECISIONS.md` entry and clear justification.

## 2026-05-10 — Strict warnings and Clippy pedantic via Cargo lints

**Decision:** Configure `[lints.rust]` with warnings denied and `unsafe_op_in_unsafe_fn` denied; enable Clippy `pedantic` at warning level in `Cargo.toml`, and run `cargo fmt --all` followed by `cargo clippy --all-targets -- -D warnings` in local and continuous integration workflows (`Makefile` target `lint`).

**Reason:** Treat warnings as errors early so regressions do not accumulate; pedantic catches foot-guns consistent with project review standards.

**Consequences:** New pedantic findings block merges until addressed or explicitly documented with a rare, justified allowance.

## 2026-05-11 — `libc` for Linux packet sockets and ioctl

**Decision:** Add the `libc` crate for Linux `AF_PACKET` raw sockets, `bind(2)`, `ioctl(2)` (including `SIOCGIFFLAGS`, `SIOCGIFADDR`, `SIOCGIFNETMASK`, `SIOCGIFHWADDR`), `if_nametoindex(3)`, `if_nameindex(3)` / `if_freenameindex(3)`, `sendto(2)`, `recvfrom(2)`, `poll(2)`, and authoritative C layout types used to validate our `sockaddr_ll` mirror.

**Reason:** The standard library does not expose these system calls, socket options, or kernel ABI structures. Maintaining raw `extern "C"` declarations for the full surface would duplicate `libc`’s audited bindings without benefit.

**Consequences:** Dependency audits must include `libc` upgrades; Linux-only code paths rely on `libc` for foreign-function-interface correctness.

## 2026-05-13 — Isolated Linux syscall module and raw ARP scan path

**Decision:** Route Linux system calls through [`src/linux_system_call.rs`](src/linux_system_call.rs); keep descriptor lifetime management on `std::os::fd::OwnedFd` (drop closes the socket); implement Ethernet II framing in [`src/ethernet_frame.rs`](src/ethernet_frame.rs), IPv4 ARP over Ethernet in [`src/address_resolution_protocol.rs`](src/address_resolution_protocol.rs), and media access control addresses in [`src/mac_address.rs`](src/mac_address.rs); orchestrate subnet scanning in [`src/linux_scanner.rs`](src/linux_scanner.rs); return [`ApplicationOutcome`](src/application_outcome.rs) from [`run`](src/lib.rs) with warnings carried in [`ScanOutcome`](src/application_outcome.rs) for the binary to print to standard error.

**Reason:** GitHub issues #21 (syscall surface), #6 (transmit), and #7 (receive/parse) require a single audited foreign-function-interface boundary, wire-visible frames without unsafe serialization tricks, and testable pure parsing logic. Automated tests avoid requiring `CAP_NET_RAW`; live tcpdump or Wireshark checks stay manual.

**Consequences:** Linux-only unit tests cover frame layout and non-privileged syscall smoke checks; full scan behavior is validated on Linux hosts with appropriate privileges outside `cargo test` unless CI is later equipped for it.

## 2026-05-14 — Packet layer modules (`MacAddress`, Ethernet II, ARP)

**Decision:** Split former `ethernet_arp.rs` into `src/mac_address.rs` (public `MacAddress`), `src/ethernet_frame.rs` (Ethernet II encode/decode), and `src/address_resolution_protocol.rs` (IPv4 ARP over Ethernet); keep 60-octet minimum transmit frames for ARP requests; reject outer VLAN-tagged Ethernet before ARP interpretation.

**Reason:** Milestone issues #8–#11 and #22 call for explicit boundaries, defensive parsing, and a typed MAC address on public scan results without changing on-wire scan behavior.

**Consequences:** Library consumers use `MacAddress` and `DiscoveredHost::media_access_control_address`; future link-layer features extend the frame module first.

## 2026-05-11 — `clap` with derive for the `scan` subcommand

**Decision:** Add `clap` with the derive feature for `new-arp-scan scan --interface <name>`, layered `--help`, and examples.

**Reason:** The project explicitly approved a parser dependency over hand-rolled `std::env::args` parsing for this milestone. Derive macros keep the command surface typed and documented next to the definitions.

**Consequences:** Any future CLI expansion should extend the derive structs/enums and keep `main.rs` limited to parsing and dispatch.

## 2026-05-15 — Linux interface enumeration via `if_nameindex(3)` plus ioctl

**Decision:** Enumerate local interface names and indexes with `if_nameindex(3)` / `if_freenameindex(3)` (wrapped in [`src/linux_system_call.rs`](src/linux_system_call.rs)), then reuse existing `ioctl` reads for flags, IPv4 address, netmask, and hardware address when classifying usable ARP scan interfaces. Centralize copying an interface name into `struct ifreq` in [`src/interface_validation.rs`](src/interface_validation.rs) (Linux-only helper) for [`SIOCGIFFLAGS`](src/linux_system_call.rs) and related requests.

**Reason:** `if_nameindex(3)` is the documented portable way to list `(if_index, name)` pairs without rtnetlink complexity; `netdevice(7)` continues to document the ioctl surface already used for per-interface discovery. Sharing `ifreq` name population avoids duplicated length checks across modules.

**Consequences:** Listing and automatic interface selection share the same filtering rules as explicit scans; `libc` remains the only foreign-function-interface dependency for these calls.

## 2026-05-15 — Ungate pure IPv4 helpers for cross-platform unit tests

**Decision:** Compile [`src/ipv4_subnet.rs`](src/ipv4_subnet.rs) and [`src/ipv4_cidr.rs`](src/ipv4_cidr.rs) on every target; keep Linux-only modules (`linux_scanner`, raw sockets, and so on) behind `#[cfg(target_os = "linux")]`.

**Reason:** Subnet and classless inter-domain routing parsing are pure standard-library logic with no `libc` dependency; building them on non-Linux hosts lets `cargo test` validate traversal and parse edge cases in continuous integration without packet sockets.

**Consequences:** Public re-exports [`Ipv4Cidr`](src/ipv4_cidr.rs) and [`Ipv4HostAddressIterator`](src/ipv4_cidr.rs) document iterator-based expansion for library callers; the live scan path uses the same iterator as the tests.

## 2026-05-15 — Clippy: `cast_possible_truncation` after bounded CIDR prefix parse

**Decision:** Allow `clippy::cast_possible_truncation` when converting the parsed decimal `u32` prefix to `u8` immediately after rejecting values greater than `32`.

**Reason:** The guard makes truncation impossible; a `u8::try_from` error branch was logically unreachable and obscured the real control flow.

**Consequences:** If the accepted prefix range ever widens beyond what fits in `u8`, this site must be revisited together with the parser.

## 2026-05-17 — Configurable scan receive window and inter-target pacing

**Decision:** Extend [`ApplicationCommand::Scan`](src/application_command.rs) with `std::time::Duration` fields `timeout` and `pacing`, public defaults [`DEFAULT_SCAN_TIMEOUT`](src/application_command.rs) and [`DEFAULT_SCAN_PACING`](src/application_command.rs), and CLI flags `--timeout-ms` / `--pacing-ms`. The Linux scanner keeps a global receive phase after the last send while pacing only between sends; millisecond spans passed to `poll(2)` clamp to [`libc::c_int::MAX`](https://man7.org/linux/man-pages/man2/poll.2.html) when they do not fit the system call parameter type.

**Reason:** GitHub issue #14 requires configurable timeout and pacing without abandoning the existing burst-send plus single receive-window model operators already rely on.

**Consequences:** Library callers must supply explicit `Duration` values or the defaults; documentation and static site pages describe the new flags. Hermetic unit tests cover poll clamping, target ordering with the optional self-probe, and pacing gating without live sockets.
