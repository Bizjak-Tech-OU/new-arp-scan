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

**Decision:** Add the `libc` crate for Linux `AF_PACKET` raw sockets, `bind(2)`, `ioctl(2)` (including `SIOCGIFFLAGS`, `SIOCGIFADDR`, `SIOCGIFNETMASK`, `SIOCGIFHWADDR`), `if_nametoindex(3)`, `sendto(2)`, `recvfrom(2)`, `poll(2)`, and authoritative C layout types used to validate our `sockaddr_ll` mirror.

**Reason:** The standard library does not expose these system calls, socket options, or kernel ABI structures. Maintaining raw `extern "C"` declarations for the full surface would duplicate `libc`’s audited bindings without benefit.

**Consequences:** Dependency audits must include `libc` upgrades; Linux-only code paths rely on `libc` for foreign-function-interface correctness.

## 2026-05-13 — Isolated Linux syscall module and raw ARP scan path

**Decision:** Route Linux system calls through [`src/linux_system_call.rs`](src/linux_system_call.rs); keep descriptor lifetime management on `std::os::fd::OwnedFd` (drop closes the socket); implement manual Ethernet and ARP frame bytes in [`src/ethernet_arp.rs`](src/ethernet_arp.rs); orchestrate subnet scanning in [`src/linux_scanner.rs`](src/linux_scanner.rs); return [`ApplicationOutcome`](src/application_outcome.rs) from [`run`](src/lib.rs) with warnings carried in [`ScanOutcome`](src/application_outcome.rs) for the binary to print to standard error.

**Reason:** GitHub issues #21 (syscall surface), #6 (transmit), and #7 (receive/parse) require a single audited foreign-function-interface boundary, wire-visible frames without unsafe serialization tricks, and testable pure parsing logic. Automated tests avoid requiring `CAP_NET_RAW`; live tcpdump or Wireshark checks stay manual.

**Consequences:** Linux-only unit tests cover frame layout and non-privileged syscall smoke checks; full scan behaviour is validated on Linux hosts with appropriate privileges outside `cargo test` unless CI is later equipped for it.

## 2026-05-11 — `clap` with derive for the `scan` subcommand

**Decision:** Add `clap` with the derive feature for `new-arp-scan scan --interface <name>`, layered `--help`, and examples.

**Reason:** The project explicitly approved a parser dependency over hand-rolled `std::env::args` parsing for this milestone. Derive macros keep the command surface typed and documented next to the definitions.

**Consequences:** Any future CLI expansion should extend the derive structs/enums and keep `main.rs` limited to parsing and dispatch.
