# Architecture overview

This document helps **new contributors** navigate the crate layout, trust boundaries, and data flow. It complements [CONTRIBUTING.md](../CONTRIBUTING.md) (conventions) and [Linux platform](linux-platform.md) (kernel-facing details).

Tracked for release documentation: [GitHub issue #33](https://github.com/Bizjak-Tech-OU/new-arp-scan/issues/33).

---

## Module responsibilities (mental map)

| Area | Modules | Role |
|------|---------|------|
| **Entry** | `main.rs` | Parse arguments with `clap`, call `run()`, write [`ApplicationOutcome`](../src/application_outcome.rs) via [`write_operator_streams`](../src/application_outcome.rs), exit codes, print `AppError` on failure. |
| **Application surface** | `lib.rs`, `application_command.rs`, `application_outcome.rs` | Public `run(ApplicationCommand)` contract, outcomes, operator output layout, timing summary attachment after successful Linux scans. |
| **Operator parsing** | `cli.rs` | Command-line types and validation (delegated from `main.rs`). |
| **Errors** | `error.rs` | Single [`AppError`](../src/error.rs) enum; `Display` / `Error` for operators and tests. |
| **Pure IPv4 logic** | `ipv4_subnet.rs`, `ipv4_cidr.rs` | Subnet math and CIDR parsing; built on every target for CI without Linux sockets. |
| **Name / shape checks** | `interface_validation.rs` | Interface name rules and Linux `ifreq` name packing helpers. |
| **Link and ARP encoding** | `mac_address.rs`, `ethernet_frame.rs`, `address_resolution_protocol.rs` | Types and on-wire framing for Ethernet II + ARP. |
| **Linux discovery** | `linux_interface_discovery.rs`, `linux_socket.rs` | Usable-interface classification, `ioctl` address and flag reads, raw socket open/bind. |
| **Linux syscalls** | `linux_system_call.rs` | Centralized `libc` calls (`socket`, `poll`, `if_nameindex`, …) with small safe wrappers where possible. |
| **Scan orchestration** | `linux_scanner.rs` | Target iteration, send/receive scheduling, merge duplicate replies, warnings. |
| **Packet layout** | `linux_packet.rs` | `sockaddr_ll` and related layout checks shared with tests. |

Linux-only modules live behind `#[cfg(target_os = "linux")]` in [`lib.rs`](../src/lib.rs). Non-Linux builds compile pure logic and return [`AppError::UnsupportedPlatform`](../src/error.rs) from `run()` for scan and list commands.

---

## `unsafe` boundaries

There is **no gratuitous `unsafe`**. It appears only where the language cannot express kernel **foreign function interface** contracts or **uninitialized structures** filled by `ioctl`.

Typical clusters:

- **`linux_system_call.rs`** — `libc` sockets, `ioctl`, `poll`, `if_nameindex` / `if_freenameindex`, send/receive on file descriptors. Each block should carry a **`// SAFETY:`** comment per project rules.
- **`linux_interface_discovery.rs`**, **`linux_socket.rs`**, **`interface_validation.rs`** — `ifreq` and `sockaddr` manipulation, reading kernel-populated fields.
- **`linux_packet.rs`** — casting a known layout to `sockaddr_ll` for interpretation.
- **`linux_scanner.rs`** — zeroed link-layer address structures where the kernel fills fields after sends.

**Rule of thumb:** treat new `unsafe` as a **last resort**, document invariants beside the block, and add a **DECISIONS.md** entry if the change is non-obvious.

---

## Packet flow (scan, simplified)

```text
CLI / library caller
       │
       ▼
  run() ──► resolve interface, validate, build target list (IPv4 subnet or single --host)
       │
       ▼
linux_scanner: open AF_PACKET SOCK_RAW, bind to interface + ETH_P_ARP
       │
       ├──► For each round: build Ethernet II ARP request frames → send on raw socket
       │
       └──► Receive loop (poll + recv): parse Ethernet II + ARP replies
                 │
                 ▼
            Merge into DiscoveredHost map, collect warnings
       │
       ▼
  ScanOutcome (hosts + warnings; timing filled in run())
       │
       ▼
  write_operator_streams() → stdout / stderr (binary)
```

For field-level behavior, read module-level `//!` comments and the [operator docs](docs.html).

---

## Testing strategy

| Layer | Location | Purpose |
|-------|----------|---------|
| **Unit** | `#[cfg(test)]` at bottom of each `src/*.rs` | Default: fast, hermetic, covers parsing, math, error `Display`, and most Linux helpers that do not need raw ARP on the wire. |
| **Integration** | `tests/*.rs` | Subprocess CLI (`CARGO_BIN_EXE_*`) and public `run()` behavior across platforms. |
| **Doc tests** | ` ``` ` blocks on public API | Compile-checked examples (`cargo test` includes them). |

**Conventions** (see also [CONTRIBUTING.md](../CONTRIBUTING.md) and `.cursor/rules/testing.mdc` if present):

- Arrange / Act / Assert with blank lines.
- Test names are full **snake_case sentences**.
- Prefer matching **specific** `Err` variants over `is_err()` alone.
- Avoid external network dependencies; prefer fixtures and controlled syscalls.

Privileged **full-subnet** scans are validated manually (for example with `tcpdump`); automating them in CI would require a dedicated harness or namespace setup (see [Linux platform](linux-platform.md)).

---

## Where to change what

| Goal | Start here |
|------|----------------|
| New CLI flag | `cli.rs`, `application_command.rs`, `main.rs` dispatch only |
| New scan semantics | `linux_scanner.rs`, possibly `ipv4_subnet.rs` |
| New operator output | `application_outcome.rs` (`write_operator_streams`, formatting) |
| New `AppError` variant | `error.rs`, then every `Display` / `source` path and matching tests |
| New syscall wrapper | `linux_system_call.rs` first |

When in doubt, open a small pull request and point reviewers to this file for orientation.
