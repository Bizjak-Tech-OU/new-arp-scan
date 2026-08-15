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

## 2026-05-18 — Scan rounds, inter-round pacing, attempts, and duplicate reply warnings

**Decision:** Extend [`ApplicationCommand::Scan`](src/application_command.rs) with `attempts: std::num::NonZeroU64` and public [`DEFAULT_SCAN_ATTEMPTS`](src/application_command.rs). Add CLI `--attempts` (minimum `1`, total scan rounds). Repurpose `--pacing-ms` to mean delay after each full round of target sends except the last round; keep `--timeout-ms` as the receive window after the final round. Implement round iteration in [`perform_arp_scan`](src/linux_scanner.rs). On conflicting address resolution replies for the same IPv4, keep the first media access control address and emit one warning per later conflicting reply.

**Reason:** Operators need optional retransmission across the subnet without per-target pacing; total rounds with inter-round pacing matches the agreed product behavior. Duplicate-safe merging avoids unstable output when multiple replies disagree.

**Consequences:** The 2026-05-17 “inter-target pacing” semantics are superseded: pacing is now strictly between rounds. Library callers pass `NonZeroU64` for `attempts` (or `DEFAULT_SCAN_ATTEMPTS`). README and static docs describe rounds, attempts, and conflict warnings.

## 2026-05-26 — Single-target ARP scan (`--host`) and `perform_arp_probe`

**Decision:** Add optional CLI `--host <IPv4>` on `scan`, optional `target_ipv4_address: Option<std::net::Ipv4Addr>` on [`ApplicationCommand::Scan`](src/application_command.rs), and public [`perform_arp_probe`](src/linux_scanner.rs) on Linux (re-exported from the crate root). Refactor [`linux_scanner`](src/linux_scanner.rs) so subnet scans and probes share send and receive scheduling, with separate reply filtering for subnet-wide versus exact-target modes. Validate targets with [`validate_strict_interior_scan_target_ipv4_address`](src/ipv4_subnet.rs); reject invalid targets with [`AppError::SingleScanTargetRejected`](src/error.rs) before opening the raw socket. Keep “no hosts found”, exit success, and stderr warnings aligned with full-subnet scans when the probe times out.

**Reason:** GitHub issue #24 requires an end-to-end single-address flow without duplicating packet logic; strict-interior validation matches full-scan interior rules and avoids ambiguous probes of network or broadcast addresses.

**Consequences:** Operators and library callers can probe one interior host with the same `--timeout-ms`, `--pacing-ms`, and `--attempts` semantics as subnet scans. README, static docs, and CLI examples describe `--host` and the new error variant.

## 2026-06-03 — macOS packet I/O strategy: direct BPF via `libc` and a portable link-layer backend

**Decision:** Add first-class macOS support for `scan` and `interfaces` using **direct Berkeley Packet Filter (BPF) access through `libc`**, not `libpcap`. Open a `/dev/bpf*` cloning device, attach it to a named interface with `BIOCSETIF`, and `read(2)` / `write(2)` complete Ethernet II frames. Reuse the existing Ethernet/ARP encoders ([`src/ethernet_frame.rs`](src/ethernet_frame.rs), [`src/address_resolution_protocol.rs`](src/address_resolution_protocol.rs)) and `MacAddress` ([`src/mac_address.rs`](src/mac_address.rs)) unchanged.

Introduce a **narrow portable link-layer boundary** that both Linux and macOS implement, so scan scheduling and ARP framing never branch on `AF_PACKET` versus BPF. The boundary exposes exactly four capabilities:

1. **Interface discovery** — enumerate usable ARP scan candidates and discover one interface's `(name, index, IPv4, netmask, MAC, usability flags)`. Produces the shared `InterfaceScanAddresses` / `ArpScanInterfaceCandidate` value types.
2. **Open a bound link-layer endpoint** — a handle attached to one interface for Ethernet II ARP frames, owning the underlying descriptor (`OwnedFd`, closed on drop).
3. **Send one Ethernet II frame** — the frame already carries its broadcast destination MAC; the backend hides any address structure (`sockaddr_ll` on Linux, plain `write` on BPF).
4. **Wait for readiness, then receive frames** — a `poll(2)`/`select(2)` readiness primitive plus a non-blocking frame read compatible with the shared scanner's deadline model. The macOS backend de-aggregates the multiple `BIOCGBLEN`-sized, `bpf_hdr`-prefixed, `BPF_WORDALIGN`-padded frames returned by a single BPF `read(2)` behind this primitive, so callers still observe one Ethernet frame at a time.

**Module and `cfg` plan:**

- **Shared, ungated, no FFI:** `ipv4_subnet`, `ipv4_cidr`, `mac_address`, `ethernet_frame`, `address_resolution_protocol`, the portable scan orchestration (target expansion, rounds/pacing/attempts, duplicate-reply merge, reply acceptance), and the cross-platform parts of `interface_validation`. The Ethernet/ARP modules are currently `#[cfg(target_os = "linux")]` only because the scanner is; they move behind the portable boundary so they compile on every target (#52, #55).
- **Linux backend (`#[cfg(target_os = "linux")]`):** existing `linux_socket`, `linux_interface_discovery`, `linux_system_call`, `linux_packet` retain their `linux_*` names and remain the only place `AF_PACKET`, `sockaddr_ll`, and `ioctl`-based discovery live.
- **macOS backend (`#[cfg(target_os = "macos")]`):** new sibling modules `macos_bpf_socket`, `macos_interface_discovery`, `macos_system_call`, `macos_packet`, mirroring the Linux split. All macOS `unsafe` is centralized in `macos_system_call` with `// SAFETY:` blocks, exactly as `linux_system_call` does for Linux (#21, #28).

**Privilege model:** macOS BPF devices require **root** (no special entitlement is assumed for this CLI). Opening or attaching a BPF device without privilege fails with `EACCES`/`EPERM`; that is surfaced as an operator-actionable "run with sudo" error, parallel to the Linux `CAP_NET_RAW` path (#31, #57). `/dev/bpf*` exhaustion (`EBUSY`) is handled by probing successive cloning minor devices.

**Reason:** The constitution's prime directive is to reach for `std`/`libc` before any external crate, and `libc` is already the sole FFI dependency for the Linux `AF_PACKET` path; direct BPF keeps macOS symmetric with Linux and adds no new dependency. The post-MVP backlog (#35) explicitly lists `libpcap` as a *future, optional* backend, so adopting it now would contradict a recorded scope decision and widen the audit surface for marginal convenience. A trait-style boundary (the constitution favors traits for behavior contracts) keeps the substantial, well-tested scan scheduling and ARP framing logic platform-neutral; only descriptor acquisition and raw send/receive differ per OS. The extra `unsafe` cost of hand-written BPF is bounded by the existing centralized-syscall pattern.

**Consequences:** Implementation proceeds as the macOS tracking issue (#60) breakdown: extract the portable backend (#52), macOS interface enumeration (#53), macOS BPF send/receive (#54), shared scan orchestration (#55), wire macOS into `run()` and fix macOS release builds (#56), macOS privilege diagnostics (#57), macOS CI job (#58), and macOS platform docs (#59). `libc` remains the only FFI dependency. Explicitly **deferred** to the post-MVP backlog (#35): the optional `libpcap` backend, Homebrew distribution / signed binaries, and passive monitor mode / VLAN handling. New macOS `unsafe` follows the documented `// SAFETY:` discipline; the BPF frame-aggregation parser is covered by hermetic unit tests over fixture buffers, while privileged live scans stay manual (same philosophy as Linux).

## 2026-05-26 — Scan timing summary on standard error and minimal exit codes

**Decision:** After a successful Linux `scan`, populate [`ScanOutcome::timing_summary`](src/application_outcome.rs) in [`run`](src/lib.rs) and have the binary print one stable standard-error line via [`ScanTimingSummary::format_stderr_timing_summary_line`](src/application_outcome.rs) after standard output. Document a minimal exit contract: `0` success (including empty results and help-only paths), `1` any [`AppError`](src/error.rs) from [`run`](src/lib.rs), `2` command-line parse or usage errors from `clap` (`error.exit()`). Do not assign distinct exit codes per [`AppError`](src/error.rs) variant (for example capability versus interface rejection).

**Reason:** Milestone issues #18–#19 call for readable timing context and deterministic operator-visible exit semantics without expanding the error surface into sysexits-style matrices.

**Consequences:** README and [`docs/docs.html`](docs/docs.html) describe the timing line template and exit table; integration tests assert parse failures exit `2` where the toolchain maps `clap` usage errors to that code.

## 2026-08-15 — RFC and IEEE packet fidelity, 802.1Q receive, IEEE MAC registries

**Decision:** Treat the on-wire Ethernet/ARP codecs as a standards contract, not a best-effort layout:

- **RFC 826:** keep transmitting Ethernet II ARP requests with `ar$hrd=1`, `ar$pro=0x0800`, `ar$hln=6`, `ar$pln=4`, `ar$op=1`, `ar$tha=0`, interface `ar$sha`/`ar$spa`, and target `ar$tpa`. Record replies from `ar$spa`/`ar$sha` (not the Ethernet source, which may differ).
- **RFC 5227:** add explicit ARP Probe (`ar$spa=0.0.0.0`) and ARP Announcement (`ar$spa=ar$tpa`) builders covered by tests. Default `scan` / `--host` remain RFC 826 requests using the interface IPv4 address (the same default as original `arp-scan`). `perform_arp_probe` keeps meaning “single-target scan”, not an RFC 5227 Probe.
- **RFC 5494:** reject reserved `ar$hrd` and `ar$op` values 0 and 65535 on receive.
- **IEEE 802.3:** pad transmitted ARP to 60 octets without FCS (46-octet MAC client data, 18 zero pad bytes). Parse length/type as a length when `<= 1500`, as an EtherType when `>= 1536`, and reject the undefined gap. Accept RFC 1042 LLC/SNAP ARP on receive.
- **IEEE 802.1Q:** decode a single customer VLAN tag on receive (VID is the low 12 TCI bits) and accept the inner ARP payload. Reject IEEE 802.1ad / unofficial QinQ TPIDs and stacked 0x8100 tags so the inner EtherType is never read from the wrong offset. Transmit stays untagged Ethernet II. macOS BPF now accepts both untagged ARP and 0x8100-tagged ARP. Linux `ETH_P_ARP` still relies on kernel VLAN tag stripping for tagged frames on the parent interface.
- **IEEE MA-L / MA-M / MA-S:** add [`MacVendorRegistry`](src/mac_vendor_registry.rs) with longest-prefix match over `arp-scan` `ieee-oui.txt` text (6 / 7 / 9 hex digits). CLI `--mac-vendor-file` loads an explicit file; `ieee-oui.txt` in the current directory is used when present. Host lines become `<IPv4> <MAC> <vendor>` only when a registry is loaded.

**Reason:** The core product is an ARP scanner. Silent misparse of 802.3 lengths, stacked VLAN TPIDs, and reserved ARP fields, plus no IEEE registry lookup, made the tool unverifiable against the RFCs/IEEE documents and weaker than original `arp-scan` on receive-side 802.1Q and vendor identification.

**Consequences:** Spec-facing tests live in [`src/protocol_conformance.rs`](src/protocol_conformance.rs) and the packet modules. Still deferred at that time: send-side `--vlan` (superseded below), LLC/SNAP transmit, bundling a full IEEE database, passive ACD / monitor mode, `libpcap`. Operators who want vendor names generate or copy an `ieee-oui.txt` (for example with original `arp-scan`'s `get-oui`).

## 2026-08-15 — IEEE 802.1Q send-side `--vlan` and Linux tagged capture

**Decision:** Operators can tag transmitted ARP requests with a single IEEE 802.1Q customer tag via `scan --vlan <VID>` (`0..=4095`, PCP and DEI zero). The request is still RFC 826 Ethernet II ARP padded to 60 octets without the frame check sequence (IEEE 802.3 / 802.3ac `ETH_ZLEN` behaviour, matching original `arp-scan --vlan`). On Linux, a VLAN scan opens `AF_PACKET` with `ETH_P_ALL` so replies may arrive tagged (`0x8100`) or with the tag stripped; non-ARP frames are ignored without malformed-frame warnings. Untagged scans keep `ETH_P_ARP`. macOS already captured tagged ARP via BPF; it now also transmits the tag when `--vlan` is set.

**Reason:** Receive-side 802.1Q parsing without a send path could not be claimed as IEEE 802.1Q fidelity, and Linux `ETH_P_ARP` silently dropped tagged replies on trunks that do not strip tags.

**Consequences:** LLC/SNAP transmit, QinQ / IEEE 802.1ad, bundling a full IEEE database, RFC 5227 Probe as a CLI mode, passive ACD / monitor mode, and `libpcap` remain deferred. VID `4095` is reserved in IEEE 802.1Q but is accepted as a 12-bit TCI field, same as original `arp-scan`.
