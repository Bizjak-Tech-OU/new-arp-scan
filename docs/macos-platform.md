# macOS platform support

This document is for **contributors** who work on or test the macOS path. End-user behavior is also summarized in the [README](../README.md) and [operator documentation](./docs.html); the Linux counterpart is [Linux platform support](./linux-platform.md).

Tracked for release documentation: [GitHub issue #59](https://github.com/Bizjak-Tech-OU/new-arp-scan/issues/59).

---

## Why the Berkeley Packet Filter

macOS has no `AF_PACKET`. To send and receive raw **Ethernet II frames** carrying **IPv4 ARP** on a chosen interface, `new-arp-scan` uses a **Berkeley Packet Filter** device (see macOS `bpf(4)`):

- Open a cloning **`/dev/bpf*`** device (the tool tries successive minor devices, skipping busy ones).
- Attach it to the interface with **`BIOCSETIF`**, then read and write complete link-layer frames.
- Install a **filter program** (`BIOCSETF`) so only ARP (`EtherType 0x0806`) frames are delivered, and disable **`BIOCSSEESENT`** so the device does not echo back the requests the tool broadcasts. Together these match the effect of a Linux packet socket bound to `ETH_P_ARP`.
- Enable **`BIOCIMMEDIATE`** for prompt delivery and **`BIOCSHDRCMPLT`** so the source hardware address written by the encoder is preserved.

Interface enumeration uses **`getifaddrs(3)`** (rather than Linux `ioctl`), aggregating the `AF_INET` address/netmask and the `AF_LINK` Ethernet address per interface. The pure ARP/Ethernet framing and the scan scheduling are shared with Linux through the portable link-layer backend (see [architecture](./architecture.md) and `DECISIONS.md`, 2026-06-03).

---

## Privilege requirements

Opening a Berkeley Packet Filter device typically requires **root** (run with `sudo`). No special entitlement is assumed for this command-line tool. Some systems grant BPF access to a user's group, in which case `sudo` is not needed.

- `interfaces` needs **no privileges** — it only reads `getifaddrs(3)`.
- `scan` opens `/dev/bpf*`. When the process lacks access, the open fails with **permission denied** and the tool reports an explicit *"requires root or BPF access (try running with sudo)"* error (`AppError::BpfDeviceAccessRequired`) that does **not** leak the device path. This is distinct from an unknown-interface error, which fails earlier during discovery.

**Contributors do not need BPF access** to run the full unit test suite on macOS: tests use fixtures, `getifaddrs` enumeration (unprivileged), unknown-interface lookups, and the BPF-open **error path**. No automated test opens a BPF device for a live scan.

---

## Interface naming

macOS interfaces use names such as `en0` (typically the primary Ethernet/Wi-Fi), `en1`, `bridge0`, and so on. The same name rules and usability filters as Linux apply: the interface must be **Ethernet**, **administratively up**, **not loopback**, **not `NOARP`**, and have an **IPv4 address, netmask, and a non-zero Ethernet address**. Loopback (`lo0`) and non-Ethernet virtual interfaces (for example `utun*`) are rejected. When exactly one interface qualifies, `scan` selects it automatically; otherwise pass `--interface en0`.

---

## Testing environment setup

1. **Toolchain** — current **stable Rust** with **edition 2024** (see `Cargo.toml`).
2. **Gate before pushing** (the same checks CI runs on `macos-latest`):

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

   `make lint` / `make test` run equivalent commands (`make lint` rewrites formatting instead of only checking it).

3. **Manual acceptance scan** (needs root / BPF access, touches your LAN):

   ```bash
   cargo build
   sudo ./target/debug/new-arp-scan interfaces
   sudo ./target/debug/new-arp-scan scan --interface en0
   sudo ./target/debug/new-arp-scan scan --interface en0 --host 192.168.1.50
   ```

   Discovered hosts print as `<IPv4> <MAC>` followed by a `scan complete: …` timing line on standard error.

---

## Verifying frames on the wire

While a scan runs, capture ARP on the same interface in another terminal:

```bash
sudo tcpdump -ni en0 arp
```

You should see the tool's broadcast ARP **requests** and the **replies** from live hosts. Wireshark with an `arp` display filter on `en0` works the same way. This is optional manual validation and is not part of automated tests.

---

## Further reading

- macOS `bpf(4)`, `getifaddrs(3)`
- [Linux platform support](./linux-platform.md) for the `AF_PACKET` counterpart
- Repository [DECISIONS.md](../DECISIONS.md) for the macOS backend decision (2026-06-03)
