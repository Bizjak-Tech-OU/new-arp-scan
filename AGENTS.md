## Learned User Preferences

- For substantial or multi-issue work, investigate the full codebase and official documentation, follow project Cursor rules, and ask clarifying questions until the scope is unambiguous before implementing.
- When executing an attached implementation plan, do not edit the plan file itself; use existing todos (mark them in progress and complete them) instead of creating duplicate todo lists.
- Prefer standard-library-only CLI argument parsing; do not add third-party parser dependencies unless explicitly approved for the project or task, and record any approved parser in `DECISIONS.md`.
- When changing developer workflow commands, update the `Makefile` and the matching documentation together so they stay aligned.

## Learned Workspace Facts

- The primary GitHub repository for this project is `Bizjak-Tech-OU/new-arp-scan`.
- Roadmap and issue planning are driven from repository `issues.md` alongside GitHub issues and milestones.
- The `Makefile` `lint` target runs `cargo fmt --all` and then `cargo clippy --all-targets -- -D warnings`.
- The `Makefile` `test` target runs `cargo test` and then `cargo test --tests`.
- The `Makefile` `build` target depends on `clean`, so `cargo clean` runs before `cargo build`.
- The `Makefile` `coverage` target runs `cargo llvm-cov --all-targets --summary-only` (requires `cargo install cargo-llvm-cov` once on the machine).
- When decoding IPv4 addresses returned in `sockaddr_in` from Linux `ioctl`, read the four octets stored at `sin_addr.s_addr` in wire order as laid out by the kernel; using `s_addr.to_be_bytes()` on little-endian hosts can permute octets and make valid contiguous netmasks look invalid.
- Newer stable Rust toolchains paired with recent `libc` releases can change whether fields such as `ifreq.ifr_name` and `sockaddr.sa_data` expose `c_char` or `u8` elements; portable code should coerce through `as _` (or equivalent) instead of assuming signed octets indefinitely.
- Non-interactive `cargo llvm-cov` runs should install `llvm-tools-preview` first (`rustup component add llvm-tools-preview`) so coverage does not block on an interactive toolchain install prompt.
- Beyond the two known environment-sensitive tests, Linux tests that open `AF_INET` datagram or raw sockets can fail with permission denied in locked-down sandboxes; rerun outside those restrictions when validating the full suite.

## Cursor Cloud specific instructions

- **Rust toolchain:** The project uses `edition = "2024"` which requires Rust ≥ 1.85. The update script ensures stable toolchain is installed. Use `cargo build` (not `make build`) to avoid the `cargo clean` that the Makefile prepends.
- **Running the CLI:** The binary is at `./target/debug/new-arp-scan` after `cargo build`. A full ARP scan requires `CAP_NET_RAW` (run as root or with `sudo`). The CLI argument parsing and error paths can be exercised without privileges.
- **Tests:** `make test` or `cargo test`. Two tests are environment-sensitive: `computes_prefix_length_for_slash_24_netmask` and `returns_rejection_when_scanning_loopback_interface_on_linux` may fail in containers where the loopback hardware type differs from a standard Linux host.
- **Lint:** `make lint` runs `cargo fmt --all` then `cargo clippy --all-targets -- -D warnings`. Clippy pedantic is enabled; newer Rust toolchains may surface additional lints not present when the code was last updated.
- **No external services:** This is a pure systems CLI — no databases, Docker, or network services are needed.
