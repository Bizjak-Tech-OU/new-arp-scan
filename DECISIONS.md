# Decisions

Lightweight records of architectural choices. Each entry follows the same shape.

## 2026-05-10 — License: GNU Affero General Public License v3.0 only

**Decision:** Ship the project under `AGPL-3.0-only` (see `LICENSE` and `Cargo.toml`).

**Reason:** Network-facing tooling should preserve user freedom when deployed as a service; the Affero variant closes the “application service provider” loophole compared to the plain GNU General Public License. `AGPL-3.0-only` avoids implicitly licensing future Affero versions.

**Consequences:** Derivatives and hosted deployments must comply with Affero terms; compatibility reviews are required before linking with differently licensed code.

## 2026-05-10 — No dependencies until `std` is insufficient

**Decision:** Keep the crate free of external dependencies during bootstrap; remove unused crates rather than carrying speculative links.

**Reason:** Dependencies increase audit surface and build complexity. `libc` was removed until foreign-function-interface work actually requires it.

**Consequences:** Any future crate addition must come with a fresh `DECISIONS.md` entry and clear justification.

## 2026-05-10 — Strict warnings and Clippy pedantic via Cargo lints

**Decision:** Configure `[lints.rust]` with warnings denied and `unsafe_op_in_unsafe_fn` denied; enable Clippy `pedantic` at warning level in `Cargo.toml`, and run `cargo fmt --all` followed by `cargo clippy --all-targets -- -D warnings` in local and continuous integration workflows (`Makefile` target `lint`).

**Reason:** Treat warnings as errors early so regressions do not accumulate; pedantic catches foot-guns consistent with project review standards.

**Consequences:** New pedantic findings block merges until addressed or explicitly documented with a rare, justified allowance.
