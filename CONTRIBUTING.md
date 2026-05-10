# Contributing

Thank you for contributing to **new-arp-scan**. This document records project-wide conventions that extend the Rust toolchain defaults and the expectations documented in this repository.

## Safety comments and `unsafe`

- **`unsafe` is reserved for real guarantees**, not convenience. Do not use `unsafe` unless there is no safe standard-library alternative.
- **Every `unsafe` block** must be preceded by a comment that states:
  - which invariants the caller must uphold,
  - what memory or concurrency assumptions the block relies on,
  - why the compiler cannot verify those facts automatically.
- Use the established Rust convention: a line-oriented `// SAFETY:` explanation immediately before the `unsafe` block, with enough detail for a reviewer to audit without guessing intent.

If you believe `unsafe` is required, record the architectural justification in `DECISIONS.md` as well.

## Foreign function interface boundaries

- Treat **foreign function interface** boundaries as trust boundaries: assume arguments from C or the operating system can violate Rust’s usual rules unless proven otherwise.
- Keep **foreign function interface calls** small and concentrated in dedicated modules; avoid scattering raw system calls across the crate.
- Prefer thin wrappers that translate foreign errors into the crate [`AppError`](src/error.rs) (or a dedicated error type) at the boundary.
- Document lifetime and threading assumptions where the foreign library keeps pointers or callbacks.

## Module ownership and layout

- **`src/main.rs`** contains only argument parsing (when implemented), minimal runtime setup, a single call into `run()` (or equivalent), process exit, and user-facing error printing. No business logic belongs here.
- **`src/lib.rs`** exposes the supported public application programming interface; integration tests depend on this surface.
- **`src/error.rs`** owns the crate-wide [`AppError`](src/error.rs) type unless a future change explicitly splits domain errors (document that split in `DECISIONS.md`).
- Prefer **flat modules** under `src/` over deep nesting. New domains get their own file or folder only when the responsibility is clearly distinct.

## Error handling

- Use **`Result` and `?`** for recoverable failures in library code. Do not use `unwrap()` or `expect()` in production paths.
- `expect()` is acceptable **only** in tests and in `main.rs` when the program cannot proceed (and the message must explain the invariant, not repeat the failure).
- Extend [`AppError`](src/error.rs) with new variants when behaviour warrants it; avoid stringly-typed errors for control flow.
- Every fallible **public** function’s documentation must include an **`# Errors`** section describing which variants callers should handle.

## Dependencies

- **Standard library first.** Adding a crate is an architectural decision, not a shortcut.
- Any new dependency requires an entry in **`DECISIONS.md`**: what problem it solves, why `std` is insufficient, and what alternatives were rejected.
- Keep `[dependencies]` minimal and audit upgrades deliberately.

## Testing

- **Business logic** must be tested (unit tests beside the code, integration tests under `tests/` against the public library application programming interface).
- Follow **Arrange, Act, Assert** structure with a blank line between phases.
- Name tests as **full sentences** in `snake_case` describing the scenario.
- Cover **positive**, **negative**, and **adversarial** cases for behaviour that matters; do not assert only `is_ok()` / `is_err()` without inspecting the outcome.
- Avoid tests that depend on the network, uncontrollable global state, or the real filesystem except behind isolation helpers approved in `DECISIONS.md`.
- Public functions require **documentation examples** that compile (`cargo test` runs them).

## Formatting and linting

- Run **`make lint`** (formats with `cargo fmt --all`, then runs `cargo clippy --all-targets -- -D warnings`), or invoke those commands yourself.
- Fix issues rather than silencing them.
- Undocumented `#[allow(...)]` attributes are not acceptable unless paired with a comment explaining why the suppression is correct **and** a `DECISIONS.md` entry.

## Licensing

By contributing, you agree that your contributions are licensed under the **GNU Affero General Public License v3.0 only**, the same license as the project (`LICENSE`).
