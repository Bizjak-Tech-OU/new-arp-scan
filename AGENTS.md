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
