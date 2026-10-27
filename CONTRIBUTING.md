# Contributing to AgentSwapper

This is an unreleased developer preview. Use disposable state and fixture agents
when developing. Never use a real subscription to reproduce a concurrency or
crash test.

Rust 1.98.0 is the pinned toolchain and the current minimum supported version.
Install Rust through rustup; `rust-toolchain.toml` selects the required compiler.
If your system cargo bypasses rustup, prefix commands with
`rustup run 1.98.0`.

```sh
cargo build --locked --workspace
cargo run -p agentswapper-cli --bin aswp -- --help
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

The fast test command includes unit tests, property tests, CLI subprocess tests,
terminal snapshots, and documentation examples. CI uses nextest for process
isolation and runs documentation examples separately:

```sh
cargo install cargo-nextest --version 0.9.150 --locked
cargo nextest run --locked --workspace --profile ci
cargo test --locked --workspace --doc
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --locked check
```

Read [CLI usage](docs/cli.md), [testing](docs/testing.md), and the
[support matrix](docs/support-matrix.md) before changing launch behavior. Keep
core domain and storage code independent of clap, Ratatui, and terminal state.
New auth, routing, or switching behavior requires evidence and failure tests.
Use typed errors, short transactions, direct argument forwarding, and validated
identifiers. Unsafe Rust is forbidden in workspace crates. Do not commit test
credentials, private state, or recorded production sessions.

Review snapshot diffs before accepting them. Commit proptest regression seeds;
do not ignore or automatically bless failures. Dependencies belong in Cargo.lock
and must pass the advisory/license policy. Licensing for this project's own
code is awaiting the maintainer's selection; Apache-2.0 is recommended.
