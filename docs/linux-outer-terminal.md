# Owned outer-terminal qualification

Status: isolated component experiment. The Python harness creates every PTY;
the fixed Rust probe accepts no provider command and never touches the terminal
running the harness. Connecting this component to the managed inner terminal
remains a separate gate.

Before changing modes, the probe verifies the private fixture record, matching
standard streams and its own foreground group. It reopens its verified stdin
through `/proc/self/fd/0` with `NOCTTY`, `CLOEXEC` and `NONBLOCK`, then rechecks
identity and the original stdin flags. This supplies a separate open-file
description instead of changing flags shared with the parent shell.

This fresh, single-threaded process refuses inherited ignored, caught or
blocked control signals. A signalfd drives signal handling in its event loop.
Terminal restoration precedes signal-mask restoration on normal and error
paths. It restores the saved mode before self-suspension, keeps that mode after `bg`,
and re-enters raw mode only after regaining the foreground. A discarded
SIGTSTP in an orphaned group returns to useful input rather than waiting for a
continuation that cannot arrive.

The local harness passes nine cases:

- UTF-8, escape, editing, signal and flow-control bytes, coalesced input and resize.
- Orphaned-group suspension fallback with working input afterwards.
- Exit and SIGTERM with queued output observed to be nonwritable.
- Full terminal-attribute restoration after explicit failure and oversized input.
- Redirected-stream refusal before mode changes.
- Real interactive-bash stop, `bg` and `fg`, triggered by a command or external SIGTSTP.

Output and input buffers are bounded. Backpressure cases wait for an actual
nonwritable queued-output observation, then stop consuming the PTY while
requesting exit or SIGTERM. Signal termination preserves SIGTERM status after
restoration. Shell tests compare `stty` snapshots across the full lifecycle;
direct cases compare every termios field and control character.

This is a fixed command probe, not a transparent byte relay. It intentionally
requires matching terminal streams and a fresh signal state. General redirected
streams, composition with an already multithreaded CLI, master-close behavior,
restoration after uncatchable process death, and the combined inner/outer
protocol remain unqualified. Both Ubuntu manager jobs and the complete
platform/package pipeline passed at `7ea68c4` in
[run 41273387293](https://github.com/shahzadlone/agent-swapper/actions/runs/41273387293).
Independent source review remains pending; this checkpoint qualifies the
isolated outer component, without claiming a managed relay or provider launch.

```sh
cargo +1.98.0 build --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml --example outer_terminal
python3 tools/check_linux_outer_terminal.py tools/linux-manager-evaluation/target/debug/examples/outer_terminal
```
