# Dependency decisions

The Unix native-launch path enables the existing `rustix` termios feature to
save and restore foreground terminal attributes after an observed child exit.
This uses an already locked dependency and adds no new package. It does not
restore a terminal after supervisor termination or establish descendant custody.

The workspace and all dependency versions are locked. Own code is Apache-2.0;
dependencies retain their original licenses. `cargo deny --locked check` checks
advisories, licenses, dependency versions, and sources. Never globally disable
an advisory category to pass CI. Accepted exceptions need a specific rationale.

## Handover encryption

The manual handover feature pins `age = 0.11.3`, with optional CLI helpers,
plugins, SSH identities, and asynchronous support disabled. It uses the standard
age-v1 passphrase format, through the library's authenticated streaming API.
The application does not implement its own encryption construction. Encryption
and decryption work factors are bounded explicitly.

Age 0.12.1 was evaluated. Its unconditional HPKE/P-256 dependency graph pulls in
`crypto-bigint 0.5.5`, affected by timing variability in constant-time operations.
That dependency is absent from the selected 0.11.3 graph. No exception for this
vulnerability is present. Re-evaluate upgrading when a suitable dependency graph
passes the audit. [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).

Two narrowly scoped unmaintained-package notices are accepted in `deny.toml`:

- `RUSTSEC-2026-0374`: `basic-toml`, reached through `i18n-config` while compiling
  age's translation macros. It parses checked-in crate build metadata rather
  than imported handover files. [Advisory](https://rustsec.org/advisories/RUSTSEC-2026-0374.html).
- `RUSTSEC-2026-0173`: `proc-macro-error2`, used by the same translation macro
  chain during compilation. It does not process runtime handover input. The
  compiler is pinned; future Rust upgrades must address its compatibility warning.
  [Advisory](https://rustsec.org/advisories/RUSTSEC-2026-0173.html).

These are maintenance exceptions, not accepted cryptographic vulnerabilities.
Wrapper restrictions in `deny.toml` reject a new direct or runtime dependency
path to these packages; only the reviewed translation-macro chain is allowed.
Remove them when the translation dependency chain is maintained without adding
an affected runtime dependency. Re-check the actual graph with `cargo tree`
before changing the rationale. Do not infer audit cleanliness merely from a
package's age, version number, or continued compilation.

## Linux terminal verification

The Linux-only development dependency `signal-hook = 0.3.18` (MIT OR Apache-2.0)
was already present through the terminal library. The guardian terminal fixture
uses its safe `flag::register` API with default features disabled. Source review
of that path confirmed the registered action only stores an atomic boolean;
filesystem and terminal operations happen in the fixture's ordinary loop.
The fixture observes SIGWINCH and leaves inherited ignored signals intact.
No new package, runtime core dependency or advisory exception was introduced.

## Linux descriptor hygiene

The experimental Linux shim pins `fuxix = 0.8.0` (MIT) for its safe
`cloexec_from` wrapper. The package has no build script and depends only on
`libc`, which was already in the lockfile. Review of the pinned source covered
the Linux `close_range(CLOSE_RANGE_CLOEXEC)` call, its `/proc/self/fd` fallback,
descriptor flag preservation and error conversion. The fallback enumerates
descriptors and therefore relies on a trustworthy procfs and a single-threaded
shim; neither this review nor the local exec test qualifies a hostile mount
namespace or concurrent descriptor creation. Errors refuse target exec.
The shim role is entered before normal CLI initialization; the core and
actual-guardian tests do not yet prove all production embedding or race cases.
The normal locked dependency audit and hosted integration remain required.
The locked dependency audit passed with this graph at `2414290` in
[CI run 40836137547](https://github.com/shahzadlone/agent-swapper/actions/runs/40836137547/job/123321241350).
That does not substitute for the pending delegated integration and race tests.

## Terminal signal restoration

The CLI directly pins the already-transitive `signal-hook = 0.3.18` on Unix.
Dashboard and hidden handover entry register atomic flags for INT, TERM and HUP.
The terminal workflow restores settings before the safe `emulate_default_handler` API
re-raises the original signal. Source review covered that API's default-handler
reset, unblocking and re-raise path, including its abort fallback if delivery
fails. No other workflow thread installs handlers for these signals. Registration
guards remove their actions on startup failure and exit. I/O does not run in
the signal callback. Dashboard handlers are removed before native launch;
foreground launch and login share their own interrupt handler with the shell
commands. This adds no package or advisory exception.

### Bounded terminal input

The CLI pins crossterm 0.29.0 and selects its `use-dev-tty` event backend on
Unix. The default Mio backend's inner TTY read loop ignores zero-byte reads
and non-retryable read errors; it can remain inside `poll` after terminal loss
without returning to our signal check. Repeated provider-free PTY shutdown
tests reproduced that hang locally. The selected backend breaks its inner
loop on a zero-byte read and retains the outer poll deadline.

Raw dashboard and hidden-passphrase input also use `VMIN=0, VTIME=1`, so an
incomplete UTF-8 or escape sequence reaches that deadline without needing a
second byte. Crossterm caches the original terminal settings before this
adjustment and restores them before shell/agent input resumes. This is not
a timeout on a user's thinking time or a completed key sequence: later bytes
still complete pending input. PTY tests exercise partial-input interruption,
repeated terminal loss and a successful encrypted pack whose Unicode password
character arrives across several read deadlines.

This feature adds locked `filedescriptor 0.8.3` (MIT) on Unix. Its published
manifest has no build script and depends on already-locked libc, thiserror 1,
and Windows bindings. Source review covered the Unix poll conversion and the
macOS select implementation's descriptor bounds; only short application poll
timeouts reach this path. It adds no network, cryptography or credential logic.
The locked advisory/license/source audit passes locally with existing duplicate
version warnings and no new exception. Hosted Linux/macOS terminal checks and
the rebuilt candidate gates remain required.

The dashboard also wraps its terminal writer during destruction. Active writes
retain their original errors; only the terminal destructor's final cursor
output is best-effort. Ratatui 0.30.2 otherwise reports a failed cursor write
with `eprintln!`, which can panic when stderr is disconnected too. Repeated
both-stream PTY loss reproduced that exit-101 path locally. Independent raw-mode
and alternate-screen restoration still run; this does not suppress launch errors
or let a failed render continue.

Interactive handover retains the handlers through cryptography and publication;
unregistering immediately after a prompt would remove the actions while that
command is still running. Pipe-based secret input retains its existing signal
behavior. The CLI also enables the existing `rustix` dependency's termios feature
for safe `tcflush(IFlush)`: unread input is discarded before restoring echo.
No new runtime package is introduced.

## Windows custody verification

The experimental Windows supervision backend and its custody examples use
exact Windows-target dependencies `process-wrap 10.0.1` and `win32job 2.0.3`,
both MIT OR Apache-2.0, plus the Microsoft Windows bindings. Native launch uses it only with the explicit experimental Windows containment
option. Only std, Job Object, and creation-flag support is enabled in
process-wrap; Tokio and tracing are disabled. The two libraries currently use
different Windows binding versions, both recorded and audited in Cargo.lock.

Source review found that process-wrap's std Job wrapper alone lacks
kill-on-close and an adequate empty-Job wait. The verification example supplies
separate root ownership and membership checks. The reusable backend instead
creates a private kill-on-close Job for each run, without assigning the
supervisor itself. Its `spawn_with` callback runs after `pre_spawn` adds
CREATE_SUSPENDED and before `wrap_child` resumes the target. It assigns the
owned process handle and invokes durable admission before returning the child.
Only the known JobObject wrapper is installed; arbitrary creation flags are
not accepted. Inner-Job termination and outer-Job membership queries avoid the
completion-port wait. `into_inner` is never called (it leaks the Job handle).

Source inspection confirmed that win32job creates an unnamed Job with null
security attributes (non-inherited handle). Its fixed membership buffer returns
query errors on overflow; those errors fail closed. A successful query's returned
PID list is the observation used here. Targeted termination uses process-wrap's
nested Job; before resume both Jobs contain exactly the suspended initial child,
so descendants inherit both. The outer Job provides kill-on-close independently.
Neither library's presence nor a clean advisory scan proves these invariants;
[backend fixtures](custody.md) must exercise them on Windows. Some internal
process-wrap failure cleanup uses an unbounded native wait; the wrapper's own
normal stop polling and admission-guard waits are bounded. Without the optional
process-lifetime root Job, a crash before the first assignment can leak a
suspended process. The CLI now installs that root for the explicit Windows
containment option; its new crash-window fixture awaits hosted validation.
No new advisory or licensing exception was added.

## Licensing and distribution

BSD-3-Clause is allowed for the RustCrypto/Dalek dependencies. The existing
MPL-2.0 exception is limited to unmodified `option-ext 0.2.0`, used by the
platform-directory helper. Preserve its license and source availability when
packaging binaries. Preserve applicable notices from every dependency; passing
cargo-deny does not itself generate a distribution's notice bundle. Provider
artwork notices remain in `assets/brand/THIRD_PARTY_NOTICES.txt`.

Upstream implementation code has not been copied into the Rust application.
The research clones and model-review transcripts are excluded from the repository.
