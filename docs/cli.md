# CLI developer preview

The command is `aswp`; `agentswapper` is the full-length alias. Both binaries
share the same implementation and state. Build from source using
[CONTRIBUTING.md](../CONTRIBUTING.md). No release or package installation is
published yet.

## Everyday commands

```sh
aswp profile add claude --alias work
aswp profile add codex --alias personal
aswp profile add kimi --alias research
aswp list
aswp profile show work
aswp status
aswp runs
aswp runs RUN_ID --json
aswp doctor
aswp registry verify
aswp tui
```

Registration creates an empty profile. It does not authenticate, discover your
email, inspect credential files, or establish available quota. `doctor` checks
registry integrity and profile directories and discovers executables on PATH;
it does not run them or claim they are compatible. Account and isolation status
are `unverified`; quota is `unknown`.

`registry verify` replays all projections in memory and reports mismatches
without rewriting them. Schema upgrades save a private database backup first.
See [registry integrity](registry.md) for upgrade and recovery details.

```sh
aswp profile alias personal side-project
aswp profile disable research
aswp profile enable research
aswp profile remove side-project
```

Removing unregisters metadata and directory mappings. It retains native files
and does not revoke a server-side login. Disabling affects future launches;
it does not interrupt an existing session. A busy or unfinished run blocks
removal. There is deliberately no force-delete or force-unlock command.

## Native launch

Inspect the selected executable and profile home first:

```sh
aswp login work --dry-run
aswp run work --dry-run -- --resume
aswp run work --dry-run --json
```

An explicit, experimental opt-in permits a native launch:

```sh
aswp login work --experimental-native
aswp run work --experimental-native -- --resume
```

Real-provider isolation is not verified on any platform. This preview sets only
the selected child's profile-home variable: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
or `KIMI_CODE_HOME`. Native configuration, platform credential stores, workspace
hooks, and version-specific behavior can reach beyond that directory. A home
variable is not a sandbox. There is no process-tree containment, native resume
verification, automatic account rotation, or managed cross-agent takeover yet. Do not
use experimental profiles for sensitive production work.

Known inherited auth, base-URL, billing-route, and selected home variables cause
a refusal, with variable names only. Other harnesses' home variables are removed
from the child environment. This list is conservative and cannot
cover every vendor version. Arguments after `--` go directly to the native
program without shell interpolation. They can still instruct the native
program to read or write other paths. `--executable /absolute/path` explicitly
selects a trusted binary; Windows batch and PowerShell shims are refused.

Launch previews show argument counts, never argument contents. They do not
reserve a profile or guarantee a later launch will succeed. Native stdout
belongs to the child, so actual launches cannot use `--json`.

A profile lease, stored outside the native home, prevents simultaneous launches by cooperating AgentSwapper
processes. A durable intent is written before spawn. An interrupted supervisor
leaves an unfinished run and blocks reuse even after its OS lease disappears.
`status` exposes the unresolved intent. Independent descendant custody
verification is not implemented. Once you have independently stopped the
native agent and all descendants, use `aswp recover RUN_ID --confirm-stopped`
to record that manual attestation. It refuses while any supervisor holds the
profile lease. This is not independently verified custody and never drives
automatic routing. Preserve state if you are unsure. A normal
direct-child exit is recorded but does not prove its descendants have stopped.

`aswp runs` shows the 20 most recent runs in journal order, including across
wall-clock changes; `--limit` accepts 1 through 200.
`aswp runs RUN_ID` inspects one run, including retired profiles. Aliases show
the profile's current label. History includes a PID and spawn time when observed,
plus a custody state: `unknown`, `exited_uncontained`, `never_started`, or
`attested_stopped`. A pending intent remains unknown even with a recorded PID.
These observations never authorize an automatic switch; stored PIDs are
diagnostics and are never used for process termination. Argument contents are
absent from history.

## Manual handover packs

Use `aswp handover pack`, `inspect`, and `pickup` to carry an existing task note
in an encrypted file. Pickup prints a manual reconciliation note; it does not
launch another agent. See the [handover guide](handover.md) for the complete
workflow, password handling, trust boundary, and limits.

## Directory mappings

```sh
aswp map work /absolute/path/to/project
aswp map
aswp run --dry-run
aswp unmap /absolute/path/to/project
```

Mappings resolve from the current canonical directory to its nearest mapped
ancestor. Renaming a profile preserves mappings because they reference its ID.
Mapping selection is printed to stderr. No match produces a refusal.

## Dashboard

The dashboard follows the selected Night Shift palette. Arrows or `j`/`k`
navigate, `/` searches, `m` masks aliases, `r` refreshes, `?` shows help, and
`q` or Ctrl-C exits. Enter shows launch preflight; it does not start an agent.
Narrow terminals keep profile, harness, and unknown quota visible, with the
selected profile's enabled state below. Terminals smaller than 34 x 10 receive
a compact fallback. Plain commands remain available without a terminal.

## Output and state

Use `--state-dir /absolute/private/local/path` or `AGENTSWAPPER_STATE_DIR` for
explicit state. Otherwise use the platform's local application-data directory.
On POSIX, state directories must be owner-only and files must have private modes;
symlinks inside the state tree, hardlinked registry/lease files, and ownership
mismatches are refused. Trusted parent-directory links are resolved first.
Windows reparse paths are rejected, but ACL privacy has not been verified.
Use local storage: network filesystems and WSL mounted Windows drives have not
passed SQLite/lease validation. Registry aliases, run metadata, and mapping
paths are plaintext local metadata. No credential or transcript import exists.

`--json` emits one object on stdout with `schemaVersion: 0` and a `data` field.
Errors use `data.error.code` and `data.error.message`. v0 is explicitly unstable;
paths in previews and mappings are local diagnostics, not anonymized exports.
Operational text escapes terminal control characters; JSON uses JSON escaping.
Parser errors (invalid syntax or arguments) retain clap's stderr/help behavior.

Exit status: `0` success, `2` argument parsing, `125` AgentSwapper refusal or
internal error, `126` unsafe/non-executable program, and `127` missing program.
Once launched, the native child's exit code is returned. POSIX signal exits
are represented as `128 + signal`; this preview does not re-raise the signal.
Child codes can overlap wrapper codes; use structured preflight for diagnostics.
