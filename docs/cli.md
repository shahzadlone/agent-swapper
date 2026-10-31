# CLI developer preview

The command is `aswp`; `agentswapper` is the full-length alias. Both binaries
share the same implementation and state. Build from source using
[CONTRIBUTING.md](../CONTRIBUTING.md). No release or package installation is
published yet.

Run `aswp` without arguments in a terminal to open the dashboard. Piped invocations
show help, and `aswp --json` returns the command summary without opening state.
The current dashboard is a basic preview; the [terminal UX contract](terminal-ux.md)
defines the complete experience being built. `Ctrl-P` toggles privacy even while
searching or adding a profile; masked input stays hidden. Press `a` to register
a native or gents profile through the dashboard. Setup reviews the details before
creation, supports `Esc` to go back and `Ctrl-G` to cancel, and uses Page Up/Down
to scroll on small terminals. Registration does not log in or start an agent.

Enter reviews a new launch, `l` reviews native login, and `c` reviews the latest
eligible gents session. The review shows the destination, workspace ownership and
continuity method; Space accepts its experimental status and Enter starts it.
Unmask with Ctrl-P first: dashboard privacy does not cover an agent's output.
The agent receives the normal terminal, and its exit returns you to the selected
profile with the result recorded. A failed launch exits to the shell rather than
assuming the terminal is safe to reuse. Native launches here start a new
conversation; cross-agent context pickup remains the manual
[handover workflow](handover.md). Check outgoing work and background jobs before
starting another agent. Native resume and gents login are unavailable in this flow.
Press `n` to rename the selected profile or `d` to review unregistration.
Unregistration needs Space followed by Enter, keeps agent files and does not
revoke a subscription login. Busy/unresolved profiles are refused. If a peer's
label/binding change is noticed during review, the dialog refreshes that identity
and requires review again. Ctrl-U clears the rename field; Ctrl-P keeps input
and errors private in either dialog.

## Everyday commands

```sh
aswp engines
aswp profile add claude --alias work
aswp profile add codex --alias personal
aswp profile add kimi --alias research
aswp list
aswp profile show work
aswp status
aswp runs
aswp runs RUN_ID --json
aswp doctor
aswp config
aswp registry verify
aswp tui
```

Registration creates an empty profile. It does not authenticate, discover your
email, inspect credential files, or establish available quota. `doctor` checks
registry integrity, profile directories and CLI preferences, and discovers executables on PATH;
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
variable is not a sandbox. Default launches have no process-tree containment.
Native resume verification, automatic account rotation and managed cross-agent
takeover are not implemented. Do not
use experimental profiles for sensitive production work.

Known inherited auth, base-URL, billing-route, and selected home variables cause
a refusal, with variable names only. Other harnesses' home variables are removed
from the child environment. This list is conservative and cannot
cover every vendor version. Arguments after `--` go directly to the native
program without shell interpolation. They can still instruct the native
program to read or write other paths. `--executable /absolute/path` explicitly
selects a trusted entrypoint. Unix executable scripts (including installed
shebang entrypoints) are supported; Windows requires an `.exe`. Batch and
PowerShell shims are refused. On Unix, the executable, symlink owners and every
directory traversed must be owned by root or the current user. Files and direct
entrypoint/link directories cannot be writable by other users; sticky shared
ancestors such as `/tmp` are allowed above trusted directories. Validation runs
when planning and again before launch. This checks permissions, not signatures,
script interpreters or immutability against another process with the same user.

For Kimi this includes known OAuth endpoint/header overrides, temporary
`KIMI_MODEL_*` settings, legacy migration-source overrides and Google SDK
credential-file selection. The current CLI's source contract and its remaining
migration/isolation limits are recorded in the [support matrix](support-matrix.md#kimi-source-contract).
Kimi launches refuse a detected or indeterminate legacy home unless you opt in
for that launch with `--allow-kimi-legacy`; the check does not read or migrate
the legacy files and cannot prevent later external changes.
For Codex it includes access tokens, workload-identity configuration and the
SQLite state-directory override. Custom provider credential variables are not
enumerable from the environment alone, so these checks do not prove isolation.
Claude launches also check for documented shared Anthropic profile indicators;
an explicit `--allow-claude-shared-auth` permits one launch when one is present
or the location is indeterminate. Managed settings and other credential sources
remain unverified; see the [support matrix](support-matrix.md#claude-source-contract).

Launch previews show argument counts, never argument contents. They do not
reserve a profile or guarantee a later launch will succeed. Native stdout
belongs to the child, so actual launches cannot use `--json`.
Both the preview and the launch message identify explicitly bypassed provider
preflights; a bypass does not establish that the selected account is isolated.

On Unix, a launch with a foreground controlling terminal attached to stdin,
stdout or stderr saves its attributes and restores them after the child is
observed to exit. When streams are redirected, it also tries `/dev/tty`; an
unavailable or non-foreground controlling terminal is left alone. If the foreground changes or
restoration fails, the command reports `terminal_restore_failed`; run history
still records the child's actual exit. A non-controlling PTY is left to its
owner. Supervisor crashes and uncontained descendants remain separate custody
limitations.

On Windows, the experimental launch path now captures console input/output modes
through owned handles, including `CONIN$`/`CONOUT$` when standard streams are
redirected. It restores and reads back those modes after the observed child exit;
the optional Job path first stops its remaining local descendants. A failed
restoration is reported after journaling the actual exit. This does not restore
an entire screen buffer, a supervisor crash or external work. The six disposable
console cases passed at `08facc1` in
[Windows CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40959372054/job/123747795279).
Interactive ConPTY launches, resume, privacy, resize, rename and unregister
also passed at `16053be` in
[Windows CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40975543816/job/123802538596).
Other applications sharing the same Windows console are not
isolated from mode changes.

A profile lease, stored outside the native home, prevents simultaneous launches by cooperating AgentSwapper
processes. A durable intent is written before spawn. An interrupted supervisor
leaves an unfinished run and blocks reuse even after its OS lease disappears.
`status` exposes the unresolved intent. A default native launch does not verify
descendant custody. Once you have independently stopped the
native agent and all descendants, use `aswp recover RUN_ID --confirm-stopped`
to record that manual attestation. It refuses while any supervisor holds the
profile lease. This is not independently verified custody and never drives
automatic routing. Preserve state if you are unsure. A normal
direct-child exit is recorded but does not prove its descendants have stopped.

`aswp runs` shows recent runs in journal order, including across wall-clock
changes. The default is 20; `config set history.limit N` saves another default,
and `--limit` overrides it. Both accept 1 through 200.
`aswp runs RUN_ID` inspects one run, including retired profiles. Aliases show
the profile's current label. History includes a PID and spawn time when observed,
plus a custody state: `unknown`, `exited_uncontained`, `never_started`, or
`attested_stopped`. The opt-in Windows backend can record `local_scope_empty`,
with the planned `localScope` backend and UUID. This says its owned Job was
observed empty; external work remains unverified. Gents client exits and client-stop attestations report
`external_runtime_unknown`. A pending intent remains unknown even with a recorded PID.
These observations never authorize an automatic switch; stored PIDs are
diagnostics and are never used for process termination. Argument contents are
absent from history.

### Experimental Windows process supervision

```sh
aswp run work --dry-run --experimental-containment windows-job
aswp run work --experimental-native --experimental-containment windows-job
```

Also available for `login`. The native target starts suspended until its owned
Job assignment and PID record succeed. When the initial CLI exits, remaining
local descendants are terminated and the Job is queried for emptiness. The
initial CLI's exit code is preserved. This changes background-child behavior;
preview the plan before choosing it. Gents and other platforms refuse this option.
The CLI first joins a process-lifetime root Job, which also affects other
children it creates after opting in. An incompatible existing Job hierarchy
causes the launch to fail rather than fall back to uncontained execution.

Any ambiguous admission, wait, cleanup or journal error leaves an unresolved
intent. `supervision_incomplete` identifies that run and gives the history
inspection command without printing native arguments or error-source contents.
A crashed supervisor's Job may clean up its descendants, but that alone
does not write an empty receipt or unblock reuse. This option is not a credential/filesystem sandbox
and does not contain work delegated to services or external runtimes. See
[measured custody results and limits](custody.md).

## Optional gents engine

```sh
aswp profile add --engine gents --alias relay --address 127.0.0.1:9191 --agent YOUR_AGENT_ID
aswp profile show relay --json
aswp run relay --dry-run
aswp run relay --experimental-gents
aswp run relay --experimental-gents --resume
aswp runs
```

Initialize, authenticate and start the dedicated gents runtime separately before
launching. The profile's home, address and agent fix the client's route; forwarded
arguments and native login are refused. `--session UUID` continues or creates an explicit
gents session with the bound agent. New launches record a fresh UUID before spawn.
`--resume` returns to the latest tracked attempt only when its client exited
successfully and its binding still matches; failed or uncertain attempts block
resume without falling back. It conflicts with `--session`. These are local
references, not proof of remote session existence or completed runtime work.
Native resume arguments still go after `--`.

`profile bind` changes the address/agent without replacing the
home. `run --engine native|gents` asserts the profile's engine selection.

Gents owns its tools, credentials, permissions and configured workspace. A client
exit does not stop runtime work. See [engine setup and comparison](engines.md)
for the complete workflow, trust boundary and current qualification limits.

## Manual handover packs

Use `aswp handover pack`, `inspect`, and `pickup` to carry an existing task note
in an encrypted file. Pickup prints a manual reconciliation note, or saves
plaintext with `--output HANDOVER_PICKUP.md` while keeping context out of stdout.
It does not launch another agent. See the [handover guide](handover.md) for the complete
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

## Preferences

`aswp config list/get/set/unset/path` manages typed display preferences independently
of the registry. Save history length with `config set history.limit 50` or start
masked with `config set ui.mask true`. Explicit `runs --limit`, `tui --mask` and
`tui --show-aliases` override saved values. See [preferences](config.md) for
storage, precedence, JSON output and recovery.

## Dashboard

The dashboard follows the Distinction palette. Arrows or `j`/`k`
navigate, `/` searches, `m` masks aliases, `r` refreshes, `?` shows help, and
`q` or Ctrl-C exits. Enter reviews a fresh launch, `l` reviews native login,
and `c` reviews the latest eligible gents session. Space accepts the experimental
launch and Enter starts it; Ctrl-P must unmask first. Esc or Ctrl-G cancels review.
`e` enables or disables the selected profile for future launches; it does not
stop existing work. Actions follow stable profile IDs, so renaming or reusing an
alias from another terminal cannot redirect an availability, rename or unregister
action. `n` opens rename and `d` opens unregister review; Esc cancels either.

Wide terminals show selected-profile details beside the list. Narrow terminals
keep profile, agent and availability state visible, with unmeasured quota in the
details below. Refresh preserves selection by ID. Masked labels remain stable
across filtering and renaming; Ctrl-P toggles privacy even during search or help.
Errors are escaped, with identifiers hidden in privacy mode. Terminals smaller
than 40 x 14 receive a compact fallback. Plain commands remain available without
a terminal.

On Windows, each dashboard phase preserves its original console input/output
modes, enables VT output for rendering, then restores the original modes before
an agent takes over or the dashboard exits. This explicitly handles the terminal
library's cached ANSI support across repeated launches. The dashboard requires
a console that accepts VT output; native shell commands remain independently usable.

On POSIX, external SIGINT, SIGTERM and SIGHUP requests leave raw mode and the
alternate screen before terminating with the original signal. This applies to
dashboard exits; native agent sessions use their own launch/supervision paths.

## Output and state

Use `--state-dir /absolute/private/local/path` or `AGENTSWAPPER_STATE_DIR` for
explicit state. Otherwise use the platform's local application-data directory.
On POSIX, state directories must be owner-only and files must have private modes;
symlinks inside the state tree, hardlinked registry/lease files, and ownership
mismatches are refused. Trusted parent-directory links are resolved first.
Windows state access validates NTFS ownership/ACLs and retains directory guards;
broad ACLs and reparse paths are refused without repair. The volume-root guard
can conflict with unrelated directory writers. Vendor-file privacy remains
unqualified and `doctor` still reports `acl_not_verified`; see
[Windows storage evidence](windows-acl.md).
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
For shell `run`/`login` commands, the native child's exit code is returned. In the
dashboard it is recorded and displayed before returning to profile selection;
quitting the dashboard normally returns 0. POSIX child signal exits
are represented as `128 + signal`; this preview does not re-raise the signal.
Child codes can overlap wrapper codes; use structured preflight for diagnostics.
