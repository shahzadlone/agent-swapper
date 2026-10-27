# AgentSwapper Roadmap

Status: M1a foundations, M1b manual handover packs, and the G0a attached gents client implemented; full milestones remain
open. There are no release dates. A
milestone is complete only when every gate below passes and the evidence (logs,
traces, fixture results) is recorded with the harness versions and OS builds it
was measured on.

## Principles

1. Claude Code, Codex and Kimi Code all launch together, in native mode, in the
   first usable milestone (M1).
2. Controlled adapters are promoted independently, one cell at a time. A cell is
   (adapter, harness version range, OS), with OS one of Linux, macOS, Windows or
   WSL2. A cell moves only after real version and platform tests pass.
   Promoting one adapter neither waits for nor implies another.
3. Sequence: manual switching (M2), then quota automation (M4), then full TUI
   (M5) and tray/service parity (M6).
4. Deferral is sequencing, not removal. The scope register at the end lists the
   full intended feature set. Nothing outside the "rejected by design" list is
   dropped by calling an earlier milestone an MVP.

Support-matrix cell states: `unsupported`, `native-verified`,
`controlled-candidate`, `controlled-promoted`, `revoked`.

## G0 - Optional gents engine qualification

Run alongside M0/M1, independently of the native adapter sequence. The
[deep evaluation](gents-evaluation.md) selects a hybrid design: native support
plus an optional gents process adapter for canonical conversation continuation.
Provider-free consumer contracts live in
[`tools/gents-evaluation`](../tools/gents-evaluation/README.md). The G0a attached-client slice is implemented behind `--experimental-gents`;
see [engine setup and comparison](engines.md). No provider support cell is promoted
and no production gents crate dependency is linked.

G0a implemented:

- `aswp engines` comparison; explicit native/gents profile selection;
- dedicated home, local address and agent binding, with leased rebinds;
- fixed gents chat arguments, durable session UUIDs and an environment allowlist;
- explicit `--resume` with binding/source revalidation and no fallback past uncertain runs;
- local `runtime.json` address check, with listener identity explicitly unverified;
- distinct client-exit history; external runtime custody remains unknown;
- schema-5 migration with backups and preservation of pending runs and unknown legacy sessions;
- provider-free tests for scope, opt-ins, rebinding, custody and tamper refusal.

The following G0 deliverables and gates remain open; the attached client does
not supply runtime ownership, account rotation or canonical replay qualification.

Deliverables:

- A pinned local contract for capabilities, scoped account/usage metadata,
  interrupt, switch/resume receipts, reconnect and context export.
- Dedicated engine agent/profile scope per AgentSwapper lineage; explicit
  frontend/engine/provider/account identities and permission ownership.
- Authenticated local transport, P2P disabled, engine-owned credentials, and
  metadata-only journal references. No direct writes to the engine database.
- Canonical history projection within the engine and capsule-based handover
  between engines; native modes remain independently usable.
- Selected small-crate reuse only when an implemented consumer needs it, with
  pinned versions, license notices, dependency review and protocol drift tests.

Gates:

- The reviewed tool-call identity fix and expanded cross-provider fixtures
  pass, including incomplete/parallel tools, compaction and reasoning affinity.
- Agent/profile isolation tests prove one session's switch cannot move another.
- Unauthorized local metadata/mutation requests fail; tokens never appear in
  argv values, journal entries or logs. No copied native credential lineage.
- Crash injection between profile switch and goal resume reconciles the same
  durable source request without duplicate continuation or uncertain tool replay.
- Selected runtime dependency findings are resolved for the shipped targets.
- Actual frontend permission tests and provider/account-pair tests pass before
  claiming same-conversation switching; no promotion from serialization alone.
- Runtime launch, reconnect and full-writer stop are measured per OS. Unknown
  custody blocks automatic transfer, including transfers out of the engine.

## M0 - Verification spike (no product code)

M0 verification runs in parallel with fixture-based foundation development.
No real-provider support cell is promoted by compiling or by passing fixture
tests. See [support matrix](support-matrix.md).

Deliverables:

- A results document for every harness x OS cell covering:
  - login into an isolated profile using the vendor's own login command;
  - refresh persistence over 48 hours;
  - where credentials live (Keychain, keyring, file) for each storage mode;
  - two concurrent sessions on one profile;
  - resume by session or thread id;
  - graceful-stop and interrupt semantics;
  - which structured protocol each harness exposes, and its version;
  - which quota signals are documented;
  - Kimi storage-layout detection (`KIMI_CODE_HOME`/`~/.kimi-code` vs legacy
    `~/.kimi`);
  - whether WSL2 and the Windows host keep separate credentials.
- A provider-free Unix process-group escape probe is implemented. See
  [custody verification](custody.md) for measured results and remaining gates.
- Crate spikes on all three OSes: `keyring-core` with native stores, `age`,
  bundled `rusqlite`, `portable-pty`, Job Objects, pidfd and cgroup scopes.
- A provider-terms review checklist. This is a user/legal decision; the product
  only records the result.

Gates:

- Every cell has a recorded result of pass, fail or unknown. No cell is
  assumed.
- For each provider, either isolated login works without mutating the global
  login on at least one OS, or that provider ships native-without-isolation
  with an explicit disclosure.
- Crate versions and a license inventory are recorded. Foundation dependencies
  are locked now; provider/OS integration dependencies need this gate.

## M1a - Implemented developer preview

Implemented, unreleased:

- `aswp` and `agentswapper` binaries sharing a Rust core and CLI library;
- validated profile aliases and opaque IDs; register, list, show, rename,
  enable, disable, and unregister without deleting vendor files;
- SQLite append-only events and projections in one transaction, full replay
  verification, and backed-up schema-1 through schema-4 to schema-5 migrations;
- POSIX private modes/owner checks, link refusal, per-profile OS leases, and
  durable run intents that block reuse after supervisor loss, and explicit
  stopped-process attestation for manual recovery;
- durable PID/spawn observations and bounded run history with conservative
  process-custody states;
- native launch plans, argument redaction, direct argv forwarding, known
  inherited-auth conflict refusal, and explicit experimental launch opt-in;
- nearest-directory mapping and JSON schema v0;
- storage/discovery doctor and a searchable, maskable Ratatui dashboard with
  launch preflight;
- fixture subprocess/crash tests, proptest, terminal snapshots, nextest config,
  pinned toolchain, Clippy, dependency policy, and cross-platform CI definition.

This does not complete M0, M1, M2, or M5. Real-provider auth,
process containment, independently verified recovery, config, secret
stores, auto switching, and handover remain open. Secret-store/encryption and
IPC scaffolding are deferred until a concrete consumer exists. Local tests
establish fixture behavior only; CI and provider matrix evidence are separate.

## M1b - Implemented manual handover packs

Implemented, unreleased:

- `handover pack`, `inspect`, and `pickup`, with a draft encrypted schema-v0
  payload that preserves a complete existing HANDOVER.md;
- hidden passphrase prompts, confirmation, cancellation with terminal restore,
  explicit bounded stdin input, and fixed-cost age passphrase encryption;
- authenticated unlock before rendering, bounded decryption cost, exclusive
  output publication, source-location/link checks, and terminal control refusal;
- metadata-only inspection and manual pickup notes with imported-data fences;
- directory and Git HEAD reconciliation, with worktree state explicitly unknown;
- fixture tests for tampering, wrong passwords, credential-location refusal,
  source preservation, drift, and failed/truncated pickup output.

This pulls a manual continuity utility forward while M0/M1 integration work
continues. It does not complete M2: no writer stop, managed switch, native resume,
read-only execution boundary, secret-store key persistence, full capsule-v1
claims/evidence model, or account backup is implied. See [handover](handover.md).

## M1 - Foundations and native launch for all three providers

Deliverables:

- Core library.
- SQLite `event_log` plus projections, committed in single transactions.
- Encrypted blob store and OS secret-store integration.
- Account and profile lifecycle for all three harnesses: add via vendor login,
  list, status, remove, alias, enable and disable.
- `run` (native launch inside containment).
- `doctor`, which reports storage mode, version, cell state and custody
  capability.
- `config` list/get/set/unset/path.
- JSON output schema v1, with a published exit-code table.
- `purge` with `--dry-run`.
- Local IPC skeleton.

Gates:

- argv canary scan: zero canary secrets in any process command line sampled
  during every M1 command (Linux `/proc`, macOS sysctl, Windows process command
  line).
- File audit (inotify / fs_usage / ProcMon): AgentSwapper writes zero plaintext
  secrets. Vendor-owned credential files are reported in `doctor` and are not
  counted as our writes.
- Rebuild: drop all projections, replay `event_log`, and get an identical
  projection dump for a 1,000-event fixture.
- Crash injection: a kill at every write point of the profile and run
  lifecycle recovers consistently in 100% of at least 200 runs per OS.
- Containment: a double-forked descendant is detected and terminated on Linux
  and Windows. On macOS it is detected or the operation is refused. Zero
  escaped writers.
- All three harnesses launch in every M0-verified native cell. Unverified cells
  show a notice instead of failing silently.
- JSON contract tests reject non-additive changes to schema v1.

## M2 - Manual switching and handover

Deliverables:

- Switch state machine, fencing epoch, custody detection.
- Deterministic checkpoints.
- Scoped workspace snapshot to a private ref.
- Capsule v1 and HANDOVER.md rendering.
- `/handover` import and `/handover-pick` pickup integration.
- Same-harness resume where M0 verified it.
- Cross-harness manual handover under a per-workspace egress policy.
- An opt-in global account activation compatibility mode for tested native
  CLI/IDE combinations, separate from managed-session handover. It must refuse
  unknown custody and prove the selected identity before reporting success.
- Side-effect ledger (inferred effects in native mode).
- Directory mappings, slot move and swap, encrypted import/export, token import
  via stdin or TTY.
- Auth diagnosis and quarantine views.

Gates:

- Orphan test: zero writes from a previous epoch by cooperating writers after
  STOPPED_VERIFIED, and zero automatic transfers when custody is unknown.
- Preservation: the user's index and worktree are byte-identical before and
  after a snapshot. The fixture includes partially staged files, untracked
  files and ignored secrets. Ignored and untracked content is never captured
  without an allowlist.
- Redaction: canaries seeded in the environment, `.env` and tool output appear
  zero times in `event_log`, capsules, HANDOVER.md and exports.
- Handover eval: at least 30 tasks interrupted at random points across the
  three harness pairs. Completion stays within a margin of the uninterrupted
  baseline; the margin is fixed and recorded before the run. Zero duplicate
  external side effects against sandboxed external targets.
- Crash injection at every switch transition recovers consistently in 100% of
  runs.
- Export/import: an encrypted round trip succeeds. No plaintext export path
  exists. A wrong passphrase fails closed.

## M3 - Controlled adapter promotion (per adapter, per cell)

Adapters:

- Codex: app-server JSON-RPC.
- Claude Code: print-mode stream-json.
- Kimi Code: ACP.

Each adapter delivers:

- protocol types pinned to the tested versions;
- a capability handshake;
- event capture with intent recorded before execution, where approvals exist;
- automatic checkpoints;
- interrupt and stop;
- native resume.

Gates for each cell:

- The contract suite passes 100% on pinned versions, using dedicated test
  accounts.
- 48-hour soak: two concurrent sessions per profile plus a forced token expiry
  produce zero unexpected logouts.
- An injected version mismatch falls back to native mode in 100% of cases.
- Claude adapter: fixtures prove hooks and MCP loading are explicitly controlled
  in print mode, with zero unexpected hook executions.
- Codex adapter: the cell records whether auth changes require an app-server
  restart. This is measured, not assumed.
- The kill switch disables the adapter with no data loss.
- Promotion and revocation are both exercised and recorded in the support
  matrix.

## M4 - Quota observation and automation

Deliverables:

- Usage readers from documented or promoted sources only.
- Per-window and per-model gates, and per-account thresholds.
- Strategies: `best`, `next-available`, `consume-first`,
  `priority-consume-first`.
- Hysteresis, cooldown and adaptive polling.
- `auto` with `--once`, `--dry-run` and JSONL events.
- CLI `watch`.
- Usage-reading handoff between machines, with holds.
- Explicit Codex reset-credit redemption through the documented method.
- Cross-provider routing under egress policy, and PAUSED_NO_ROUTE.

Gates:

- AgentSwapper performs zero independent token refreshes or copied-lineage
  mutations during polling. Vendor-owned renewal is observed and attributed to
  the vendor process rather than treated as a product failure.
- Deterministic replay of recorded usage traces shows zero ping-pong in the
  hysteresis fixtures. Every decision log line names the window and the line it
  was judged against.
- Abrupt-exhaustion drill: a checkpoint is reached without a final model call
  in 100% of drills.
- Zero routes to API-key accounts unless the user explicitly enabled them with
  a cap.
- Redemption persists the idempotency key before sending, and reuses it after a
  simulated timeout. It never runs automatically.

## M5 - Full TUI parity

Deliverables:

- Dashboard, watch page, auto view and account actions.
- Themes and masking.
- Settings.
- Embedded native sessions (PTY) and structured transcripts for controlled
  sessions.

Gates:

- Every CLI action is reachable from the TUI.
- Snapshot tests show masking hides emails and org names on every screen,
  including event logs.
- The whole TUI is keyboard-only operable.
- ConPTY resize and Ctrl-C tests pass, and the TUI works in the terminals listed
  in the matrix.

## M6 - Tray, services and harness integrations

Deliverables:

- Tray/menu bar: macOS menu bar, Windows tray, and Linux tray where supported.
- Login services: launchd, a Windows per-user mechanism, and a systemd user
  unit, each with install/status/uninstall.
- A background automation engine as an IPC daemon.
- Claude statusline, plus an optional in-harness integration installed from a
  locally verified package.
- `upgrade` with release signature verification.

Gates:

- Install then uninstall leaves no residue.
- Builds are signed, and notarized on macOS.
- Integrations are off by default and restore the previous setting exactly.
- No integration installs from an unpinned remote source.

## M7 - Extended scope

Deliverables:

- Delegated-worker mode: a supervisor-mediated official CLI in a separate
  worktree, read-only by default, with a per-delegation budget.
- Opt-in sharing of definitions and history, where verified safe per harness.
- External security review of the broker, export and IPC paths.

Gate: every review finding is fixed or accepted in writing.

## Scope register (full intended scope)

| Area | Milestone |
|---|---|
| Optional gents engine, canonical continuation, scoped local contract | G0, alongside M0/M1 |
| Native launch, all three harnesses | M1 |
| Account add/list/status/remove/alias/enable/disable | M1 |
| Config, doctor, JSON schema v1, exit codes, purge | M1 |
| Slots, move, swap, directory mappings | M2 |
| Manual switch, capsules, /handover, /handover-pick | M2 |
| Same-harness resume, cross-harness handover | M2 |
| Encrypted import/export (selected and full), token stdin import | M2 |
| Auth diagnosis, quarantine, recovery, stashed-credential review | M2 |
| Controlled adapters (Codex, Claude Code, Kimi Code) | M3 |
| Usage display, thresholds, gates, strategies, auto, watch | M4 |
| Usage sharing with holds, reset credits and banked resets | M4 |
| Cross-provider policy routing | M4 |
| TUI, themes, masking | M5 |
| Tray/menu bar, services, statusline, in-harness integration, upgrade | M6 |
| Delegated workers, shared definitions/history opt-in, external review | M7 |

Rejected by design:

- plaintext exports;
- secrets as positional arguments;
- automatic reset redemption;
- silent API-spend fallback;
- using one vendor's tokens in another client;
- synthesized private session files;
- automatic tool-call replay;
- remote multi-user replication.
