# AgentSwapper Architecture

Status: TARGET DESIGN, with an M1a developer preview implemented. See
[CLI usage](cli.md) and the [support matrix](support-matrix.md) for actual
behavior and limits. No live-account integration is verified. Vendor behavior
is either cited from official documentation
(see References) or is a hypothesis that the verification spike (roadmap M0)
must confirm. The command is `aswp`, with full-length alias `agentswapper`.

## 1. Purpose and boundaries

AgentSwapper is a local, single-user CLI (later a TUI and tray client) that:

- keeps several subscription identities for Claude Code, Codex and Kimi Code as
  isolated native profiles;
- launches and supervises agent sessions under a chosen profile;
- switches accounts within one harness, and hands work from one harness to
  another, through an explicit, recoverable state machine;
- observes quota where a documented signal exists and routes only by policy the
  user has authorized.

Non-goals: proxying model traffic; copying or forwarding subscription tokens to
any other client; making one vendor's subscription usable from another vendor's
harness; synthesizing private session files; remote multi-user replication;
exactly-once external side effects. The later, explicit global activation and
encrypted recovery paths may move credential bytes under a journaled custody
protocol; routine profile launch never copies them. At most one refresh-capable
holder may be active per credential lineage.

A model gateway is not a harness migration and does not transfer subscription
entitlement. Anthropic documents that routing Claude Code to non-Claude models
is not supported. In native mode, cross-vendor continuation therefore means
stopping one official CLI and starting another. An optional execution engine
can instead retain its own canonical conversation while changing providers.
The [gents evaluation](gents-evaluation.md) selects this as an early parallel
qualification track, not a replacement for native adapters. An experimental attached-client slice is implemented; real runtime/provider
pairs remain unverified. See [execution engines](engines.md).

## 2. Identity model

| Identity  | Meaning                                                    | Stored as                         |
|-----------|------------------------------------------------------------|-----------------------------------|
| provider  | Billing/legal vendor (anthropic, openai, moonshot)         | enum                              |
| account   | One login lineage at one provider, owned by the vendor CLI | random `account_ref`, masked label |
| harness   | Agent program plus exact version                           | name + semver + build             |
| engine    | Owner of tools, permissions and conversation execution      | native harness or qualified external runtime |
| frontend  | Visible interface, which may connect to a different engine  | name + version + protocol binding |
| model     | Model requested inside a harness; a capability, not an entitlement | vendor model id            |
| profile   | Directory + env binding where a harness keeps config/auth for one account | path + env var name  |
| session   | Harness-native conversation/thread id                      | scoped to (harness, profile)      |
| run       | One supervised process tree                                | ULID + containment handle         |
| workspace | Repo/worktree identity                                     | canonical path, root, remote hash |
| lineage   | Chain of runs and capsules for one task across switches    | ULID                              |

Rules: emails are display data only and maskable; a session id is never used
outside its harness; resuming a session under a different account of the same
harness is allowed only where an adapter test proves the vendor supports it;
quota is tracked per (account, window) and never summed or compared across
providers or windows.

## 3. Stack decision

| Criterion                          | Rust      | Go                     | Python/Textual       | TypeScript      |
|------------------------------------|-----------|------------------------|----------------------|-----------------|
| Single signed binary               | strong    | strong                 | weak (interpreter)   | medium          |
| Job Objects, pidfd, Keychain FFI   | strong    | good (cgo for Keychain)| indirect (ctypes)    | weak            |
| Typed protocol schemas             | strong    | good                   | medium               | strong          |
| TUI maturity                       | Ratatui, fewer widgets | Bubble Tea, strong | Textual, strongest | Ink, medium |
| Iteration speed                    | slower    | fast                   | fastest              | fast            |

Selected: Rust. The hard parts are process containment, state-machine
correctness, OS secret stores and signed distribution. Future integration
dependencies require their own M0 validation. Current foundation dependency
versions are locked in Cargo.lock for reproducible builds:

- `clap` (CLI), `tokio` (runtime, child processes), `serde`/`serde_json`, JSON
  Schema generation for public output types;
- `rusqlite` with bundled SQLite;
- `ratatui` + `crossterm` for the TUI;
- `keyring-core` with platform-native store crates, as the current `keyring`
  documentation directs applications that choose their own backends;
- the `age` crate for blob encryption;
- `portable-pty` (ConPTY and Unix PTY) for hosting native sessions only;
- `windows-sys`, `rustix`, and libproc bindings for containment;
- `tracing` with a redacting layer.

Costs accepted: slower iteration, async plus PTY complexity, smaller widget set.
Mitigation: a core library with no UI dependency, adapters as separate crates.
The current slice uses synchronous native processes, SQLite, and Ratatui.
Tokio, secret stores, IPC, PTYs, and containment are deferred until
there is an implemented consumer and verified platform behavior.
The manual handover-pack feature now consumes age for explicit password-based
exports, with no stored encryption key. See [handover](handover.md) and
[dependency decisions](dependencies.md) for its draft format and boundaries.

## 4. Profiles and CLI auth ownership

These rules describe native profiles. A future external engine owns its own
login and refresh flow, with separate opaque account references and qualified
entitlements. AgentSwapper does not import native tokens into it. The engine
identity is part of the account/session scope; matching provider names do not
make credentials or sessions interchangeable.

- The vendor CLI owns login, token storage and refresh. AgentSwapper creates a
  profile directory and runs the vendor's own login command inside it via the
  documented environment variable. It never copies credential bytes between
  profiles: one profile is one lineage.
- Claude Code: `CLAUDE_CONFIG_DIR` per profile. Keychain naming on macOS and
  file storage elsewhere are verified per version.
- Codex: `CODEX_HOME` per profile. The credential store chosen per the Codex
  auth documentation is respected; users are never silently moved from keyring
  to file storage. A store mode that cannot be isolated on a platform is marked
  unsupported for that cell.
- Kimi Code: current docs use `KIMI_CODE_HOME` and `~/.kimi-code`; older
  kimi-cli docs use `~/.kimi`. The adapter detects the version and selects the
  layout. The preview has no version detector, reports unverified isolation,
  and requires explicit `--experimental-native` for all native execution.
- Managed-session switching leaves the global default login alone. A separate
  `account activate --global` compatibility operation remains in the parity
  scope for users of an already-open native CLI or IDE. It is opt-in, scoped to
  a tested provider/version/store combination, and prefers a documented vendor
  activation mechanism. Any file-backed fallback requires provider-compatible
  locks, an encrypted recovery journal, identity and lineage checks, and
  post-write verification. Unknown concurrent custody refuses activation.
  Hot pickup is claimed only after an end-to-end check proves the running CLI
  accepted the new account. This mode does not move work between brands.
  The profile and global store cannot both refresh copies of one lineage:
  activation transfers credential custody, holds the profile out of launch,
  and reconciles vendor-owned renewal before custody can return.
- Vendor CLIs may store credentials in plaintext files in some modes.
  AgentSwapper restricts permissions on directories it creates and reports the
  storage mode in `doctor`. It does not promise that no plaintext credential
  exists on disk.
- AgentSwapper's own secrets (blob keys, export passphrases) live in the OS
  credential store. On headless Linux/WSL without Secret Service it refuses, or
  uses a passphrase-protected key file the user explicitly chose. There is no
  silent fallback. Secrets never appear on argv. Token import reads stdin or a
  TTY prompt.
- Explicit encrypted recovery exports may include vendor files only under a
  separate, disclosed backup scope. Restoring them requires idle custody and
  a lineage check; normal switching does not maintain competing token copies.

## 5. Interaction modes and adapters

Target native mode is general compatibility. The vendor CLI runs in the user's
terminal with the profile environment, inside containment. AgentSwapper sees
process lifecycle, workspace state and any hooks the user enabled. It never
switches mid-turn automatically; at exhaustion it offers a handover. M1a has
no containment, exhaustion observation, or handover action; it only offers
explicit experimental launch and preflight.

Controlled mode drives the harness over its official structured protocol, and
enables automation only where support is proven:

- Codex: app-server JSON-RPC (threads, turns, events, `thread/resume`,
  `account/login/start`, `account/rateLimits/read`,
  `account/rateLimitResetCredit/consume` with `idempotencyKey`). Documented
  protocol methods are preferred over hard-coded backend endpoints. The
  external `chatgptAuthTokens` mode is experimental and not used by default.
  Whether a running app-server needs a restart after an auth change is
  verified per version, not assumed.
- Claude Code: print mode with stream-json and resume, per the headless docs.
  `-p` skips the workspace trust prompt and loads hooks and MCP servers unless
  explicitly controlled, so the adapter passes explicit settings and permission
  flags. `--bare` does not use subscription auth and is not used for
  subscription profiles. Flags observed locally on 2.1.310 (`--safe-mode`,
  `--restricted`, `--effort`, `--model`) are used only within pinned, tested
  version ranges.
- Kimi Code: ACP session and control capabilities per the kimi-acp reference.

Promotion: each (adapter, harness version range, OS) cell starts disabled. It is
promoted only after the pinned contract suite passes. Before a session starts,
an unknown version can offer native mode with a notice. A failure during a
running controlled turn pauses for recovery; it never launches a replacement
process before the outgoing run is reconciled. Each adapter has a local kill switch.

PTY fallback: `portable-pty` only hosts native sessions inside the TUI.
Screen-scraped text never drives a switch, a quota estimate, or a "verified"
claim.

Optional engine mode: the implemented first slice attaches `gents chat` to a
separately operated local runtime, with fixed home/address/agent bindings and
explicitly unknown external runtime custody. The full design below still needs
qualification. Qualify gents through a pinned, authenticated local process
adapter. Keep AgentSwapper's SQLite journal, policy and supervision independent;
gents owns its history, credentials and tools. Use a dedicated agent/profile per
lineage to avoid agent-wide model changes affecting unrelated sessions. Show
frontend, engine, provider, account and permission owner separately. Provider
projection may retain the conversation while dropping incompatible reasoning;
moving between gents and a native harness uses the handover capsule. No direct
database mutation or copied credential lineage is part of this integration.
See roadmap G0 and the [evaluation](gents-evaluation.md) for qualification gates.

## 6. Supervisor and process custody

Each session gets a supervisor process. There is no AgentSwapper always-on daemon
before the tray milestone. An optional external engine may need its own runtime
process; that does not waive ownership and shutdown verification. Containment:

- Windows: Job Object with kill-on-close.
- Linux: cgroup v2 user scope where available, else process group, pidfd and
  child subreaper.
- macOS: process group plus descendant scan; no equivalent kernel container
  exists.

Custody is `live`, `stopped_verified` or `unknown`. Unknown custody blocks
automatic transfer. The user may override with an acknowledgment recorded in
the event log.

Fencing: a monotonic epoch per (workspace, lineage) in SQLite, mirrored in a
lease file in AgentSwapper's state directory (not the repo). Cooperating managed
writers (adapters, hooks we install) check it before acting. Fencing does not
constrain native agents or tools that ignore it, which is why stopping the
whole process tree is the primary guarantee.

## 7. Switch state machine

```
ACTIVE -> PREFLIGHT -> QUIESCING -> CHECKPOINTING -> STOPPING -> STOPPED_VERIFIED
       -> RECONCILING -> VALIDATING -> ACTIVATING -> ACTIVE(epoch+1)
side states: PAUSED_NO_ROUTE, NEEDS_HUMAN, ABORTED_WITH_EFFECT_LEDGER
```

Every transition writes an intent event and its projection update in one SQLite
transaction before acting, then commits the outcome.

1. Quiesce: controlled mode interrupts the turn via protocol; native mode sends
   the documented interrupt or asks the user. New approvals stop.
2. Checkpoint: deterministic and model-free (journal tail, scoped workspace
   snapshot, structured plan state). A semantic summary is added only if quota
   remains.
3. Stop all old writers: graceful protocol shutdown, then signal, then container
   kill. Verify the whole tree is gone and scan for survivors whose cwd is inside
   the workspace. If that cannot be determined, go to NEEDS_HUMAN.
4. Reconcile: diff the workspace against the checkpoint; classify side effects.
5. Validate: egress policy, permission ceiling, target capability, adapter
   promotion, account eligibility.
6. Activate: within the same harness, use native resume where verified;
   otherwise start a new session from the capsule. The first target turn is
   read-only reconciliation, enforced through verified permissions or a
   sandbox. If a native adapter cannot enforce this boundary, pickup is
   explicitly manual and is not advertised as protected automatic continuation.

Once routing and egress policy are authorized, a switch does not prompt. Prompts
appear only when policy does not cover the target or custody is unknown.

## 8. Side effects

The ledger has classes `read`, `local_reversible`, `local_irreversible` and
`external`, and statuses `not_started`, `started_unconfirmed`, `confirmed`,
`failed` and `uncertain`. Intent is written before execution where a harness
exposes pre-tool hooks or structured approvals. Otherwise effects are inferred
afterwards and labeled lower confidence. Uncertain effects reach the target as
read-only probes. Re-execution requires a human ack or a vendor-documented
idempotency key. There is no exactly-once guarantee for external effects.

## 9. Workspace snapshots

There are no automatic snapshots of every file. The default scope is tracked
files, captured with git plumbing, a temporary `GIT_INDEX_FILE`, and a private
ref under `refs/agentswapper/`. The user's index and worktree are untouched.
Untracked and ignored files are excluded unless an explicit allowlist names
them; those are stored as encrypted private blobs, not git objects. A fixed
denylist (`.env*`, key material, credential directories) always applies.
Non-git workspaces get hashes of allowlisted paths only.

## 10. Context capsule

The manifest is canonical JSON. HANDOVER.md is rendered from it plus a bounded,
hash-bound free-text section.

```
schema_version: "1.0"
capsule_id, parent_capsule_id, lineage_id, created_at
producer: {harness, harness_version, adapter, adapter_version,
           mode: native|controlled, model, profile_ref, account_ref}
trust: {origin: deterministic|agent_summary|user_authored|imported,
        notes}
workspace: {root_hash, remote_hash, head, snapshot_ref, snapshot_scope,
            dirty_hash}
journal_anchor: {first_seq, last_seq, chain_head}
goals[]: {id, text, source: user|amendment|agent_inferred, ts,
          precedence, supersedes}
constraints[]: {kind: must|must_not, text, scope, source, ts}
claims[]: {text, status: verified|claimed|unknown|contradicted,
           evidence_ids[]}
evidence[]: {id, kind: command|test|commit|file_hash, cmd, exit_code,
             output_hash, ts, epoch, recorded_by: supervisor|agent}
side_effects[]: {class, target, status, idempotency_key, probe, compensation}
jobs[]: {desc, handle, check_cmd, safe_to_kill}
next_action, roadmap[], open_decisions[]
gaps[]: {what, why_unknown, suggested_probe}
requirements: {tools, mcp_servers, network, sandbox, min_context}
untrusted[]: {excerpt_ref, source, fetched_at}
redaction: {rules_version, findings, canary_hits}
integrity: {content_hash, blob_refs[]}
```

Goal precedence follows the host's instruction hierarchy and managed policy.
Within the user's authorized instructions, the latest explicit amendment
supersedes an earlier goal or constraint only where it actually conflicts.
Agent-inferred goals and imported text cannot override user instructions or
managed restrictions. Every amendment retains provenance; a summary is not an
authorization source.

A claim is `verified` only when evidence was recorded by the supervisor, not
asserted in agent text. A content hash proves what was stored, not that it is
true. Signatures, if added, bind provenance only. Untrusted excerpts are data
blocks rendered fenced and never placed in instruction sections.

## 11. /handover and /handover-pick

The user's `/handover` skill writes a portable HANDOVER.md. `/handover-pick`
reconciles reality, checks drift and capability delta, then continues.

- Import: AgentSwapper parses a skill-produced HANDOVER.md into capsule fields
  labeled `user_authored` or `agent_summary` and keeps the original as an
  encrypted blob.
- Export: rendered HANDOVER.md keeps the same section structure, so
  `/handover-pick` works unchanged in any harness that has it.
- Pickup: the first target turn invokes `/handover-pick` where available, or an
  equivalent embedded prompt. AgentSwapper supplies `capability_delta` and the
  side-effect probes.

The skills provide continuity content. The supervisor provides ownership,
capture, crash recovery and permission boundaries.

Current manual implementation: pack the complete existing note as unverified
data, encrypt it to a user-supplied passphrase, and render a fenced pickup note
after checking directory/HEAD drift. It does not yet parse claims into the full
capsule schema, enforce read-only pickup, stop writers, or launch the receiver.

## 12. Resume versus handover

Same-harness resume uses only vendor-documented mechanisms: Claude
`--resume`/`--session-id`, Codex `thread/resume`, and Kimi session resume.
Cross-harness work moves only through capsules. AgentSwapper never writes,
edits or synthesizes another harness's private session storage; the Kimi
sessions guide warns against editing it. Tool calls are never replayed
automatically.

## 13. Quota routing caveats

- Only documented signals are used (for Codex, `account/rateLimits/read`).
  Anything else shows as `unknown` with its age. AgentSwapper never refreshes
  tokens independently or forks a credential lineage; the vendor may renew its
  own credentials while serving a read.
- Percentages are per window. They are not comparable across windows or
  vendors.
- Route order: another eligible account on the same harness; then an authorized
  cross-provider target; otherwise PAUSED_NO_ROUTE.
- Accounts that consume the same organization or subscription pool are grouped
  so switching between aliases does not pretend to create new capacity. Model,
  tool, context, privacy, and latency requirements filter routes before quota
  ranking. Unknown quota is not treated as an unused allowance.
- There is no silent API-spend fallback. API-key accounts join routing only if
  the user enables them explicitly, with a spend cap.
- Banked resets and credits are spent only on explicit user action. The
  idempotency key is persisted before sending and reused on retry.
- Provider terms may restrict rotation. Policy is user-attested, and adapters
  degrade to native mode if a vendor forbids a mode.

## 14. Egress and permission boundary

A cross-provider handover discloses workspace content to a new provider. Each
workspace has a stored, revocable allowlist of providers. Target grants are the
workspace ceiling, intersected with target capability, intersected with grants
marked portable. Approvals never transfer implicitly. Delegated-worker mode
(later) runs in a separate worktree, read-only by default.

## 15. Storage and secure storage

One SQLite database lives in local app data (WAL mode, never in synced folders):

- an `event_log` table: append-only, with seq, epoch, kind, a bounded redacted
  payload and an optional blob ref;
- projection tables: accounts, profiles, sessions, runs, switches,
  side_effects, capsules, policies.

Each event and its projection update commit in one transaction. A rebuild test
regenerates the projections from `event_log`. JSONL is an export for audit only:
it is not authoritative and is never applied as state without validation.

Sensitive context (capsule bodies, snapshot blobs, imported HANDOVER.md) is
stored as age-encrypted, content-addressed files. The database holds only
bounded, redacted metadata and opaque refs. There is no full-database
encryption claim.

Redaction combines format rules and, when explicitly supplied, in-memory
matching against known secret values. Synthetic canaries test the capture
pipeline. Content hashes alone do not detect or redact secrets, and entropy
heuristics are not a guarantee. Raw tool output is excluded by default;
captured context follows an allowlist and is encrypted.

Writes use temp, fsync, rename and a directory fsync, plus `F_FULLFSYNC` on
macOS and replace-retry on Windows.

## 16. Local IPC

- POSIX: a Unix socket in a 0700 per-user runtime directory, with a peer
  credential check.
- Windows: a named pipe whose ACL is limited to the current user SID, rejecting
  remote clients.
- Protocol: versioned JSON-RPC 2.0, with no TCP listener.

The CLI, TUI and tray are all clients.

## 17. Crash recovery

At startup the supervisor finds intents that have no committed outcome and runs
their idempotent handlers. Each handler re-checks custody, then re-attaches to
or stops a surviving tree, or goes to NEEDS_HUMAN. It never auto-retries an
external effect.

Deterministic checkpoints run:

- on a timer;
- every N events;
- before external-class tools;
- at a quota reserve band.

This way abrupt exhaustion needs no final model call.

## References (official; recommendations above are ours)

- Codex app-server: https://developers.openai.com/codex/app-server/ (currently
  redirects to https://learn.chatgpt.com/docs/app-server)
- Codex auth and credential storage: https://developers.openai.com/codex/auth/
- Claude Code headless/print mode: https://code.claude.com/docs/en/headless
- Claude Code LLM gateway: https://code.claude.com/docs/en/llm-gateway
- Kimi ACP: https://moonshotai.github.io/kimi-code/en/reference/kimi-acp
- Kimi sessions: https://moonshotai.github.io/kimi-code/en/guides/sessions.html
- keyring crate: https://docs.rs/keyring/latest/keyring/
