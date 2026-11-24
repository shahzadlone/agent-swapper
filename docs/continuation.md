# Shutdown checkpoint: 2026-11-03

The user requested a pause after this checkpoint for a system shutdown. Resume
only when requested. The release-hardening goal is unfinished; this document is
a resume point, not release approval.

## Saved work

- Work directly on `main`. All extra local and remote branches and temporary
  worktrees were removed at the user's request. Do not recreate them.
- `6bde1d1` implements protected socket inode/path checks, root PID-1 listener
  credentials and policy rechecks around connection. Activation, generation,
  journal and Store/terminal fixtures share the same authenticated manager
  connection through socket and service admission.
- `80df3ed` adds deterministic permission-change races before and after the
  connection. Both must refuse before sending bytes. The fixture independently
  checks connection counts, socket restoration, absence of worker artifacts and
  retirement of any activated guardian. Qualification barriers do not exist in
  default builds. This does not yet test pathname replacement during connection.
- The fresh-entry alternative is preserved in
  [linux-fresh-entry-design.md](linux-fresh-entry-design.md); it is a proposal,
  not an implemented topology. Production managed launch remains disabled.

## Evidence and first action on resume

1. Check [CI 41668603562](https://github.com/shahzadlone/agent-swapper/actions/runs/41668603562)
   for `a293c23`, and find the CI run for the final pushed `main` checkpoint
   containing `80df3ed`. They were pending at the shutdown checkpoint. Inspect
   job/annotation evidence at the exact SHA; a queued or slow run is not a failure
   and must not be blindly restarted. Address any failures on `main`.
2. The earlier observation-only checkpoint `425db79` passed its complete
   [pipeline 41666325873](https://github.com/shahzadlone/agent-swapper/actions/runs/41666325873).
   The main cleanup-rule commit `b8bd75e` passed
   [pipeline 41665747889](https://github.com/shahzadlone/agent-swapper/actions/runs/41665747889).
   These results do not qualify the newer endpoint connection or race controls.
3. At `80df3ed`, local checks passed: 15 manager unit tests, qualification
   doctests, default API doctests (4 positive and 9 negative), 62 Linux Python
   fixture controls, strict manager/evaluator Clippy and the dependency/feature
   boundary check. Native permission races remain unverified until CI completes.
   No privileged fixtures or provider logins ran on the developer machine.

Local logs and status snapshots are preserved outside build outputs in
`.research/checkpoints/2026-11-03-endpoint-races/`. Historical branch commits,
the original uncommitted drafts and the branch inventory are recoverable from
`.research/branch-cleanup-20261103/`; the bundle was verified before deletion.
Completed local build outputs are cleaned before pausing. Rebuild only for the
next required check, retain only active caches, and clean them after use.

## Next implementation work

After assessing the pending CI evidence, add adversarial endpoint-path replacement
coverage, including cases where the retained inode itself remains unchanged.
Then complete the production guardian/helper/shim and fresh CLI entry composition,
real launch-plan/Store/terminal integration, installation/update/removal with
active-generation preservation, and authenticated restart recovery. See
[socket policy](linux-socket-policy.md),
[production integration](linux-production-integration.md) and
[release review](linux-release-review.md) for the current boundaries.

Other platform containment, provider privacy/resume/permission behavior, gents
ownership and cross-engine replay, quota/fallback automation, and release
packaging/signing gates still need their corresponding implementation or evidence.
Do not mark the broader goal complete from the Linux socket checkpoint alone.

The namespace-origin implementation's independent review remains open: Opus
returned a safety-classifier refusal without a usable implementation audit.
Do not count that as approval or resubmit it to bypass the refusal.

The user has login subscriptions for Claude, Codex and Kimi and explicitly asked
to defer requesting disposable test profiles until all provider-free work is
finished. Do not ask for credentials or run real-provider qualification now.
Continue using conventional commits, Apache-2.0 and the existing AgentSwapper
name/`aswp` command. Preserve the accepted README artwork and theme.

# Resume session: 2026-11-20

Resumed autonomously after the 2026-11-03 shutdown. Progress since `a61b90f`,
all on `main` with CI evidence where noted:

- `9eb75d4` fixed the `80df3ed` rustfmt regression that failed run
  [41670414526](https://github.com/shahzadlone/agent-swapper/actions/runs/41670414526);
  the complete pipeline passed at `9eb75d4`
  ([44856598355](https://github.com/shahzadlone/agent-swapper/actions/runs/44856598355)).
  The earlier failing steps were diagnosed locally: workspace format was the
  only real regression; the transport-baseline refusal on the developer
  machine is the inherited `CAP_WAKE_ALARM` bit, not a code defect.
- `16c4180` added the four deterministic endpoint race phases (`pinned`,
  `replaced`, `validated`, `connected`) with a third qualification barrier
  between pathname validation and connect, plus pathname-replacement
  coverage. The first replacement helper renamed the retained inode aside,
  which bumps its ctime and refused on the retained-fd stamp before the
  pathname comparison could run (native failure in run 44857838695).
- `56ae933` replaced that helper with a root bind-mounted live impostor
  socket with identical metadata; the retained inode and its metadata stay
  untouched. All four phases passed natively on both Ubuntu images in
  [44858871208](https://github.com/shahzadlone/agent-swapper/actions/runs/44858871208),
  recorded in [socket policy](linux-socket-policy.md).
- `f785e68` landed the socket-race audit follow-up: stranded-impostor
  cleanup, instantaneous-mapping and deadline-ordering comments, and the
  structural byte-freedom and initial-namespace peer-credential notes.
- `211f252` added the producer-side installation transaction
  (`agentswapper-linux-runtime::install_plan`): fixed layout parity with the
  installed readers, deterministic unit texts matching the loaded socket
  policy, manifest/selector serialization, atomic same-directory staging with
  single-link verification, selector replacement and full rollback. Passed
  full CI at `211f252`. Executing the plan with privilege and
  install/upgrade/removal tests remain open gates.
- `97d572b` moved the manager snapshot validation into the runtime crate
  (`manager_snapshot`) without the uuid dependency; core keeps a
  compatibility re-export. Passed full CI at `97d572b`.
- `2160779`/`9581ac4` added the production fresh-entry bootstrap
  (`agentswapper_linux_runtime::fresh_entry`): queued original stdin with
  in-band terminal identity over a private sequenced-packet socket, exec
  thread teardown, failed-exec restoration, and peer/identity/rights
  refusals. Qualification of the composed entry remains open.

Independent audits this session: the Linux origin crate (audit-sol,
APPROVE-WITH-NOTES, no code defects; local CAP_WAKE_ALARM notes recorded) and
the 6bde1d1/80df3ed socket hardening (general-purpose; medium findings
closed by the new phases). The required independent review of exec-held
journal ordering, queued exits and the surviving owner is in progress;
its findings must be addressed before any production launcher promotion.

A pre-existing flake was observed twice in
`admission_transport::tests::socket_reset_is_not_attributed_to_a_queued_record`
(clean EOF observed instead of the reset refusal); not reproduced in
isolation and not yet diagnosed. Watch CI.

Next implementation work: address the journal-composition review findings,
then the installer executor with install/upgrade/removal tests, then
production helper entry composition. Do not enable production managed launch
from any of this; gates live in [production integration](linux-production-integration.md).

# Session continuation: 2026-11-21

- `38f4bbe` closed every finding from the two independent reviews of this
  session: install_plan post-rename rollback tracking, atomic non-replace
  links, created-directory fsync, the sockets.target install section and the
  never-rollback committed-selector rule; fresh_entry loader-environment
  refusal, untrusted-canary refusal, trailing-record refusal, bounded
  identity receive and unmasked exec-error reporting; plus the
  AdmissionJournal durability contract and the 128+signal fixture note.
- The journal-composition independent review (audit-sol) returned
  APPROVE-WITH-NOTES: exec-held ordering, queued-exit attribution, surviving
  owner authority and retirement-value acceptance all pass; the notes are
  addressed. This satisfies the required independent source review for the
  fixture composition; a production adapter still needs its own review.
- `9bb91d7`..`dfdf831` added the disposable install/upgrade/removal
  transaction exercise and qualified it natively on both Ubuntu images in
  [44909060150](https://github.com/shahzadlone/agent-swapper/actions/runs/44909060150):
  staging cross-validated through the installed readers at the derived fixed
  paths, overwrite refusal, atomic selector upgrade with old-generation
  retention, full rollback, dangling-selector refusal after removal and
  fresh-inode re-installation. Two CI-step environment lessons: the scratch
  root needs protected root-owned ancestry (not /tmp) and an executable,
  non-nosuid filesystem (not /run); refusals now surface as step annotations.
- The composition test for fresh entry exercises prepare → exec → assume
  with PID/group preservation, marker input delivery and canary refusal.

Next implementation work: the three production helper images and their
entry points, the installer executor and CLI/doctor surface, launch-plan/
Store composition, and authenticated restart recovery. All enablement gates
remain in [production integration](linux-production-integration.md).

# Session continuation: 2026-11-21 (second)

- `e0970d6`..`c9218d6` added the `agentswapper-linux-install` executor crate
  and qualified it end to end on hosted systemd in
  [44930204914](https://github.com/shahzadlone/agent-swapper/actions/runs/44930204914):
  bounded argument-validated systemctl control, root install of real
  generations at the fixed paths, ordinary-caller verification through the
  namespace origin and authenticated manager transport, selector upgrade
  observed by the reader, inactive removal, active-removal refusal, and
  deselect-plus-removal restoring an unselected host. The executor performs
  no launch. `deactivate` is the administrator's way out of the active-removal
  refusal. The dependency boundary check now pins the install crate's default
  graph.
- CI lessons encoded in the workflow: installer scratch roots need protected
  root-owned ancestry (not /tmp) and an executable non-nosuid filesystem (not
  /run); generations are exactly 32 hex characters; the installer entry
  examples keep unconditional `main` functions so non-Linux clippy stays
  green; refusals surface as step annotations because anonymous CI log
  access is gone (annotations via the checks API are the only readable
  channel).

Next implementation work: the three production helper images and entry
points, the CLI/doctor surface for install/verify/removal, launch-plan/Store
composition, and authenticated restart recovery.

# Session continuation: 2026-11-21 (third)

- `ca3baff` ported the activation packet discipline to the runtime crate
  (`activation_packet`): one kernel credential per packet, exactly one
  descriptor only for terminal responses, every refused capability closed, a
  single ECONNRESET retry that preserves the original deadline, and the
  4096-byte record bound, using the existing rustix ancillary graph. Full
  pipeline passed.
- `4c029f0` added the shared authenticated exit vocabulary (`target_exit`):
  the pinned journal serialization shape and a Linux wait-status decoder that
  refuses stopped/continued targets, validates the real-time signal range
  and preserves core-dump information. Full pipeline passed.
- The installer crate (`agentswapper-linux-install`) and its hosted lifecycle
  remain qualified at `c9218d6` (see the second continuation note).

Next implementation work: the three production helper entry points built on
the now-shared runtime pieces (activation packets, target exit, fresh entry,
launch envelope, admission transport), then the CLI/doctor surface, the
launch-plan/Store composition and authenticated restart recovery.

# Session continuation: 2026-11-21 (fourth)

- `ca01d4f` added helper self-observation (`self_image`): after exec, a
  helper re-derives its own digest, ownership, mode, link count, mount
  policy and file capabilities from `/proc/self/exe`.
- The guardian entry crate binds the running bytes to the installed
  manifest: it parses its manager-assigned unit name (`%n`) into the
  installed user, opens the manifest with the service's own fixed group,
  requires the digest, single root-owned 0755 image, mount and capability
  policy, and the fixed service identity, then refuses at the not-yet-enabled
  production service protocol gate. The installed template passes `%n`.
- `82d9196`..`7b68a8c` extended the hosted lifecycle with that control:
  the INSTALLED guardian image runs, binds to its own bytes and refuses at
  the gate. The complete pipeline passed at `7b68a8c`
  ([44963920154](https://github.com/shahzadlone/agent-swapper/actions/runs/44963920154)).
  CI lessons: `install` takes images in guardian/session-helper/exec-shim
  order; the control must exec the installed image, not the build output;
  the guardian group comes from the service identity, not the unit stem.

Next implementation work: the guardian's production service protocol
(authenticated activation request, offer, launch envelope, held exec,
terminal relay, authenticated exit and retirement) built on the qualified
runtime pieces, then the session-helper and exec-shim entries, the
CLI/doctor surface, and authenticated restart recovery.

# Session continuation: 2026-11-21 (fifth)

- `1e62fb8` implemented the guardian's production activation service and the
  shared offer vocabulary: the systemd-activated guardian verifies the fixed
  ordinary identity, the initial namespace, the kernel message sender and
  systemd's connection-instance naming (`<counter>-<peer pid>-<peer uid>`),
  reads exactly one bounded production request (`ASWPBIND1`/`ASWPRUN1`),
  sends the bounded offer, and refuses launch data ("production launch data
  is not accepted yet") until the launch protocol is separately qualified;
  bind sessions end at a kernel-confirmed clean disconnect.
- The ordinary activation client (`activation_client`) observes the loaded
  socket policy, connects the protected endpoint, sends the bind request,
  validates the offer against the kernel sender, binds the original service
  and claims its one-use key.
- `8631b35`/`e8231ed` qualified the complete production activation round trip
  on hosted systemd: the installed guardian image runs as the real service
  instance, the client's authenticated connection activates it, the offer is
  validated, the service binding claims its key, and the activated instance
  retires after the clean disconnect. Full pipeline passed at `e8231ed`
  ([44974572857](https://github.com/shahzadlone/agent-swapper/actions/runs/44974572857)).
  CI lessons: the direct-run guardian control now proves self-binding and
  rejects at the invocation/phase boundary (its stdin is not a socket under
  bash); the `install` image order is guardian/session-helper/exec-shim.

Next implementation work: the launch protocol itself — launch envelope
transfer over the authenticated connection, the exec shim's held exec, the
durable intent and GO discipline from the journal client, the terminal relay
composition, authenticated target exit and scope retirement. The fixture
machinery (journal_client, managed_terminal_relay, activated_terminal) is
the qualified reference for every step.

# Session continuation: 2026-11-21 (sixth)

- `8106e0e`/`4310b66` framed the production launch protocol in the runtime
  crate: the launch gate, exec release, exec confirmation and authenticated
  target-exit report frames — exact-length versioned sequenced-packet
  records with no transferred capability, bound to the run nonce and the
  original child identity, with the withdrawal peek that distinguishes a
  clean client disconnect from any queued record. Full pipeline passed at
  `4310b66`
  ([44977531483](https://github.com/shahzadlone/agent-swapper/actions/runs/44977531483)).

Next implementation work, in order:
1. The guardian's launch phase over the authenticated connection: accept
   `ASWPRUN1`, receive the zeroizing launch envelope, create the inner PTY,
   spawn the installed exec-shim image with a private control socket,
   transfer the slave descriptor, nonce and envelope, hold the exec
   (ptrace TRACEME + stop, as the qualified fixture shim does), confirm the
   exec event to the client, release on the client's exec-release frame,
   wait the direct child, and report the authenticated `TargetExit`.
2. The exec-shim role in the guardian binary (role dispatch by argv), with
   its own self-image binding against the manifest's exec-shim digest.
3. The client side: send the envelope, commit the durable run intent in the
   Store (schema 9 `begin_run_with_scope` + association), then send the
   launch gate and exec release only after the intent is durable, consume
   the exit report with the retained original-scope retirement observation.
4. The session-helper role, the terminal relay composition
   (`managed_terminal_relay` is the qualified reference), and the CLI/doctor
   surface.

# Session continuation: 2026-11-21 (seventh)

- `8106e0e`/`4310b66` framed the launch protocol (gate, exec release, exec
  event, authenticated exit report) and passed the full pipeline.
- `1e759bd` implemented the guardian's launch phase and the exec-shim role
  and passed the full pipeline
  ([44980532646](https://github.com/shahzadlone/agent-swapper/actions/runs/44980532646)):
  the client's launch envelope travels only over the authenticated channel;
  the guardian creates the owned inner PTY, spawns the installed exec-shim
  image with a private control socket and a clean environment, transfers the
  terminal slave, nonce and envelope, holds the exec at the kernel's exec
  trap under its tracer (the shim's own TRACEME stop happens before any
  launch data is read), confirms the exec event to the client, releases on
  the exact-child exec release, waits the direct child, and reports the
  authenticated target exit. The shim role binds its own running bytes to
  the manifest's exec-shim digest and acquires the target session without
  inheriting a controlling terminal.

Next implementation work, in order:
1. Extend the activation client (`activation_client`) with the launch flow:
   send `ASWPRUN1`, the envelope, the launch gate nonce, wait the exec
   event, send the exec release, consume the exit report. Hosted CI target:
   a fixed disposable program (never a provider command).
2. The durable run intent: the client commits the Store association
   (schema 9 `begin_run_with_scope`) before sending the launch gate and the
   exec release; uncertain sends stay unresolved; a foreign key never
   authorizes. The qualification journal tests are the reference.
3. The terminal relay composition on the client side (the outer terminal
   and the PTY master backhaul), resize/raw mode/stop-bg-fg behavior per
   the qualified relay fixture.
4. The session-helper role and the CLI/doctor surface.

# Session continuation: 2026-11-22

- `1e759bd` + fixes through `6d81de8` delivered the **held-exec launch
  end to end on hosted systemd**: the ordinary client sends `ASWPRUN1`, the
  zeroizing launch envelope, its run-nonce launch gate; the systemd-activated
  guardian spawns the installed exec-shim image under its tracer, transfers
  the PTY slave, nonce and envelope, holds the exec at the kernel trap,
  confirms the exec event to the client, releases on the exact-child exec
  release, waits the direct child and reports the authenticated exit. The
  lifecycle also covers the bind-mode offer round trip and instance
  retirement. The full pipeline passed at `22e2662`
  ([45041455234](https://github.com/shahzadlone/agent-swapper/actions/runs/45041455234)).
- CI debugging lessons now encoded in the workflow and harness: the service
  template keeps StandardOutput off the activation socket (a stdout write
  polluted the protocol and died with EPIPE); the systemd-supplied stdin is
  nonblocking and must be set blocking for the timeout-driven reads; the
  client's offer receive needs the nonblocking credential-enabled socket
  while the launch-control frames need blocking credential-disabled; the
  client owns and sends the run nonce (the earlier client code awaited a
  gate it should have sent); the exec-shim image must be the guardian
  binary (role dispatch lives there); the lifecycle's launch control must
  run while the generation is still installed and selected; journal dumps
  surface as step annotations because anonymous log access is gone.
- `22e2662` scoped RUSTSEC-2026-0592 (url 2.5.8 blob-origin, through the
  pinned cargo-about 0.9.3 build tool) out of the build-tools deny policy
  with written justification; the runtime graph does not depend on url.

Next implementation work:
1. The durable run intent: the launch client commits the Store association
   (schema 9) BEFORE sending the launch gate and exec release; uncertain
   sends stay unresolved; the qualification journal tests are the reference.
2. The terminal relay composition on the client side (outer terminal +
   PTY master backhaul), resize/raw/stop-bg-fg per the qualified relay
   fixture.
3. The session-helper role and the CLI/doctor surface (install/verify/
   launch subcommands beyond the disposable examples).
4. Authenticated restart recovery.

# Session continuation: 2026-11-22 (second)

- `b22ec05`..`d2a773d` moved the launch client into the install crate's
  library (`client`) with the durable journal seam (`launch_client::Journal`
  + a local fsync'd `FileJournal`): the run intent is committed before the
  launch gate, the durable spawn observation before the held-exec release,
  and the authenticated exit is audited before the connection closes. The
  hosted launch control requires exactly the three journal records for the
  one run. The full pipeline passed at `d2a773d`
  ([45071347909](https://github.com/shahzadlone/agent-swapper/actions/runs/45071347909)).
  The library move initially dropped the channel-policy switches (blocking +
  credential-disabled) required by the launch frames; restored and covered
  by the hosted control.
- The journal callbacks are the mandatory-semantics seam a production Store
  adapter must implement; core's live linux-scope path stays
  qualification-gated until its own review (the docs' promotion gate).

Next implementation work:
1. The production Store adapter behind the `Journal` seam, with the
   independent review the seam's contract demands, and the CLI wiring
   (`aswp` subcommands) for install/verify/bind/launch.
2. The terminal relay composition on the client side (outer terminal +
   PTY master backhaul), resize/raw/stop-bg-fg per the qualified relay
   fixture.
3. The session-helper role and authenticated restart recovery.

# Session continuation: 2026-11-22 (third)

- `e66ad1d`..`2bc7837` added the terminal master backhaul and the bounded
  client-side relay: the guardian hands the PTY master to the client after
  the held-exec release, the client relays the target's bytes to its outer
  terminal (a feeder thread feeds outer input without shutting down the
  target's terminal), and consumes the authenticated exit report after the
  master ends. The master's EIO after the last slave closes is the relay's
  clean end (the qualified fixture's convention). The hosted launch control
  launches /bin/echo and requires its output to reach the client; the full
  pipeline passed at `2bc7837`
  ([45103616256](https://github.com/shahzadlone/agent-swapper/actions/runs/45103616256)).
- Raw modes, resize and job-control handoff stay with the separately
  qualified relay composition (managed_terminal_relay); this bounded path
  preserves byte order, final output and the exit-report ordering.

Next implementation work:
1. The interactive relay qualification: raw mode entry/exit, resize
   (TIOCSWINSZ backhaul), shell stop/bg/fg with the outer terminal, hidden
   input — per the qualified managed_terminal_relay fixture, adapted to the
   production channel.
2. The production Store adapter behind the `Journal` seam + CLI wiring.
3. The session-helper role and authenticated restart recovery.

# Session continuation: 2026-11-22 (fourth)

- `66a5f59` added the relay's interactive essentials: when the client's
  outer terminal is a real tty the relay runs it in raw mode for the
  target's lifetime and restores the saved attributes on every exit path,
  and the feeder forwards window-size changes to the PTY master
  (TIOCSWINSZ). Without a tty the outer terminal is untouched. Raw-mode
  entry still requires the foreground, per the qualified terminal owner
  policy. Full pipeline passed at `66a5f59`
  ([45105708094](https://github.com/shahzadlone/agent-swapper/actions/runs/45105708094)).

Next implementation work:
1. The interactive relay qualification on a real pty (the hosted control
   can wrap the client in `script` to give it a tty): shell stop/bg/fg,
   hidden input, resize evidence — per the qualified
   managed_terminal_relay fixture.
2. The production Store adapter behind the `Journal` seam + the CLI wiring.
3. The session-helper role and authenticated restart recovery.

## Session status summary (2026-11-22, end)

Qualified and integrated on main, each with full-pipeline evidence:
- Endpoint authentication + adversarial pathname replacement races.
- Installation transaction (producer plan, root executor, hosted lifecycle
  with upgrade/removal/deselect) + the install executor crate.
- Activation protocol: guardian service, offer vocabulary, connection
  identity, bind-mode round trip, instance retirement.
- Held-exec launch: envelope, PTY, tracer hold, exec event, exact-child
  release, authenticated exit report.
- Terminal backhaul: master transfer, bounded byte relay, raw mode +
  resize backhaul, EIO convention; /bin/echo output reaches the client.
- Durable journal seam (intent before gate, spawn observation before
  release, exit audit) with the fsync'd FileJournal and the hosted
  three-record control.

Open gates, in order, each needing its own focused session:
1. **Production Store adapter** behind `launch_client::Journal` — the seam's
   contract requires an independent review before wiring; core's live
   linux-scope path stays qualification-gated until that review (do not
   promote it by relaxing checks).
2. **Interactive relay qualification** on a real pty (wrap the client in
   `script` on hosted CI): stop/bg/fg, hidden input, resize evidence.
3. **Session-helper role** (the outer owner image: launch client + Store)
   and the CLI exec composition per the fresh-entry design; the CLI must
   not link the transport (boundary check stays).
4. **Authenticated restart recovery**; then the real-provider cells (the
   user's Claude/Codex/Kimi subscriptions are available; disposable test
   profiles were deferred until all provider-free work is done — this is
   the trigger point for asking).

# Session continuation: 2026-11-22 (fifth)

- `bc51be2`..`f80ab01` qualified the **interactive launch through a real
  pty**: the hosted control gives the launch client a real outer pty as its
  controlling terminal with its own group in the foreground (a background
  terminal read or mode change raises SIGTTIN/SIGTTOU and stopped the whole
  client), feeds input through the full production channel, applies a
  window-size change mid-flight, and requires the target to see both the
  forwarded size and the input. The relay's feeder syncs the inner master
  to the outer terminal's current size at relay start and forwards changes
  on a 100 ms poll. The full pipeline passed at `f80ab01`
  ([45160165455](https://github.com/shahzadlone/agent-swapper/actions/runs/45160165455)).
- Debugging lessons encoded: the client's feeder is detached (joining it
  hangs on a terminal whose read side never closes); the tracer detaches at
  the exec release (continuing it delivered the shell's own SIGCHLD as a
  tracer stop); pty master reads report EIO after the last slave closes;
  `stty size` prints rows-then-columns.
- The independent review of the `Journal` seam (2026-11-22) fixed the
  signatures: `confirm_intent` consumes the one-use ServiceKey by value,
  `audit_exit` takes the one-use retirement value after the client's own
  retirement observation, and the client keeps its retained binding through
  the closure (`13c4e23`). The standing gap — durable recording of a scoped
  run's target exit — is documented on the seam for the Store adapter design.

Next implementation work:
1. The production Store adapter behind the reviewed seam (in a home where
   core and the manager crate can both be depended on — the session-helper
   binary composition), including the schema/event decision for the scoped
   run's durable target exit.
2. The CLI wiring (`aswp` subcommands exec'ing the installed helpers per
   the fresh-entry design; the CLI never links the transport).
3. Shell stop/bg/fg through the relay (the qualified fixture's job-control
   evidence adapts to the production channel).
4. Authenticated restart recovery.

## Store adapter readiness (independent review, 2026-11-22)

The demanded independent review of the `Journal` seam completed with the
verdict: wireable after bounded FIX-FIRST items (all implemented in
`13c4e23`), with one standing design gap. Key findings, all with file:line
references in the review:
- `confirm_intent` must carry the one-use `ServiceKey` by value (it is
  non-cloneable and doctest-enforced); the adapter moves it into
  `bind_linux_scope` — implemented.
- `finish_run(RunCompletion::ChildExited)` is unimplementable for
  LinuxCgroup-scoped runs (the RunFinished projection requires local_scope
  IS NULL for exited, and LinuxScopeRetired sets outcome=local_scope_empty);
  the adapter must use retirement-commit semantics instead.
- The client must keep its retained `BoundService`, close the activation
  socket first, observe the original scope's retirement on the still-open
  manager connection, and only then authorize the retirement commit —
  implemented in the closure order.
- The adapter owns the profile lease lifecycle (register/lease/release);
  the unresolved intent blocks profile reuse by design; lease-fd transfer
  to the guardian belongs to the fresh-entry/session-helper composition.
- STANDING GAP: schema 9 records scope emptiness but has no durable record
  of a scoped run's authenticated target exit (today it lives only in the
  FileJournal text and client memory). The Store adapter design must add an
  event/outcome for scoped-run exits before item 5 is complete.
- No rollback of a partially begun run: atomic event+projection commits and
  the append-only journal mean the unresolved intent is the durable state
  that blocks reuse until the separately qualified restart recovery.

# Session continuation: 2026-11-22 (sixth)

- `30b6b71` closed the review's standing schema gap: the LinuxScopeRetired
  event carries the nonce-bound authenticated target exit (pinned
  serialization mirroring the runtime's shape) and the projection commits
  exit_code with the scope-emptiness outcome in one atomic transaction,
  using the journal's established code/128+signal mapping. Unknown exits
  stay NULL; the optional field keeps older journal rows decodable. Full
  pipeline passed.
- `976800e`/`e363c97` added the **session-helper crate** — the outer owner's
  launch entry whose Store-backed journal implements the reviewed Journal
  seam: the run intent consumes the one-use ServiceKey into the durable
  scope association before the gate, the spawn observation precedes the
  release, and the authenticated exit commits with the retirement,
  resolving the run and releasing the lease. The live linux-scope path is
  promoted to the reviewed production surface (the 2026-11-22 review being
  the demanded gate), feature-gated so core's and the CLI's default graphs
  stay free of the manager dependency; the boundary check pins the
  session-helper's default graph. Full pipeline passed at `e363c97`
  ([45274663129](https://github.com/shahzadlone/agent-swapper/actions/runs/45274663129)).
- The core gents launch test `core_opt_ins_cannot_authorize...` was
  observed failing once in a full-workspace parallel run and passing in
  isolation and on reruns (timing flake, same class as socket_reset).
  Watch CI.

Next implementation work:
1. The session-helper's CLI-facing composition: the `aswp` entry exec'ing
   the installed session-helper image per the fresh-entry design (the CLI
   never links the transport), with the profile/alias selection coming from
   the caller's configuration.
2. Shell stop/bg/fg through the production relay (the qualified fixture's
   job-control evidence adapts to the production channel).
3. Authenticated restart recovery.
4. The real-provider cells (Claude/Codex/Kimi subscriptions available; the
   deferred disposable-profile request triggers once the provider-free
   gates above close).

# Session continuation: 2026-11-23

- `30b6b71` closed the review's standing schema gap (durable scoped-run
  target exit) — full pipeline passed.
- `976800e`/`e363c97` added the session-helper crate and qualified it.
- `6718598` wired the CLI's opt-in `aswp managed-launch PROFILE --
  PROGRAM [ARGS]`: it requires a compatible protected installation for the
  calling user, resolves the profile's harness from the Store, and execs
  the installed session-helper image as a fresh process with the shell's
  job identity preserved (the fresh-entry design's first requirement).
  This process never links the transport; the helper owns the Store, the
  manager connection and the launch client. The session-helper's Store
  adapter looks up the caller's existing profile instead of registering
  one. Full pipeline passed at `6718598`
  ([45281538786](https://github.com/shahzadlone/agent-swapper/actions/runs/45281538786)).

Next implementation work:
1. The hosted managed-launch composition control: the lifecycle's launch
   control switches to `aswp managed-launch` through the installed
   session-helper image (installing the session-helper image into the
   manifest's role) and requires the durable journal records plus the
   pty relay evidence through the fresh-exec composition.
2. Shell stop/bg/fg through the production relay.
3. Authenticated restart recovery.
4. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).

# Session continuation: 2026-11-23 (second)

- `41d998d`..`d65cfd0` qualified the **managed-launch composition on hosted
  systemd**: the lifecycle installs the real session-helper image in its
  manifest role, registers a disposable native profile, and runs the
  interactive pty control through `aswp managed-launch` — the CLI execs the
  installed session-helper image (fresh-exec with the shell's job identity
  preserved), whose Store-backed journal commits the durable intent and the
  retirement with the authenticated exit while the target sees the
  forwarded size and the input through the production channel. The
  lifecycle's durable-journal and disposable-launch controls were kept, the
  pty control's client interface was generalized (`--client ARGS... --target
  TARGET...`), and the step's timeout was raised for the added controls.
  Full pipeline passed at `d65cfd0`
  ([45301246754](https://github.com/shahzadlone/agent-swapper/actions/runs/45301246754)).

Next implementation work:
1. Shell stop/bg/fg through the production relay (the qualified fixture's
   job-control evidence adapts to the production channel).
2. Authenticated restart recovery.
3. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).
4. The release-candidate packaging/signing gates.
