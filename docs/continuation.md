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
  not an implemented topology. Production managed launch remains disabled for
  users and release: nothing enables it for a user's shell or in a release
  artifact, though the experimental `aswp managed-launch` CLI entry exists and
  hosted CI drives it end to end (see the 2026-11-25 section below).

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
   production channel. (Closed in the 2026-11-25 session.)
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
   managed_terminal_relay fixture. (Closed in the 2026-11-25 session.)
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
   evidence adapts to the production channel). (Closed in the 2026-11-25
   session.)
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
   job-control evidence adapts to the production channel). (Closed in the
   2026-11-25 session.)
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
   pty relay evidence through the fresh-exec composition. (Closed: the
   control landed in `41d998d`..`d65cfd0`; the 2026-11-25 session added
   the pty relay evidence it requires.)
2. Shell stop/bg/fg through the production relay. (Closed in the
   2026-11-25 session.)
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
   job-control evidence adapts to the production channel). (Closed in the
   2026-11-25 session.)
2. Authenticated restart recovery.
3. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).
4. The release-candidate packaging/signing gates.

## Composition status (2026-11-23, end of run)

The production composition now runs end to end on hosted systemd through
the real CLI entry:
`aswp managed-launch PROFILE -- PROGRAM ARGS` → execs the installed
session-helper image (fresh-exec, shell job identity preserved) → the
Store-backed journal commits the durable intent (one-use key into the
scope association) → the launch gate → the guardian's tracer hold and
exec release → the PTY relay with raw mode, resize backhaul and the EIO
convention → the authenticated exit report → the retirement commit with
the one-use retirement value → the run resolves and the lease drops.
Every step has hosted CI evidence on both Ubuntu images.

The remaining design slices, each needing its own focused session:
1. **Production relay composition with job control**: move the qualified
   relay composition (managed_terminal_relay, 68 owned-PTY cases) from the
   fixture crate to the production install crate, replacing the fixture
   journal with the Store adapter and the fixture transport with the
   production channel; shell stop/bg/fg, hidden input, nested jobs and
   suspension per the fixture's evidence. This is the docs' "real
   launch-plan/Store/terminal integration" slice.
2. **Authenticated restart recovery**: the durable intent after client
   death; the docs require a separately qualified recovery mechanism.
3. **Real-provider cells**: login/refresh/resume/permission per harness
   (the deferred disposable-profile request triggers here).
4. **Release-candidate packaging/signing gates**: the candidate pipeline
   exists (unsigned, reproducibility-verified); the signing gate is open.

## Final checkpoint (2026-11-23, end of run)

The managed-launch composition is fully qualified end-to-end on hosted
systemd through the real CLI entry, on both Ubuntu images, with every
intermediate gate green. The complete chain, each step with hosted CI
evidence recorded in this document:

`aswp managed-launch PROFILE -- PROGRAM ARGS` (fresh-exec, shell job
identity preserved, transport never linked into the CLI) → the installed
session-helper image → the Store-backed journal (durable intent with the
one-use key before the gate; spawn observation before the release; the
authenticated exit committed with the one-use retirement value) → the
guardian's activation protocol (kernel-sender authentication, systemd
connection-instance binding, bounded offer) → the held-exec launch
(envelope, PTY, tracer hold, exec trap, exact-child release) → the
terminal relay (raw mode, resize backhaul, EIO convention, detached
feeder) → the authenticated exit report → the retirement commit → the run
resolves and the lease drops.

The two open design slices, both recorded above with their constraints:
1. The production relay composition with job control (the qualified
   fixture's 68-case evidence adapts to the production channel).
2. Authenticated restart recovery (a separately qualified mechanism).

Then the provider cells (the disposable-profile request triggers) and the
candidate packaging's helper-asset inclusion (the adversarial verifier and
its pinned test fixtures need a careful, fresh pass).

The next session should start with the production relay composition — the
last provider-free gate before the real-provider work begins.

# Session continuation: 2026-11-23 (third)

- `bcd8f41` added the relay's suspension handling: in raw mode the suspend
  character arrives as a plain byte; the relay intercepts it, stops the
  target's process group, restores the outer terminal's cooked mode, and
  waits for the user's explicit `fg` before re-entering raw and continuing
  the target (the inner pty's ISIG would also generate the stop, but then
  the client could not observe or reverse it). The suspension flag is
  shared with the relay's main loop; the exit paths restore the outer
  terminal's saved attributes. Full pipeline passed at `bcd8f41`
  ([45305344313](https://github.com/shahzadlone/agent-swapper/actions/runs/45305344313)).

Next implementation work:
1. The production relay composition's remaining interactive evidence
   (nested jobs, hidden input, long sessions) — adapted from the qualified
   fixture's owned-PTY cases to the production channel. (Closed in the
   2026-11-25 session.)
2. Authenticated restart recovery.
3. The candidate packaging's helper-asset inclusion.
4. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).

# Session continuation: 2026-11-24

- `bc82390`..`7d4c5cf` included the Linux helper images in the candidate
  packaging and its reproducibility verification: the Linux candidate
  builds, packages and rebuild-verifies the guardian and session-helper
  images alongside the CLI binaries (the rebuilt marker's inventory defines
  the comparison; other targets keep their two-binary archives; the
  verifier's executable-mode check covers the helpers when present). An
  administrator can now install a full managed-launch deployment from a
  candidate. That commit's own run is a failure, not a pass: `7d4c5cf`
  ([45315043782](https://github.com/shahzadlone/agent-swapper/actions/runs/45315043782))
  finishes `failure` because `linux-manager-evidence (ubuntu-24.04)` failed
  its step 22, "Evaluate fixed-user socket activation" (every candidate,
  reproduce-candidate and attest job passed, and the ubuntu-22.04 manager
  job passed, so the helper-asset packaging evidence itself stands). The
  green round for this work is `8b920c0`
  ([45322498534](https://github.com/shahzadlone/agent-swapper/actions/runs/45322498534)),
  which is `7d4c5cf` plus the annotation and lifecycle-timeout corrections
  below and whose every job concluded `success`.

Next implementation work:
1. The production relay composition's remaining interactive evidence
   (nested jobs, hidden input, long sessions) — adapted from the qualified
   fixture's owned-PTY cases to the production channel. (Closed in the
   2026-11-25 session.)
2. Authenticated restart recovery.
3. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).

# Session continuation: 2026-11-24 (second)

- `60f469f` moved the journal dump out of the annotation budget (the
  per-line error annotations consumed the step's cap and hid the actual
  control failure) and `8b920c0` raised the lifecycle step's timeout to 14
  minutes for the three launch controls. The full pipeline passed at
  `8b920c0`
  ([45322498534](https://github.com/shahzadlone/agent-swapper/actions/runs/45322498534));
  that SHA has exactly one run, so no earlier same-commit timeout exists —
  the composition's three launch controls keep the headroom on slower
  runners.

Next implementation work:
1. The production relay composition's remaining interactive evidence
   (nested jobs, hidden input, long sessions). (Closed in the 2026-11-25
   session.)
2. Authenticated restart recovery.
3. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).
# Session continuation: 2026-11-25 (production job control)

The qualified PTY job-control topology (the evaluation fixture's
`activated_job_control.rs` / `activated_terminal.rs` evidence) is now
ported into the production launch path. This section records the
implemented topology, the evaluated deviations, and the evidence plan.

## Production topology (supersedes the seventh session's shape)

The seventh session recorded the shim "acquires the target session without
inheriting a controlling terminal". That shape could not survive an outer
foreground handover: a pre-handoff master close SIGHUPs the pty's foreground
group, and the acquisition order made that group the guardian itself (an
empirical kill of a unit test). The guardian now owns the session in three
steps that bracket the spawn in `launch.rs`: `prepare_session` runs before
anything exists (default-disposition check, conditional `setsid`,
tty-inheritance refusal, and a block on the whole seven-signal job
vocabulary — `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`
and `SIGCHLD`, `job_control.rs`'s `JOB_SIGNALS`), `bind_session` then binds
the session's controlling terminal before the fork (`TIOCSCTTY` with
argument zero; a child inherits the controlling-terminal link only at fork
time, so the bind must precede the spawn), and `grant_foreground` runs after
the kernel's exec trap delivers the trace-stop (`tcsetpgrp` to the shim's
own group plus read-back verification). The kernel gives a fresh
controlling terminal's foreground to the session leader, so the guardian's
own group IS the terminal's foreground between the bind and the grant; the
grant is what ends that. The shim keeps its exec gated on the
slave/nonce/envelope transfer and verifies the whole topology
(`getsid == getppid`, its own group, the slave's session is the parent's,
the slave's foreground is its own group) plus the inherited blocked
7-signal mask, clearing that mask only immediately before `exec`.

One evaluated deviation: the foreground grant now precedes the run gate.
No bypass exists — the slave/nonce/envelope transfer remains the only exec
path and is still gated on the durable intent; the grant only orders the
terminal handover ahead of it.

`bcd8f41`'s suspension handling was defective: it intercepted the suspend
byte at the relay and stopped the target's group directly. That is not
honest job control — the guardian never observed a real stop, and the
client stayed accountable for the inner terminal's conventions. The
production client now suspends ITSELF through its signal owner: the inner
pty's ISIG generates the real SIGTSTP, the guardian observes the child's
stop and sends a 42-byte literal STOP notice (signal, child, sequence),
the client restores the outer terminal, suspends on SIGTSTP, and after
the outer shell's `fg` returns the foreground it re-enters raw and sends
a 32-byte RESUME grant; the guardian accepts exactly one authorized
continued, re-grants the inner foreground and resumes the target.

## Deviations from the qualified fixture (evaluated, deliberate)

- Literal versioned frames instead of the fixture's JSON records:
  STOP notice 42 bytes, resume grant 32 bytes (it must fit the control
  receive's 32-byte bound; the child binding lives in the notice).
- Resume-sequence bound 64 against the fixture's 8: the bound exists to
  fail a pathological loop loudly, and 64 gives interactive use room the
  fixture's 8 would under-serve; the protocol's monotonic check still
  governs each cycle.
- A target that dies while stopped is reported as the honest exit over
  the same control channel before the guardian closes: the client's
  grant-send BrokenPipe path receives the queued authenticated report
  instead of declaring the target missing.
- The hosted 68-case fixture matrix is not duplicated; the production
  channel's interactive evidence moves into the rewritten
  `tools/check_linux_launch_pty.py` scenarios.

## Hosted evidence plan (CI wiring included)

`tools/check_linux_launch_pty.py` is rewritten around the production
shape: an anchoring session-leader process (a fresh fork, so `setsid`
always succeeds) owns the controlling terminal, spawns the launch client
in its own process group, and releases the child's exec from behind a
pipe barrier only after its group and the foreground exist, so the
setpgid race can never let exec win; it performs the shell's own `fg`
resumption on an explicit command. Scenarios: basic (kept), hidden-input
(a target-side echo-off read announced by a readiness marker; the token
may appear exactly once), raw-bytes (64 deliberate bytes including ISIG,
flow-control, EOF and high bytes, verified by digest), nested-jobs (an
interactive bash's own ^Z stops only its inner job; the client must not
stop; the relay's raw modes must survive the whole exchange; `rc:148`
names the inner status, amd64 runners), job-control (a direct-target
^Z: real client suspension observed through `waitpid(WUNTRACED)` and
`/proc/<pid>/status` state `T`, a terminal-mode audit comparing the
suspended client's restored cooked state and the resumed client's raw
state against the pre-exec baseline, foreground resumption, resumed run,
authenticated exit and a second restored-to-baseline audit — the
regression shape for the guardian's stop → grant → continued → run →
report path, ended with SIGINT so the report shape is `Signal`, while
`basic`/`long-active` cover `Code { 0 }`), long-active (75 s of live
target past every admission window) and long-stopped (a 70-second hold
across the stop/resume path, with the same mode audits before and after
the hold). Both client paths (`aswp managed-launch` and the disposable
`activation_client`) run all scenarios. The step budgets here only ever
became effective later: the job's own 10-minute cap was the real ceiling,
so `7897d3e` raised it to 30, `ea44547` to 45, and `259aff3` brought the
job's explicit step budgets back inside that cap (lifecycle 15 minutes,
staging 4, 36 in total). The job-control,
hidden-input, nested-jobs and raw-byte mechanics were validated locally
against a fake client; the real guardian path is hosted-CI-only (no
root/systemd on the developer machine).
Local gates green at the time of writing: the full workspace suite
including the new harness-less fresh-process regression, clippy and fmt
(`setpriv --inh-caps=-all` prefix required locally; the inherited CapInh
bit defeats `scope_observation` identically at clean HEAD).

## Re-review round (all six findings incorporated)

The post-restructure audit re-review rated CHANGES-REQUIRED; every
finding is now addressed in code:

1. Blocker — `Signals::new` refuses a pre-blocked mask, so the client's
   block-before-admission ordering made every launch refuse (uncovered
   because the guardian path cannot run locally). The sequence now lives
   as `Signals::claim_with_terminal_stops` in the runtime crate: admit
   first, then extend the owner's blocked mask with the terminal in-band
   stop signals (TTIN/TTOU join it; TSTP is already part of the owner's
   set) so every later thread inherits the stop-proof mask. A
   harness-less fresh-process regression (`tests/signal_init_sequence`,
   driver + fixture roles in one binary, because the libtest harness is
   itself multithreaded) pins the exact production sequence.
2. Feeder outcomes could vanish into a discarded `JoinHandle` return.
   Every feeder exit path now funnels exactly one final word through the
   status channel; the relay waits one bounded cycle (`FEEDER_FINAL`,
   500 ms) for it after the shutdown flag and refuses even an
   authenticated target end on a feeder failure. Silence stays the one
   accepted case: a feeder wedged in a full master write ends with the
   process, never reporting.
3. The feeder's flag-to-read window is now closed from both sides: the
   shutdown flag is rechecked after the poll returns and before every
   read and write attempt, so no terminal reach survives the flag
   outside one bounded poll cycle. Joining the thread was evaluated and
   rejected again: a blocked master write must not wedge the client's
   honest end.
4. Mode restoration is now ownership-gated (`Outer::raw_held`): the
   restore runs only while this owner actually holds raw mode. The
   suspended client's failure path — the foreground wait giving up while
   another job owns the terminal — can no longer reach for the terminal;
   the foreground-admission failure before raw entry never touches it.
   The checker's post-exit baseline equality audit covers the happy
   path.
5. The checker anchor's setpgid race is closed with an exec pipe
   barrier: the child joins its group and holds its exec until the
   foreground exists, and the parent-side setpgid tolerates the
   child-side win. Stress-verified locally.
6. The scenarios now audit terminal attributes: the job-control and
   long-stopped scenarios assert the cooked restore at every stopped
   checkpoint, the raw re-entry after the resume acknowledgement and the
   final restoration against a baseline captured while the anchor still
   holds the client's exec (the start order on the commands pipe releases
   the exec only after the control acknowledged the capture — the
   auditor's fast-raw-client reproduction closed this); nested-jobs
   asserts the raw modes survive the inner job exchange, and
   hidden-input waits for the target's echo-off readiness marker instead
   of a fixed sleep.

A second re-review pass raised two follow-ups, both incorporated:

- The baseline capture raced the client's first instruction (the exec
  release followed the PID narration directly). The anchor now waits for
  the control's `start` order after narrating the PID; `main()` captures
  the terminal-mode baseline and only then releases the exec, so every
  later driver state is provably the client's own doing.
- "Silence = wedged full master write" was unsound: the backhauled master
  is nonblocking, so silence never established the documented exception,
  and the feeder's blocking stdin read could outlive the shutdown flag.
  The feeder's stdin is now set nonblocking (saved flags restored before
  its final word is sent, so the shared description returns to its
  caller-owned state), every cycle checks the shutdown flag, and the
  relay requires the feeder's confirmed completion: both a feeder error
  and timeout/disconnected silence refuse the launch, even over an
  authenticated target end. The one-time flags change on a shared stdin
  description is the cost of bounded I/O; it is confined to the feeder's
  lifetime and deliberately restored before the relay may proceed.

A third pass found one follow-up: a benign stdin end consumed by `drive`
  while the target still ran (piped input closed early) would leave the
  relay's final wait forever silent and refuse the later honest exit.
  The single completion word is now preserved wherever it is first
  consumed (`FeederScope` carries the receiver and the observed word;
  `FeederScope::confirmed` is the production helper that accepts a
  consumed word, bounds one wait for a pending one, and refuses on any
  silence), and real feeder regressions cover the stdin-EOF and shutdown
  paths - `spawn_feeder`'s input became an injectable `OwnedFd` so the
  tests exercise the true thread end to end. The re-review verdict after
  this change: APPROVE-WITH-NOTES, and the remaining note (the protocol
  test once duplicated the combine logic) is covered by the shared
  helper the test now calls.

Next implementation work:
1. Record the full pipeline evidence for this composition once the run
   completes; address any scenario failures on `main`.
2. Authenticated restart recovery.
3. The real-provider cells (the deferred disposable-profile request
   triggers once the provider-free gates above close).

## Installation lifecycle evidence (2026-11-25)

The "Exercise the installation lifecycle end to end" step is green on
both ubuntu-22.04 and ubuntu-24.04 manager-evidence runners in run
`45535617406` (tested commit `988beae`: the launch fix `45e4e71` plus a
documentation-only follow-up; job 138941362212 completed
02:51:06Z-02:58:37Z, job 138941362280 completed 02:51:26Z-02:58:58Z,
both step conclusions `success`). Kernel-level
diagnosis and the preceding fix chain, in order:

- The held-exec launch refused itself in CI with "Inappropriate ioctl
  for device": the production port bound the terminal's controlling
  link after the exec-shim fork, so the shim inherited no
  controlling-terminal pointer (it is fixed at fork and never
  propagates) and its `tcgetsid`/`tcgetpgrp` verification failed with
  ENOTTY. The qualified fixture (`activated_job_control.rs`) binds
  before the fork; `17afffc` restored that order (`bind_session` before
  the spawn, `grant_foreground` after the tracer stop). The guardian
  teardown SIGHUP seen in earlier traces was the downstream artifact
  of the shim dying first and the guardian closing the last terminal
  descriptors; it is now inert (below).
- `80e69e4` restored the rows-cols order of the resize witness that
  `54acb58`'s control rewrite had reverted (`f80ab01` had it right:
  `stty size` prints rows cols, so the resized target emits `33 111`).
- `f72a5f1` removed the stray argv separator the disposable pty
  scenarios passed into the fixed launch argv, which made the client
  treat `--` as the program and refuse "invalid Linux launch envelope".
  With it gone, the pty control's managed and disposable scenarios -
  hidden-input, raw-bytes, nested-jobs, job-control, long-active,
  long-stopped - all passed on both runners at `988beae`
  ([45535617406](https://github.com/shahzadlone/agent-swapper/actions/runs/45535617406),
  lifecycle step green on ubuntu-22.04 and ubuntu-24.04); `f72a5f1`'s own
  round ([45517591514](https://github.com/shahzadlone/agent-swapper/actions/runs/45517591514))
  was cancelled mid-step and carries no pty evidence. The strace
  instrumentation and its manifest-digest repair were retired in `9cb3ac0`.
- `45e4e71` hardened the launch phase: the guardian blocks the whole
  job-control vocabulary during launch (mirroring the qualified
  fixture's `blocked_job_signals`; the shim witnesses the inherited
  mask before clearing it for the target's exec), and a launch whose
  installed image is absent refuses before any session or terminal is
  taken, keeping the single-slot session machinery out of the common
  misconfiguration refusal. Two audit rounds (sol) reviewed the chain;
  the second returned APPROVE-WITH-NOTES, and `988beae` folded its
  documentation notes in: the serve precondition (single-threaded
  service process) and the grant's proven-group comment.

Run-level status of the same round: the matrix run `45535617406`
finishes `failure` because the separate `test (ubuntu-latest)` job hit
a one-off `launch_protocol::tests::stop_notices_and_resume...`
BrokenPipe on the new `ubuntu26` preview image (instant EPIPE, first
occurrence in every prior green round, 60/60 locally). The cause was the
test's own ordering, never the production bound check: that receive
refuses a sequence beyond its bound before it reads, so a receiver thread
that exited first closed its endpoint and the parent's send reported
`BrokenPipe` over the real refusal. `40d0571` reworked the helpers and
`ea44547` split them into two layers - a fixture failure that must not
happen and the receiver's verdict that a refusal case asserts - so a
broken fixture can no longer pass as a refusal.

Every later round that stopped mid-flight did so at 10.1-10.4 minutes in
exactly the two `linux-manager-evidence` jobs while other jobs in the same
runs finished later, so no run-level cancellation existed; the job's own
10-minute cap was the canceller (`c3862e6` run 45539037326, `576811d` run
45542168722, docs head `56f1911` run 45542346656). With the cap at 30
minutes the round went green: `40d0571`
([45710066875](https://github.com/shahzadlone/agent-swapper/actions/runs/45710066875))
concluded `success` on every job, with `linux-manager-evidence` taking
14m22s on ubuntu-22.04 and 13m46s on ubuntu-24.04 - the lifecycle step
464 s and 452 s, fixed-user socket activation 229 s and 218 s - and
`test (ubuntu-latest)` green in 4m23s. Those durations are two to five
times the observed steps' budgets under the old cap, which is why the cap
and not the step budgets was the ceiling; `259aff3` then trimmed the
lifecycle budget to twice its slowest observed run.

Cleanup at this checkpoint: the diagnostic strace/annotation
scaffolding is gone from `.github/workflows/ci.yml`; the master-residue
drain on a shim refusal and the `guardian:` narration lines in
`launch.rs` are deliberate production diagnosability and stay. No
`aswp-trace` remnants exist. Rust build caches were cleaned at the
checkpoint boundary (workspace target plus the evaluation target);
recovery reported in the handoff note.

## Restart-recovery groundwork review (2026-11-25, second pass)

The design survey for authenticated restart recovery (independent, read
only: every claim below carries a file:line in the survey record) found
three defects that block the profile after ordinary errors, not only after
crashes. They are fixed on `main` in `6f1a621`, and an independent review
(2026-11-25, sol) required two corrections to that commit before it was
accepted: the adapter's retry had to reuse the exit it was given, and the
lost-acknowledgement tests had to name their refusal. Both are in the same
line of work; the survey's own authority questions are answered below.

- **The durable run existed before anything could resolve it.**
  `StoreJournal::open` planned the run (`RunPlanned` with a fresh linux
  cgroup scope) and only then connected, claimed the signal owner and bound
  the scope. Every refusal before the intent - an unclaimable signal owner
  under `nohup`, a refusing endpoint, a terminal that closes - therefore left
  an unfinished run that blocked the profile until an operator attested it
  stopped (`registry recover --confirm-stopped`). The intent and its scope
  binding now commit in one transaction (`Store::begin_linux_run`,
  `record_events_with_scope`), so the journal's open takes only the lease and
  a launch that never reaches its intent leaves nothing durable behind. This
  changes the failure semantics of the 2026-11-22 mapping recorded above: the
  mapping's ordering is unchanged, but "a failed intent leaves an unresolved
  run" is no longer true, because the intent is now the run's beginning.
- **The client abandoned the scope on every post-intent error.** The relay's
  verdict is captured instead of returned, the control channel is dropped,
  the original scope's retirement is observed on the retained binding and
  handles, and only then is the relay's error propagated; the retirement
  commits with no authenticated exit. A failed launch now reports its own
  failure after its run resolves, and no path can commit an exit that the
  nonce-bound report did not authorize. A failing retirement observation is
  the one case that still leaves the run unresolved, which is the only honest
  outcome: nothing observed the scope's closure.
- **The retry contract was documented but not implemented.** `audit_exit`
  discarded the failed retirement value. The adapter now retains the pending
  association, the original observation and the exit as one tuple, retries
  from that tuple rather than from a caller's fresh receipt (a receipt
  belongs to one launch and cannot be charged to another run), and treats an
  already-durable retirement as terminal: a lost acknowledgement is that
  same commit, and reporting it as failure would hold the lease for the rest
  of the process's life. `audit_exit` takes the exit as an option for the
  same reason the settle path needs it, and `Journal::retry_audit` is the
  retry entry the contract promised: it takes neither a new receipt nor a new
  exit, and a journal that retains nothing answers so instead of pretending.
  A journal is one launch: the adapter records the invocation its intent was
  committed for and refuses any other, and refuses a second intent, so a
  retained tuple can never be charged to a run it was not granted for.
- **A lost acknowledgement with a known exit was reported as corruption.**
  The duplicate recognition compared only `exit_code IS NULL`. It now matches
  the recorded exit as well as the exact event payload, so a retry carrying a
  known exit recognizes its own commit, while a retirement claiming a
  different exit - or none - still fails closed.

Evidence: `Store` fixtures for the atomic pair - the refusal is the second
event, and the assertion shows the log and the run row are unchanged - and
for the lost acknowledgement with a known exit versus a foreign one or a
retirement claiming none; an adapter test that a launch which never reaches
its intent leaves the profile leasable; and local fault tests of the
settlement decision itself (a failed observation never reaches the commit, a
commit failure surfaces as the error, a settled retry succeeds and every
other retry keeps the first error). What has no local harness is the
observation and the commit against a live manager, and a fabricated
retirement receipt is not constructible by design; that coverage belongs to
the hosted lifecycle, where the experimental CLI already drives these paths.

This section was written while the review of those commits was still open.
The review's findings were the retry entry, the second-event rollback
assertion, the named refusals, the module and trait wording, the review
record itself, and the production-path coverage above. All but the last are
closed: `retry_audit` exists, the rollback fixture refuses on the binding
using a second profile, a journal now refuses any invocation but its own and
a second intent, and the wording above is the corrected one. Hosted
production-path coverage is the lifecycle's and is not claimed here.

Recovery of a run whose client died is **not** implemented, and the review
rejected the boundary the survey proposed. An authenticated "no unit for this
invocation" plus a missing or different cgroup directory are negatives about
identifiers the caller chose, checked against a Store the same user can
write; they cannot distinguish a closed scope from a record that says so, so
a `RecoveredService` would have been attestation wearing the name of an
observation. The proof would need root-owned retirement provenance - a
manager-side record of the closure the user cannot write - which is new
authority for a root component and a new cross-upgrade durable surface. Until
that is designed and reviewed, `registry recover --confirm-stopped` stays the
only way to clear an orphan, and stays attested rather than proved.
`docs/linux-restart-recovery.md` records the argument, the corrected crash
windows, and the facts a future design must start from.
