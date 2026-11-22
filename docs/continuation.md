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
