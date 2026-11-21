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
