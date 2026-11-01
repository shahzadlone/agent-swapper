# Linux managed execution: production integration boundary

Status: shared [transport, signal and terminal ownership](linux-runtime.md)
and fresh process entry are qualified. A fixed [real-Store terminal consumer](linux-store-terminal.md)
passed native qualification. Shared retained kernel observations are now being
qualified as the next runtime extraction. Normal Linux execution is
still the explicit uncontained preview. The fixed qualification crate must not
be enabled as a production launcher by removing its CI checks.

## Keep the authority small

Use fixed-user socket activation and an ordinary-user guardian. Installation
defines one non-root UID/GID, a protected guardian image, a fixed template and
a root-owned endpoint directory. The socket itself permits that user to connect.
Client data cannot choose another UID, a systemd property, an executable to run
as root, a unit file or a root command. No broad sudo/polkit permission is part
of the runtime design.

The root manager owns process membership and removal. The guardian owns the
inner terminal, its direct child wait and the profile lease. A fresh outer
helper owns terminal signal handling; a surviving parent restores attributes
after observed child stop/death when its original group owns the foreground.
The trusted session helper owns both Store and the original manager/process
observation handles. The surviving parent restores terminal state and has no
journal-completion authority. The existing CLI/TUI must start that fresh helper
instead of changing signal masks in an already multithreaded process.

This remains local process custody under a trusted kernel/root manager. It does
not isolate mutually hostile programs running as the same user, cover work
delegated to another service, or prove vendor credential isolation. Provider
support cells and cross-engine handover must state those distinctions.

## First production slice

1. Extract reviewed reusable transport, manager binding, retained process/scope
   observation and terminal ownership into a Linux-only runtime crate. Keep the
   temporary-unit installer, fault commands, marker files and fixed targets in
   the qualification workspace. A separate production policy validates the
   installed root-owned manifest, image, unit template, endpoint and protocol
   version. No environment variable enables a weaker identity policy.
2. Build and package a fixed guardian/helper entry point with a clean bootstrap
   environment. Never load the target's `LD_PRELOAD`, language startup hooks or
   configuration into a trusted helper. Send bounded launch data over a private
   transferred socket, using the existing zeroizing envelope; apply the target
   environment only at its final exec. Launch bytes must not enter argv values
   of helpers, journal diagnostics or logs.
3. Connect the real launch plan, lease and Store. Commit run intent before
   preparing the shim; authenticate original manager/guardian/scope/child and
   terminal capabilities; confirm exec while held; commit the spawn observation;
   then release. An uncertain send or missing event remains unresolved. Do not
   infer exec from EOF or infer a target exit from a shim's exit code.
4. Relay terminal bytes and preserve final output, resize, hidden/raw input,
   target-managed nested jobs and shell suspend/resume. Consume authenticated
   target status separately from terminal/control closure. Propagate target
   codes and signals to the caller only from that status, preserving explicit
   cancellation behavior. Long active and suspended sessions need bounded
   admission/observation/cleanup phases, not a total execution timeout.
5. Introduce an opaque, non-cloneable local-scope retirement value constructed
   only by the production observer. Bind it to run, profile, logical scope,
   manager invocation and original retained handles. Store must reject another
   run's value, duplicates and any fabricated/serialized substitute. Record
   target exit and scope emptiness separately. A free OS lease is insufficient.
6. Add explicit opt-in CLI/doctor diagnostics and disposable install/upgrade/
   removal tests. Require compatible protected installation before starting;
   refuse stale or mismatched installation instead of silently launching outside
   containment. Keep uncontained native execution an explicit separate choice.

## Qualification before enabling the slice

- Complete independent source review of exec-held journal ordering, queued exit
  reports, the surviving owner and their composition; resolve concrete findings.
- Pass actual integration tests for journal failure, uncertain delivery, malformed
  framing/capabilities, guardian/client loss, stopped loss, final-output blockage,
  terminal loss and sessions crossing every startup/old fixture deadline.
- Add exit propagation tests for zero/nonzero exits, named and real-time signals,
  and unknown outcome after guardian loss. A received exit report is not enough
  to authorize profile reuse before independent original-scope retirement.
- Exercise protected installation, replaced images/templates/sockets, upgrades
  with active runs and rollback without overwriting unrelated files or changing
  user data. CI installation stays disposable and cannot be invoked on the user's
  host merely by copying its environment variables.
- Review the new production dependency graph and include guardian/helper assets
  in reproducible package checks. Qualification-only dependencies must not enter
  other platforms or the default runtime accidentally.
- Run the deferred real-provider isolation/login/resume/permission tests before
  promoting provider cells. Fixture success alone does not enable account
  rotation, quota routing or automatic cross-brand takeover.

## Crash recovery and later scope

A live client can retain original handles and observe their retirement. After
that client dies, a newly launched client does not possess those handles. A
missing unit name, an unlocked file or a reused PID cannot replace them. Keep
the durable intent unresolved until a separately qualified recovery mechanism
or the existing explicit operator recovery applies. Do not extend a live
retirement observation into an undocumented restart receipt.

External SIGSTOP/whole-group death can prevent every user-space restorer from
running. Document measured terminal limits and shell behavior instead of
promising restoration after all owners are killed. Remote/delegated work and
gents runtime ownership also need independent execution-engine contracts.
macOS needs its own measured backend; no Linux or Windows result promotes it.

The [managed-launch history](linux-managed-launch.md) records the underlying
design and earlier experiments. This document describes the next implementation
boundary; it is not evidence that any of these production gates already passed.
