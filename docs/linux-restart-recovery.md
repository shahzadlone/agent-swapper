# Restart recovery for managed launches

Status: design, reviewed 2026-11-25; **not implemented**. Nothing here
enables a launch for a user or a release. The provider-free defects that
made an ordinary error strand a profile are fixed separately (`6f1a621`,
`e7fb98c`); this page is the remaining gate.

## The problem

A managed launch holds a durable run and a one-use retirement authority
together. `Store::retire_linux_scope` accepts only the in-memory
`PendingLinuxScope` that `confirm_intent` produced, matched against a
`RetiredService` the manager observed on its own connection, and against the
durable `LinuxScopeBound` binding
(`crates/agentswapper-core/src/store/linux_scope.rs`,
`crates/agentswapper-linux-manager/src/service.rs`). That value cannot be
serialized or reconstructed, so after the client dies the original handles
are gone and the Store can no longer retire its own run. The run stays
unresolved, the profile stays blocked behind it, and the only way out today
is the operator attestation `aswp registry recover RUN --confirm-stopped`,
which records `user_attested_stopped` and proves nothing.

The client is not the only loser: the guardian sees the withdrawn channel,
errors out, and `ChildWaiter::drop` kills the direct target, so a dead
client's target is bounded. Before the exec release the target is held under
`PTRACE_O_EXITKILL`. The target's descendants are not directly killed; they
end when the unit's cgroup is torn down.

## Crash windows

The durable record is a `runs` row written by the intent, with the profile
lease held by the live helper (a file lock, released when the helper dies).

| Window | Durable state | Observable afterwards | Reuse today |
| --- | --- | --- | --- |
| before the intent | only the lease | an activated unit waiting for its envelope or gate, bounded by the launch budget | free: nothing durable was written |
| after the intent, before the gate | intent plus binding, no pid | the guardian waits for the gate; EOF makes it refuse | blocked |
| gate and spawn | binding, possibly a pid | the target's exec is trapped and held | blocked |
| relay, target alive | binding and pid | the withdrawn channel errors the guardian, the waiter kills the target, the unit's cgroup is torn down | blocked |
| target exit, before the exit commit | same | the exit report existed only in the client's memory; the guardian logged the target's exit | blocked, exit lost |
| after the retirement commit | `local_scope_empty` | nothing live | free once the helper exits |

The last two rows are what the fixes above changed: a failing launch now
settles its run with an unknown exit instead of leaving it open.

## Who recovers, and when

The recoverer must hold the profile lease, so it is the same user's next
launch or an explicit command - never the manager and never a system
component, which would write to a user's Store across a privilege boundary
and would have to retire a scope it runs inside.

- **The next launch, inside the installed session helper, before the journal
  takes the lease.** The helper recovers in a short-lived Store session, then
  opens the journal; a recovery that cannot commit falls back to today's
  refusal.
- **An explicit `aswp registry recover RUN` in an observed mode**, executed
  through the helper because the CLI never links the transport.
- **Doctor stays read-only**: it may report whether a run has a binding
  (recoverable) or not (attestation only) and must change nothing.
- **Reboot and service restart**: after a reboot nothing survives, so
  recovery succeeds trivially; a systemd daemon-reexec or bus restart breaks
  in-process observation, so those runs need the later recovery path.

## What a restarted process may accept as proof

The authentication target is the *observations*, not the requester: after a
crash there is no peer, so kernel sender credentials do not apply, and any
process running as the same user could already write
`user_attested_stopped`. The proof therefore reuses only existing
primitives:

1. the profile lease, held by the recoverer;
2. the durable binding, read from the Store;
3. the unit name parsed as this uid's installation shape;
4. the manager owner checked over an authenticated connection;
5. `invocation::retired`: either an authenticated "no unit for this
   invocation" or the same identity in `inactive`/`failed`;
6. kernel checks as in `Binding::bind` (initial namespaces, cgroup2), then
   the unit's cgroup path absent, or present with a different device and
   inode than the recorded binding;
7. the manager owner rechecked, and the commit made while still holding the
   lease.

This is sound because a cgroup v2 directory cannot be removed while it is
populated, moving out of it requires the root-owned `cgroup.procs` that the
bind-time controls verified, and invocation identities never return. Both
facts only move one way, so a later commit has no time-of-check race. The
guardian's pidfd is not re-witnessed; the removal of the cgroup directory
takes its place.

Refused, always:

- any target exit other than the nonce-bound report, including
  `ExecMainStatus` (the guardian's own 0/125), journal text or a guardian wait
  status;
- inferring "stopped" from a pid, `/proc`, a lookup by unit *name*, a free
  lease alone, or elapsed time;
- recovery while the lease is held or the unit is active or deactivating;
- recovery of a run with no binding;
- recovery by a system component.

## The new authority boundary (for independent review)

```rust
// crates/agentswapper-linux-manager
pub struct RecoveredService { /* private fields, not Clone, must_use */ }

pub fn observe_orphan_retirement(
    manager: &AuthenticatedManager,
    claim: RecoveryClaim,   // unit, invocation, user, device, inode
) -> io::Result<RecoveredService>;
```

`RecoveredService` means: at that moment systemd reported no live instance of
the invocation, and the unit's cgroup path was not the recorded directory.
It does not mean the target exited, that the guardian's pidfd exited, that
delegated work ended, or that the profile is free.

```rust
// crates/agentswapper-core, behind the same feature gate as the live path
impl Store {
    pub fn recover_linux_scope(
        &mut self,
        run: &str,
        recovered: RecoveredService,
    ) -> Result<(), RecoverFailure>;
}
```

It takes the lease itself, compares the claim's bytes exactly against the
durable binding, and commits atomically. Its only caller is the session
helper. Independent review must approve this boundary before anything is
enabled; it is not a reuse of the in-memory path and must not become one.

## Recorded vocabulary

The retirement vocabulary needs one addition, because a recovered run is not
an observed retirement:

- `Event::LinuxScopeRecovered { id, scope, binding }` with no exit field,
  whose guard requires `outcome IS NULL`, `exit_code IS NULL`, the exact
  binding and a linux cgroup scope on a non-`gents` profile;
- a new outcome and custody wording for it, or a deliberate decision to reuse
  the `local_scope_empty` wording - open question below;
- schema 10, so an older binary refuses with `NewerSchema` instead of
  misreading the outcome as corruption.

An alternative that needs no schema change - reusing
`LinuxScopeRetired { exit: None }` - was considered and rejected because it
merges "observed through the original handles" with "recovered from the
stored record".

## Evidence plan

Local, without root:

- Store fixtures for each window state, including the refusals above (busy
  lease, mismatched binding, non-cgroup scope, `gents` profile, double
  commit, foreign receipt);
- compile-fail doctests showing `RecoveredService` cannot be built, cloned or
  serialized by ordinary code;
- unit tests for the path-absent and inode-mismatch logic and for the
  existing invocation-collection race;
- the admission-mutant pattern the other linux controls use.

Hosted, in the lifecycle step (it already has sudo, real systemd and a pty
harness): kill the helper's process group at guardian log markers - run gate
received, exec event sent, exec released with a long-running target, target
exited - and assert that the instance is gone, that a relaunch refuses
before the change and recovers after it, and that the row shows the
recovered outcome with an unchanged binding. Negative controls: a stopped
helper keeps the lease, so recovery returns busy; an active unit is refused.

Deterministic barriers for the mid-flight windows need qualification-only
hooks in a separately installed generation, never in the production image.

Untestable here: power loss beyond `synchronous=FULL`, whether kernfs inode
numbers are never reused within a boot, a root process renaming cgroups, and
same-uid tampering with the Store, which is out of scope.

## Open questions

1. Is per-boot kernfs `st_ino` uniqueness on 64-bit acceptable as a
   documented assumption, and should the binding carry a boot identity for
   diagnostics?
2. Should recovery require an observed pid, or also accept the intent and
   spawn windows that have a binding but no pid? The same observation proves
   the scope retired either way.
3. Does the recovered outcome get its own custody wording, or reuse the
   `local_scope_empty` text?
4. Does the atomic intent-and-binding commit need its own review record?
   It has one (2026-11-25, in `continuation.md`); the 2026-11-22 mapping's
   ordering is unchanged, only its failure semantics.
