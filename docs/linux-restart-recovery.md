# Restart recovery: why it is not implementable from the user's record

Status: design review closed, **nothing implemented** (2026-11-25). The
provider-free settlement defects that made an ordinary error strand a
profile are fixed separately (`6f1a621`, `e7fb98c`, `cf1eb74`); this page
records why the remaining gate - a run whose client died - cannot be closed
the way the survey first proposed, and what would have to exist instead.

## The gap

A managed launch holds a durable run and a one-use retirement authority
together. `Store::retire_linux_scope` accepts only the in-memory
`PendingLinuxScope` that `confirm_intent` produced, matched against a
`RetiredService` the manager observed on its own authenticated connection and
against the durable `LinuxScopeBound` binding
(`crates/agentswapper-core/src/store/linux_scope.rs`,
`crates/agentswapper-linux-manager/src/service.rs`). None of that survives the
client's death, so the Store can no longer retire its own run: it stays
unresolved, the profile stays blocked, and the only way out is the operator
attestation `aswp registry recover RUN --confirm-stopped`, which records
`user_attested_stopped` and proves nothing.

## What the survey proposed

A new boundary: `observe_orphan_retirement` in the manager, which would
combine an authenticated "no unit for this invocation" answer with
kernel evidence that the recorded cgroup directory is gone and its device and
inode are no longer the ones bound, returning a `RecoveredService` that only
`Store::recover_linux_scope` could consume, committed under the profile lease.
The intent was that this is more than attestation: an independent observation
of the closure, not the user's word.

## Why that argument fails

Every input to the proposed proof is either the user's own write or a
negative statement about an identifier the caller chose.

- **The record being checked is the thing in doubt.** The run row, its
  binding, the unit name, the invocation, the device and inode all live in a
  Store the same user can write. Matching an observation against them proves
  only that the observation matches the file.
- **Two negatives do not authenticate an association.** "No unit for this
  invocation" and "that cgroup directory is not the bound one" are both true
  of an invocation and a binding that never existed. A same-uid process can
  write such a record and have the proposed API bless it. The result would be
  an attestation wearing the name of an observation - worse than today's
  honest `user_attested_stopped`, because it would look proved.
- **The ordering in the proposal did not work.** `Store::lease` refuses a
  profile with an unresolved run, so the recoverer cannot lease first and
  observe after, and the proposed API observe first and lease at commit, with
  no manager at commit time for the promised ownership check.
- **The kernel facts are one-way, but they are not provenance.** A cgroup v2
  directory cannot be removed while populated, and an invocation identity
  never returns, so a genuine observation cannot be stale. Nothing about
  those facts binds them to the record that asked the question.

The conclusion is not a fixable ordering defect. Within a single trust
domain - one uid, one writable Store - no amount of checking can distinguish
"this run's scope closed" from "the file says so", because the file is the
only statement about which scope was ever this run's.

## What would change the answer

Root-owned provenance: a record of the closure made by something the user
cannot write. The manager and the guardian are the natural authors, because
they already observe the scope's retirement on their own authenticated
connection and already run as a separate identity. A design would need:

- the installation shape to name a root-owned, append-only retirement log,
  bounded and rotated, keyed by the unit's invocation identity and the user;
- the manager to append exactly one record when it observes an instance's
  scope closed, including enough to bind it to the launch that requested it -
  and nothing that would let a user cause records for launches they did not
  make;
- the recoverer to read it (read-only, unprivileged) and to keep its own
  checks as a cheap pre-filter;
- an independent review of that new authority, because appending to a
  root-owned log per launch is new write authority for a root component and a
  new durable surface across upgrades.

Until such a design exists and passes review, the honest position is that
crash recovery cannot be stronger than attestation, and adding an API that
looks stronger is the harm to avoid.

## Corrected facts for the next design

The survey's crash-window table was wrong in ways that matter:

- **Before the gate something is already under the tracer.** The guardian
  forks a shim, traps it before the resume, grants it the foreground and only
  then waits for the launch gate; a helper killed before the gate does not
  leave "nothing running".
- **The "exec released" marker precedes the detach, the master transfer and
  the waiter.** `ChildWaiter` is installed after the master is handed over;
  its drop *attempts* a kill, which is cleanup policy, not evidence of
  retirement. Hosted crash scenarios must therefore kill at markers that do
  not imply a state the code has not reached.
- **No authenticated exit is durably recoverable before the commit.** The
  exit report exists in the client's memory until `audit_exit`; a crash before
  it loses it, so any recovered outcome has no exit by construction.
- **A successful retirement drops the lease before the helper exits.** The
  lease is a live-file lock, so a helper killed later leaves the profile free;
  the unresolved row is what blocks reuse, not the lock.
- **`Binding::bind` proves the caller's own namespaces and cgroup2, not the
  membership of what was recorded.**
- **Doctor must call a bound run a candidate for attestation**, never
  "recoverable", and must change nothing.

## What stays from the survey

The one-way kernel facts still bound what any future evidence must show: the
scope cannot close out from under a live process, and an invocation identity
never returns, so a genuinely observed closure is final. The refusals the
survey listed remain the right refusals - never an exit other than the
nonce-bound report, never "stopped" from a pid, `/proc`, elapsed time or a
free lease, never recovery by a system component. They are simply not
sufficient to constitute proof on their own.

## Decision

- `aswp registry recover RUN --confirm-stopped` remains the only way to clear
  an orphaned run, and it remains attested rather than proved. Nothing in the
  CLI, the helper or the docs may present it as recovery.
- No `RecoveredService`, no `Store::recover_linux_scope`, no schema 10
  `LinuxScopeRecovered` event. The proposed events stay unimplemented, so no
  migration and no schema bump is owed.
- The next step, if crash recovery is wanted, is a reviewed design for
  root-owned retirement provenance. It is not started.

## Evidence for this document

`Store`'s run and binding records are user-writable by design
(`docs/custody.md`, `docs/linux-scope-retirement.md`); the retirement path's
in-memory values are not serializable and cannot be rebuilt
(`store/linux_scope.rs`); the guardian's markers and the waiter's placement
are in `crates/agentswapper-linux-guardian/src/linux/launch.rs`;
`invocation::retired` answers a negative for identifiers it is given
(`crates/agentswapper-linux-manager/src/invocation.rs`). The review that
reached this conclusion is recorded in `docs/continuation.md`.
