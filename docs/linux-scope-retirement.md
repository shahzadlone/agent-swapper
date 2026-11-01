# Linux scope retirement and journal completion

Status: implemented behind `linux-journal-qualification`. The initial durable
completion checkpoint (`17f74e3`) passed full CI, including both native Ubuntu
runners. The association changes below require their own native result. Normal Linux launching remains the
explicit uncontained preview; this is not a production managed launcher or a
provider-isolation qualification.

The journal now distinguishes an empty local process scope from a known target
exit. A valid retirement can permit profile reuse while the target's exit code
remains unknown. Reuse also requires the existing OS lease to be free.

## Original live association

Before target preparation, the Store records the admitted unit, invocation,
guardian UID/PID and original cgroup device/inode. These fields are diagnostics.
A private pending association additionally retains the original `ServiceKey`,
run/scope identity and an allocation identity for this exact Store instance.
Neither that association nor a retirement value can be reconstructed from JSON.

Each binding permits one claim of its non-cloneable service key. In the Store
terminal relay, the journal owns that key and lends it back to target preparation,
which checks the exact
original binding before sending launch data or transferring the lease. A key
from an independent witness cannot prepare the original target. Schema 9 also
prevents one manager invocation from being associated with multiple runs,
including after the original run retires. The Store records the canonical run
identity returned by lookup rather than retaining a caller's spelling.

Other fixed qualification consumers can hold the claimed key locally. The key
check itself establishes the original binding; it does not independently prove
that a journal transaction occurred or that the separately supplied lease belongs
to a particular run. The Store relay's private association supplies that coupling.

```mermaid
sequenceDiagram
    participant J as Live journal consumer
    participant B as Original service binding
    participant S as Store
    J->>S: Commit run intent and original binding
    J->>B: Prepare and start under journal gates
    J->>B: Close control and observe retirement
    B-->>J: One opaque retirement value
    J->>S: Match original live association and commit retirement
    S-->>J: Local scope retired; target exit remains unknown
```

The manager binding checks original cgroup removal, original guardian pidfd
death and authenticated original-invocation retirement on the exact retained
connection. The terminal-session consumer additionally checks the original
target pidfd before issuing its result. One deadline covers observation and
issuance. A fresh witness of the same invocation has a different key and cannot
replace the original binding after a crash.

The Store rejects another run's value, another Store instance, an independent
witness and mismatched durable identity. A failed commit returns the original
retirement value for an in-place retry. A retry cannot append a second completion
event. The fixed command-line qualification fixture aborts on a commit error;
its unresolved durable record continues to block reuse.

The general Store event writers reject scope transitions even when their JSON
is otherwise valid. Only this module can authorize recording after live-key or
receipt validation. An explicitly named test-only path exercises projection and
migration rules without manufacturing runtime authority.

## Durable state

Schema 8 added `linux_binding` metadata and indexes unfinished runs by absent
outcome rather than absent exit code. `LinuxScopeBound` commits before target
preparation. `LinuxScopeRetired` atomically appends its event and updates the
projection to `local_scope_empty`, leaving `exit_code` null. A child exit alone,
an unlocked lease, copied diagnostic fields or a missing unit name cannot emit
this transition through the completion API.

Migration retains the existing verified pre-migration backup and rollback
behavior. Old pending Linux runs remain pending with no invented binding or
completion. Older schemas containing future receipt events or unexpected DDL
are refused. History displays a retired Linux scope with `exit=unknown`.

## Evidence and limits

Local workspace tests, strict workspace/qualification Clippy, dependency-boundary
checks and Python fixture checks pass before native submission. Tests cover
schema-7 migration and backup preservation, rollback on mismatched metadata,
duplicate completion, lease gating and unknown target status. The hosted suite
adds real wrong-run, independent-witness, duplicate and reopened-Store controls,
commit failure followed by retry with the same value, and guardian SIGKILL with
successful scope retirement but unknown target exit. Native results are pending.

The qualification-only Store API does not enable the normal CLI's managed
backend. Target-exit persistence, protected production installation, the fresh
production guardian/helper and their launch integration still require their
own implementations and qualification. Lost original handles stay unresolved;
this mechanism does not provide restart recovery, remote-work custody or vendor
credential isolation. Real-provider checks remain deferred until the final
validation stage requested by the user.

## Association review follow-up

A source-only Opus 5.5 review identified that cloneable keys and repeated key
retrieval made incorrect consumer composition possible. The one-claim key,
preparation check and unique invocation index address that finding together.
The raw-path `ServicePolicy` constructor is now qualification-only; ordinary
consumers must supply a protected selected installation.

Local controls pin the serialized binding format, reject duplicate invocation
association before and after retirement, and migrate a schema-8 registry while
preserving unknown exit status and its verified backup. Native controls exercise
wrong-key preparation and then successfully prepare the original service with
the same lease and key. Wrong-run and reopened-Store refusals return their
retirement values; the original Store subsequently commits those same values.
This revision's native results are pending. Additional review findings and
production gates are tracked in [the follow-up](linux-release-review.md).
