# Fresh managed CLI entry: integration candidate

Status: proposed topology, not implemented. Runtime component qualification does
not establish this composition. Start with explicit non-TUI `aswp run`; preserve
the existing dashboard launch path until its return and stop behavior has an
independent qualified design.

## Preserve the shell's original job

Executing a fresh supervisor image in the original CLI process preserves its
PID, process group and shell job membership while removing old runtime threads.
Launching an extra supervisor below an arbitrary multithreaded CLI does not
provide this automatically: a stopped helper alone may leave the original CLI
running, so the shell never sees its job stop. Do not silently change the
foreground group or assume the current fixed fixture accepts a grandparent's
group.

Prepare a durable run intent and a bounded private bootstrap packet before
exec. The new image must use a clean helper environment. Target argv/environment
belong in the private launch envelope, not helper command arguments or loader
environment. Preserve original terminal streams and lease capabilities through
the private descriptor protocol. No data should be restored from ambient global
authentication state. Failed or uncertain entry leaves the durable intent
unresolved; neither EOF nor the absence of a target marker completes it.

The fresh owner installs its signal mask before opening any runtime. It owns the
real Store and profile lease and starts a fixed relay child in its original
foreground group. The relay owns the private manager connection, inner terminal
and activation capability. Its protected shim reaches the exec hold before
requesting the parent's durable spawn observation.

Before acknowledging release, the parent independently binds original manager,
invocation, scope, guardian and child handles, then records RunSpawned. The relay
can release the exact held exec only after receiving that acknowledgement.
Neither party can reuse another run's acknowledgement or infer whether an
uncertain send reached its peer. On owner loss the relay must close its original
control capability even while stopped, as in the measured stopped-parent case.

The parent's retained observation is essential. The relay's serialized
"retired" message or its exit code cannot create a local-scope receipt. After
the relay exits, the parent independently verifies the original scope and
processes, and records target exit separately. It must not bind new handles only
after the old processes have disappeared. Parent death keeps the real journal
unresolved for separately qualified recovery.

## Required qualification

- Bootstrap exec preserves shell PID/group and private terminal streams; target
  argv/environment canaries never enter helper argv or environment.
- Invalid/truncated/extra capability bootstrap packets refuse before target
  execution; failed exec and lost peer retain the run intent and lease policy.
- Parent journal failure and disconnect while the target is held prevent an
  acknowledged release; uncertain release remains unresolved.
- Real interactive shell stop/bg/fg works across both helpers; the parent's
  SQLite/manager activity never changes another foreground job's terminal.
- Owner death while active and stopped retires the original relay and scope,
  while the journal preserves unknown outcome and no new owner fabricates proof.
- Native target exit status and output drain remain independent from scope
  retirement. The parent consumes only authenticated exit data plus its original
  independent retirement observation.
- Re-entry roles cannot run with inherited unsafe helper loader variables,
  another profile's lease, another run's intent, or an unqualified installation.

The root-installed guardian remains independent of the application database and
CLI. The unprivileged outer owner may use the application core; avoiding those
dependencies in the root-installed helper is the reason for the shared runtime
crate. The exact bootstrap frame and lease-transfer ordering still require an
implementation review and fault tests before this candidate becomes a product
entry point.
