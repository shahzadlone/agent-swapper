# Process custody verification

Native launches are uncontained by default. Windows users can explicitly opt
in to the experimental per-run Job backend described below. A direct-child exit, a free profile
lease, and an operator's stopped-process attestation do not prove that every
descendant has stopped. Run history reports those observations separately.
No current outcome enables automatic switching.

## Provider-free probes

Run the Unix probe with:

```sh
cargo test -p agentswapper-core --test custody_probe
```

It re-executes the test binary with an authentication-free environment and private fixture
files. Runtime-library and coverage instrumentation settings are allowlisted.
A child starts another session, spawns a writer, and exits. The probe
reaps that intermediate process, kills the original process group, and requires
new atomic heartbeat updates after the kill. A control writer remains in the
original group and stops. The writer reports its own group and session IDs.
All observations share one deadline. Its ignored test is the fixture entry
point, invoked explicitly by the probe. It is not an omitted verification gate.

The root remains unreaped until after the group signal, preserving its process
ID. Cleanup uses a private stop file for the escaped writer and the owned root
handle for termination. Linux adopts and reaps the fixture through a subreaper.
The probe never signals a PID read from a file. All fixtures have deadlines.

| Check | Recorded result |
| --- | --- |
| Detached writer survives original group kill | Demonstrated locally on WSL2, Linux 6.18.54.1-microsoft-standard-WSL2, and in CI on Ubuntu kernel 7.0.0-1017-azure, 2026-10-27 |
| Linux delegated cgroup | Not available to the current user on that host; hierarchy and control files are root-owned |
| Linux delegated cgroup fixture in CI | Admission refusals, cooperative detached-writer cleanup, outside control survival and retired-handle rejection passed on Linux `7.0.0-1017-azure` x86_64, Rust 1.98.0, at `639dac2` in [CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40477921157/job/122100633637) |
| macOS detached-writer probe | Passed on macOS 26.6.2 arm64 / Darwin 25.6.0, Rust 1.98.0, at `11ab437` |
| Windows Job fixture | Targeted termination, supervisor crash cleanup and breakaway refusal passed at `c728e58` in [CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40465056279/job/122058337169); not integrated into native launch |
| Real provider isolation and custody | Unverified for every harness |

Process groups remain useful for interrupt delivery. This probe establishes why
they cannot provide the stop evidence needed for automatic handover. A fixture
result does not promote a real-provider support cell.

CI records OS release, build, architecture, and the exact Rust compiler in
`target/platform-evidence.json` and a public `Platform evidence` check
annotation. A runner alias alone does not establish a verified OS version.

## Strict supervision gates

Linux needs a separately owned delegated cgroup, admission before target code
runs, a kill of that run's subtree, and a subsequent empty observation. The
kernel documents membership inheritance, migration, and the subtree interfaces
in its [cgroup v2 reference](https://docs.kernel.org/admin-guide/cgroup-v2.html).
The implementation must refuse missing delegation and must never kill the
parent cgroup as a fallback.

Windows needs assignment before target execution, non-inherited ownership of
the Job handle, crash cleanup, breakaway refusal, and a kernel query confirming
no owned workers remain. A completion notification or direct-child exit alone
is insufficient. See Microsoft's [Job Objects reference](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

An audit of process-wrap 10.0.1 found that its std Job wrapper creates a Job
without kill-on-close, and its wait helper does not distinguish an empty-Job
notification from other completion messages. The default native launcher does not use
it; the opt-in Windows backend adds separate ownership and empty checks. A separate Windows-only verification example combines its suspended
assignment with a process-lifetime root Job and independent membership queries.
Its provider-free runtime probe passed in the CI run linked above; enabling a
feature by name alone is insufficient. The default native launch remains uncontained.

Run that provider-free spike on Windows with:

```sh
cargo run -p agentswapper-core --example windows_custody_probe
```

It tests targeted Job termination, hard termination of the owned supervisor,
and refusal of breakaway child creation at both the root and inner Jobs.
Adjacent normal children are positive controls; refusal must be Windows
access-denied, rather than an arbitrary spawn error. The root membership query must leave only the trusted
supervisor after targeted termination. Crash cleanup uses a controlled writer's
lifetime lock and heartbeat as fixture observations; it does not issue a general
custody certificate. Helpers have deadlines and use private temporary files.

## Delegated Linux cgroup probe

The `linux_custody_probe` example requires an already delegated cgroup v2 parent
containing the unprivileged supervisor. It never creates a privileged delegation
or kills the parent. It refuses ordinary directories, links, a root user,
wrong ownership, writable-by-others directories and threaded groups.

The supervisor creates a unique run group, places its owned child there, verifies
membership and releases a trusted shim through a private GO pipe. Missing or
invalid GO and GO without membership refuse execution for individually checked
reasons; a file named `go` grants no authority. The cooperative fixture target
double-forks and changes session. The probe requires continuing heartbeats before
the targeted `cgroup.kill`, then verifies the group is empty, retires it and reaps
the killed writer. A writer outside that run group must continue. A separate
test holds an admission descriptor across retirement and requires late entry to
fail with ENODEV. Fixture processes have deadlines, and cleanup targets only owned groups.

For manual invocation, explicitly supply an already delegated parent containing
the supervisor (ownership alone does not prove systemd delegated a scope):

```sh
cargo build --locked -p agentswapper-core --example linux_custody_probe
target/debug/examples/linux_custody_probe /sys/fs/cgroup/PATH_TO_EXISTING_DELEGATION
```

The CI helper only accepts membership in its dedicated `aswp-custody-ID-ATTEMPT`
system service and invokes the probe. It performs no setup and refuses arbitrary
terminal scopes. Current WSL delegation remains unavailable, so local results cover
refusal and compilation only. CI creates a separate transient systemd service
on disposable GitHub-hosted Linux, delegates it to the runner user and executes
the probe unprivileged. Privileged setup is confined to that workflow; it is not
run on the user's host or a self-hosted runner. See systemd's
[delegation settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
The CI checkpoint at `639dac2` passed all three recorded assertions: exact
admission refusals; cooperative setsid-writer termination with an empty, retired
group and surviving outside control; and ENODEV for the previously opened late
admission handle. The table above records the measured kernel and compiler.

This tests admission and explicit subtree cleanup, not supervisor-crash recovery,
credential isolation, a hostile process migrating itself out of the delegation,
or a production custody certificate. The GO pipe is not an authentication boundary
against other malicious processes running as the same user. Those remain separate gates.

Containment addresses owned local processes. It is not a filesystem sandbox or
proof about work delegated to an external service. Credential custody, native
login isolation, workspace fencing, and external side effects require separate
verification before managed switching can be enabled.

## Per-run Windows backend (experimental)

`supervision::windows_job` owns a fresh kill-on-close Job per run, never placing
the supervisor in it. The target is created suspended, assigned by its owned
process handle, checked as the sole member, and passed to the admission callback
before the nested wrapper resumes it. Root-process exit and local-scope emptiness
are separate observations. Stop consumes the scope, terminates its nested Job,
and queries the outer Job until empty within five seconds. Errors produce no
receipt. The receipt is non-cloneable with private fields; no handle or late
admission operation is exposed. `aswp run` and `aswp login` can select it with
`--experimental-native --experimental-containment windows-job`. It refuses other
hosts and gents profiles without fallback. Any error after durable intent keeps
the run unresolved, including spawn errors where the target may never have run.
Only a successful matching receipt records `local_scope_empty`. Operator recovery
still records an attestation, even if crash cleanup happened in the kernel.

Run the backend fixtures on Windows:

```sh
cargo run --locked -p agentswapper-core --example windows_supervision_probe
```

They exercise delayed admission, rejection/unwind, immediate descendant creation,
root exit with a live descendant, normal and breakaway child controls, already-empty
stop, two independent run scopes, failed spawn isolation, drop and supervisor
crash cleanup. Writer lifetime locks distinguish termination from voluntary exit;
fixture observations after a crash are not durable recovery receipts. The backend passed at `ef6e973` in
[Windows CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40638824387/job/122651927673),
alongside successful Linux, macOS and dependency jobs. That checkpoint verified
the backend fixture, before launch/journal integration; integrated launch/journal and failure injection subsequently passed at `6d0e394`.
See the [validation record](supervision-validation.md) for measured platforms,
review findings and remaining limits.

The interval between process creation and first Job assignment is not atomic.
A hard supervisor crash there may leak a suspended process (no target code has
executed). Dependency cleanup after a nested-wrapper failure can use an unbounded
wait. The backend does not constrain work requested through WMI, COM, Task
Scheduler, services or other outside processes, and does not defend against a
malicious process with the same OS identity. Provider credential isolation,
workspace fencing and cross-brand context continuity remain separate gates.

Additional Windows unit tests inject failure after admission returns success,
admission rejection/unwind, a membership-query error and an expired cleanup
deadline. A separate kernel Job observer verifies that admitted processes drain
on those error paths; no receipt is returned. Compile-fail doctests reject receipt
construction/duplication and scope reuse after stop. The ignored Windows test
entrypoint is re-executed by these tests with a private marker and no provider.
