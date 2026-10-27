# Process custody verification

Current native launches are uncontained. A direct-child exit, a free profile
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
| Detached writer survives original group kill | Demonstrated locally on WSL2, Linux 6.18.54.1-microsoft-standard-WSL2, 2026-10-27 |
| Linux delegated cgroup | Not available to the current user on that host; hierarchy and control files are root-owned |
| macOS detached-writer probe | Awaiting CI for this probe |
| Windows strict Job containment | Not implemented or verified |
| Real provider isolation and custody | Unverified for every harness |

Process groups remain useful for interrupt delivery. This probe establishes why
they cannot provide the stop evidence needed for automatic handover. A fixture
result does not promote a real-provider support cell.

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
notification from other completion messages. The dependency has not been
adopted. Its wrapper behavior needs additional ownership and verification
before it can support these gates; enabling a feature by name is insufficient.

Containment addresses owned local processes. It is not a filesystem sandbox or
proof about work delegated to an external service. Credential custody, native
login isolation, workspace fencing, and external side effects require separate
verification before managed switching can be enabled.
