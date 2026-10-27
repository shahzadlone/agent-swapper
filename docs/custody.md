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
| Detached writer survives original group kill | Demonstrated locally on WSL2, Linux 6.18.54.1-microsoft-standard-WSL2, and in CI on Ubuntu kernel 7.0.0-1017-azure, 2026-10-27 |
| Linux delegated cgroup | Not available to the current user on that host; hierarchy and control files are root-owned |
| macOS detached-writer probe | Passed on macOS 26.6.2 arm64 / Darwin 25.6.0, Rust 1.98.0, at `11ab437` |
| Windows strict Job containment | Not implemented or verified |
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
notification from other completion messages. The native launcher does not use
it. A separate Windows-only verification example combines its suspended
assignment with a process-lifetime root Job and independent membership queries.
Its runtime evidence is still pending; enabling a feature by name is insufficient.

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

Containment addresses owned local processes. It is not a filesystem sandbox or
proof about work delegated to an external service. Credential custody, native
login isolation, workspace fencing, and external side effects require separate
verification before managed switching can be enabled.
