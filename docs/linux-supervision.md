# Linux supervision experiment

Linux native launches remain uncontained. These provider-free experiments are
gates toward an opt-in backend, not a cleanup guarantee for current launches.

## Proposed ownership

The interactive supervisor keeps the foreground process group. A guardian runs
in a separate process group, outside the target cgroup, with no terminal I/O.
It owns a duplicate of the profile lease and a private control channel. Closing
the parent channel triggers cleanup; the guardian retains the lease until that
cleanup finishes. The target joins the supervisor's foreground group only after
private admission and a durable spawn observation.

A terminal's group-directed signal must not kill both supervisors. Separating
the guardian group addresses that particular failure, without preventing a
same-user process from killing both or a service manager from killing their
entire containing scope. Simultaneous supervisor loss remains unknown custody.

The existing durable unfinished run already blocks another launch after a
supervisor loses its lease. The guardian-held lease additionally blocks manual
attestation while cleanup is still active; it is not a replacement for the
journal. A cleanup observation and a root exit status are separate evidence.

The delegated cgroup parent must contain the supervisor and permit child-group
creation and admission. No privileged setup or process-group fallback will run
automatically. Trusted helpers must start with a neutral environment: target
environment and input are restored only after admission. Preserve inherited
ignored signal dispositions; do not blindly reset them. See Linux
[cgroup delegation](https://docs.kernel.org/admin-guide/cgroup-v2.html),
[exec signal semantics](https://man7.org/linux/man-pages/man2/execve.2.html) and
[shared file-lock ownership](https://man7.org/linux/man-pages/man2/flock.2.html).

## Executable evidence

`linux_admission_transport_probe` checks descriptor transfer, original stdin
semantics, close-on-exec and malformed admission. `linux_custody_probe` combines
that transport with actual delegated cgroup admission and cleanup. Their CI
results are recorded in [supervision validation](supervision-validation.md).

`linux_guardian_probe` uses only temporary files and cooperating fixtures. The
parent transfers its locked open file description over the anonymous socket;
the guardian has a different process group and no terminal standard streams.
The controller separately verifies that:

- Closing the parent's lease and channel while it stays alive produces EOF
  at the guardian and does not release the lock.
- Killing the owned parent's process group with SIGKILL leaves the guardian
  alive, observing EOF, and holding the lock.
- A separate open cannot acquire the lease until the guardian is explicitly
  allowed to finish simulated cleanup. It can acquire it afterwards.

The controller is a subreaper for these fixtures. Waits and reads are bounded;
cleanup never signals a PID read from a fixture file. This experiment does not
kill target processes, use a cgroup, test shell job control or issue a production
scope receipt. No providers, user credentials or host services are involved.

The guardian probe passed 25 local iterations (50 scenarios), then the Linux CI
probe at `d88d7cb`; all four CI jobs passed. This validates the separate-group
and lease behavior, not the remaining terminal and cgroup integrations.

## Remaining gates

An interactive bash/PTY fixture must cover foreground-group ownership,
interrupt, suspend/`fg`, resize, terminal close and inherited ignored signals.
Next, combine guardian failure cases with delegated cgroup cleanup and detached
writers. Audit group creation and removal failure paths before promoting the
fixture code. Integrate admission and receipts with the journal only once those
gates pass; every ambiguous result must remain unresolved. macOS needs its own
measured backend rather than inheriting Linux claims.

Claude Opus 5.5 at xhigh reviewed the proposed architecture. Its process-group,
signal-disposition and lease-retention observations informed these experiments.
The review did not qualify the implementation or real-provider behavior.
