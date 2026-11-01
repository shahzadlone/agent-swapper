# Manager and installed-image review

Opus 5.5 reviewed source at `24cfa45` on 2026-11-01 with xhigh reasoning.
It executed no tools or tests. The review traced the fixed observer/guardian and
found latent public-API gaps and a misleading test assertion. It did not find a
high-severity defect reachable through the supplied fixed-path callers. The
subsequent opaque manager handle, shared retirement query and corrections below
are separate changes requiring their own combined native evidence.

| Finding | Correction and evidence |
| --- | --- |
| zbus's unique-name parser also accepts the bus-driver alias | Queries use an opaque authenticated manager handle and reject a different owner; an explicit colon-prefixed destination check also rejects the driver exception before authentication/query. A regression establishes that zbus accepts the alias while this policy refuses it |
| Unit object-path encoding left leading digits unescaped and mishandled empty labels | Encoding and regression cases now cover leading digits, empty labels, underscores and UTF-8 bytes, following systemd's bus-label rules |
| Root UID/mode metadata on a user-mounted filesystem can look like protected ancestry | Image admission also refuses nosuid mounts; its constructor explicitly requires an independently trusted namespace and fixed installed location. This is a conservative mount-policy check, not a universal filesystem-provenance proof |
| The temporary symlink test stopped at writable ancestry rather than the leaf | The staging test now checks that specific ancestor refusal; a separate protected `/proc/self` leaf test requires ELOOP |

The label behavior is documented by the primary
[systemd implementation](https://raw.githubusercontent.com/systemd/systemd/main/src/basic/bus-label.c).
The bus-driver exception was checked in the pinned zbus_names 4.3.1 source.
The mount-policy rationale follows [UDisks' documented mandatory nosuid option](https://storaged.org/udisks/docs/mount_options.html).
A legitimate administratively configured nosuid installation is also refused;
we do not assume `/usr` can never use that policy. Root/kernel and the caller's
installation-location policy remain trusted.

The image checker additionally requires absence of `security.capability`.
Present capabilities and uncertain xattr errors refuse admission. The new hosted
harness tests protected acceptance, nosuid, noexec, a capability xattr, a leaf
symlink, a writable image and non-root ownership. It creates only owned inert
files in private tmpfs mounts, drops root before opening them, never executes
them, and unmounts before removing its original empty directory. A failed unmount
never triggers recursive deletion. Local tests verify refusal before privilege
or fixture creation on an ordinary host and before mounting in the original
mount namespace. No privileged image fixture was run on the user's host.

The transport deadline helper is tested independently with
paused Tokio time and a pending future. An outer nine-second test guard makes a
missing transport deadline fail instead of hanging. The actual negative control
removed that inner deadline and failed with the expected assertion; the corrected
wrapper passes. This negative control exercises the helper, not the `connect`
wiring; the latter is checked by source review and the hosted stalled-socket
case. The timeout cannot preempt synchronous prerequisite filesystem reads.
Tokio's test clock is enabled only as a Linux dev feature of the
already pinned dependency, with no new registry package.

The concrete consumer still checks the current manager owner around scope
retirement and retains the original kernel handles. Shared read results are not
Store completion receipts. The new manager handle cannot silently retarget a
replacement owner and exposes no arbitrary method calls. It remains outside the
default CLI/core dependency graph.

Source checks outside the original excerpt confirm that journal and terminal
writer roles call `activated_guardian::writer_check`, and that the service calls
`protected_executable` before dispatching those protocols. Activation and both
journal binding paths call the shared `admit` transport. These checks resolve
excerpt uncertainty, not provider isolation or production installation.

Combined source `4fb4abf` passed the complete pipeline in
[run 41290326745](https://github.com/shahzadlone/agent-swapper/actions/runs/41290326745).
The seven original image/mount/capability controls passed on both Ubuntu 22.04
and 24.04. The client-side guardian comparison through the retained proc
directory and original pidfd (`7ca3650`) subsequently passed the complete pipeline
in [run 41290629942](https://github.com/shahzadlone/agent-swapper/actions/runs/41290629942).
These results include the shared manager and child-waiter changes, native scope
and terminal controls, cross-platform checks and unsigned package rebuilds.

Protected configuration handles were added after those reviewed snapshots.
Image admission also now uses the extracted file opener; that image path and
the new FIFO control require this revision's native evidence too. Config handles
retain the opened root-owned regular file, require mode 0644 and read at
most 16 KiB without changing the shared file offset. They do not establish
configuration semantics, an atomic administrative update or production manifest
provenance. Their eleven-case installed-asset harness has separate pending CI
evidence; the earlier seven-case pass does not qualify that extension.

The isolated retirement-query branch `064d3b9` passed Ubuntu 22.04 but failed
a background-admission case on Ubuntu 24.04 after the relay disappeared. That
branch predates the three suspension corrections. The output does not establish
the disappearance's cause; its result is not treated as qualified. The combined
branch contains the already qualified corrections and now retains the original
relay pidfd plus bounded lifecycle diagnostics in that harness, so unexpected
exit fails with useful evidence instead of only a missing `/proc` file.

The combined local terminal checks pass all nine outer-terminal and 13 owner
cases, eleven advisory/termination exec cases, three cleanup-signal cases and
the duplicate-stop regression. Both locked license/advisory policies pass.

## Follow-up review of `7ca3650`

Opus 5.5 xhigh performed a second source-only review on 2026-11-01. It found no
high-severity defect reachable through the supplied fixed callers. It identified
stale qualification statements above and a terminal status that could be lost
when an admission consumer used nix's finite signal decoder. It also identified
a numeric-PID window in a cleanup test and gaps in the retirement-race test and
deadline evidence descriptions.

The follow-up changes retain the terminal raw wait status after revoking wait
ownership; ECHILD records no outcome. The real-time decoder regression now proves
that the observed signal remains available after EINVAL. The active guardian's
exit-report path already uses raw events before decoding and was not affected.
The pre-extraction destructor was checked: it killed only its direct child,
so the shared waiter did not remove process-group cleanup. Descendant retirement
remains the manager's separate responsibility.

The cleanup test now uses its original pidfd for the final ECHILD assertion.
The retirement test exercises fresh absence, continued presence, recheck failure,
non-race refusal and a mismatched sender; the last two must not invoke a recheck.
All invocation lookups also apply the explicit unique-destination check. The
activation caller supplies both fragment and guardian-image locations from its
validated prefix. The image harness independently refuses shared mount propagation
before creating or mounting any fixture. The namespace prerequisite's API docs
explicitly distinguish identity-map/init.scope checks from host namespace proof.

Local follow-up validation passes 35 runtime tests, five compile-fail doctests,
eight manager tests, 49 evaluation tests, strict runtime/manager/consumer/core
Clippy, three mount-harness refusal controls, 14 activation-harness tests and
the dependency-boundary check. Native qualification remains pending.
Exact image mode 0755 remains the fixed fixture installation contract; supporting
read-only vendor layouts requires an explicit packaging decision. A hard-killed
hosted fixture may leave an empty temporary directory on its disposable runner;
cleanup never recursively deletes a mounted path. Production manager reload and
re-exec policy, versioned installation and removal, and an opaque Store completion
receipt remain open. No qualification result enables managed production launch,
automatic profile reuse or completion from a diagnostic boolean.

## Protected-file follow-up at `e8cc4e8`

Opus 5.5 xhigh reviewed the retained-config consumer and prior corrections using
source only. It found no high-severity defect reachable through fixed callers.
It identified that the shared leaf open needed O_NOCTTY: a session leader opening
a terminal device could acquire it before fstat refused the non-regular file.
The opener now prevents that process-wide side effect. A fresh-session subprocess
allocates its own PTY, reaches the exact leaf refusal and checks that it still
has no controlling terminal. Removing O_NOCTTY made that test fail; restoring it
passes. No user's terminal or privileged fixture is involved.

The executable-as-config control now asserts its exact mode refusal, and the
bounded-reader test proves the shared offset remains at seven. Admission decoder
failures now use the retained raw outcome to report the actual terminating signal;
the active exit-report protocol remains unchanged. The native-qualified status
is explicitly scoped to `7ca3650`, rather than implying these subsequent changes
were already covered by that earlier run.

Local checks pass 36 runtime tests, five compile-fail doctests, eight manager
tests, 49 evaluation tests and strict runtime/manager/consumer Clippy. Two ignored
helper roles are invoked by their passing subprocess tests. The current changes
still require native qualification. The review recommends an opaque activated
service binding as the next extraction, consumed by the existing qualification
client and witness before installation or Store receipt work.

The retained-config/FIFO checkpoint `6d2f727` subsequently passed the complete
pipeline [41291656552](https://github.com/shahzadlone/agent-swapper/actions/runs/41291656552),
and the first review follow-up `e8cc4e8` passed
[41292133837](https://github.com/shahzadlone/agent-swapper/actions/runs/41292133837).
The later NOCTTY correction has its own evidence requirement; the two earlier
passes are not substituted for it.
