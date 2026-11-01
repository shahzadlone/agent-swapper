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

The transport's own eight-second deadline is also tested independently with
paused Tokio time and a pending future. An outer nine-second test guard makes a
missing transport deadline fail instead of hanging. The actual negative control
removed that inner deadline and failed with the expected assertion; the corrected
wrapper passes. Tokio's test clock is enabled only as a Linux dev feature of the
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

Remaining recommendations include corroborating the guardian's image through
its retained proc directory, replacing path-only template metadata with protected
file handles, and explicitly deciding production behavior during manager reload
or re-exec. Current uncertainty continues to refuse completion; it never grants
profile reuse. Combined native and cross-platform evidence for these corrections
remains pending.

Local combined validation passes 32 runtime tests, five compile-fail doctests,
seven manager tests and 49 evaluation tests, with strict runtime/manager/consumer
Clippy. The ignored runtime receiver role is invoked by a passing process test.
The two image-harness refusal tests, 14 activation-harness tests and production
dependency-boundary check also pass. Native mount controls remain pending.

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
