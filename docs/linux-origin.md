# Linux namespace origin candidate

The installation selection reader now captures this read-only observation before
opening its selector, manifest or images. Normal CLI execution still uses the
explicitly uncontained preview; the managed launcher is not enabled. A successful
observation does not establish service-manager custody, trusted installation
files or target exit.

## Contract

Capture the calling thread, including when it is not the process leader. Require
an ordinary, nonzero real/effective/saved/filesystem UID and GID, with each group
of four equal; bounded ordinary supplementary groups; and empty effective,
permitted and inheritable capabilities. Ambient capabilities are a subset of
permitted capabilities and are also checked explicitly in the procfs path.

The user namespace must have the kernel's reserved initial-user inode. Mount,
PID and cgroup namespaces must be owned by that user namespace. This permits
root-created container or mount namespaces; it does **not** prove membership in
the machine's initial mount/PID namespace. Matching the actual protected system
manager and its scope remains a separate prerequisite.

The observation retains namespace and owner descriptors, cannot be cloned or
sent/shared between threads, and must be rechecked on the originating thread
before relying on it. A helper captures its own observation after exec. Returned
facts and backend names are diagnostics and cannot construct an observation.
Trusted kernel, root and the process's own code are prerequisites. This is not
protection against same-UID code injection or a hostile administrator.

## Two capture mechanisms

1. Prefer a pidfd for the current TID using `PIDFD_THREAD`, then request namespace
   descriptors directly from the kernel. Unknown operations permit a fresh
   procfs capture; permission and I/O failures do not silently fall back.
2. On older kernels, authenticate a genuine procfs root by filesystem type and
   root inode. Resolve `thread-self` within that same mount; match its Pid/Tgid,
   all four UID/GID tiers, supplementary groups and capabilities to syscall
   observations. Pin each namespace symlink with `O_PATH|O_NOFOLLOW` and query
   its kernel-generated link text without following it. All these traversals
   prohibit mount crossings. Open the final fixed namespace name from the held
   directory and require an nsfs handle of the right type whose inode matches
   the independently pinned link. Re-read that link and retain the handle.

The final procfs-to-nsfs hop cannot use `BENEATH`, `NO_XDEV` or `NO_MAGICLINKS`;
Linux rejects those flags for a magic-link jump. The independent link identity
check authenticates the resulting descriptor instead. A borrowed initial-user
namespace handle is never used as the reference identity. Revalidation uses the
same backend and repeats the complete capture.

The small `ffi.rs` module is the sole unsafe boundary: fixed scalar namespace
ioctls, fresh descriptor ownership and credential queries. No caller supplies
ioctl numbers, raw descriptors or filesystem paths. `setfsuid(UINT_MAX)` and
`setfsgid(UINT_MAX)` use Linux's invalid-ID query behavior and do not change IDs.
All other operations use the pinned safe Rustix API. No new external dependency
version is introduced.

## Qualification

Six local Rust controls and three negative API doctests passed, including actual
leader/nonleader capture, agreement between both backends, credential mismatch
refusal, strict status parsing and malformed namespace links. Default and
qualification strict Clippy passed. Four ordinary Python controls check fixture
gates and exact failure classification. The ordinary local probe passed both
backends on WSL kernel 6.18.54.1; no local namespace or credential changes ran.

Hosted Ubuntu 22.04 and 24.04 jobs require explicit capability outcomes for the
measured images, not a version-based runtime decision. Both require procfs and
automatic capture success. The older runner must explicitly report unsupported
pidfd queries; the newer runner must pass them. An image update that changes
this observation requires reviewing the matrix expectation.

Privileged controls run only on opted-in disposable hosted runners, in recursively
private mount namespaces. They exercise a protected positive, root refusal,
a fresh child user namespace with full identity UID/GID maps, fake procfs,
a genuine procfs subdirectory in place of the root, overlaid status and an
overlaid namespace directory. A separate owner control leaves the observer in
the initial user namespace but enters a disposable mount namespace owned by a
child user namespace. Both capture methods must reject that owner, despite the
observer's initial-user membership. They require the intended result and diagnostic;
crashes, setup failures and generic errors are not successful negative tests.
Only the root parent maps its blocked child; no subordinate-ID files, accounts,
AppArmor policy or host sysctls are changed. Python starts isolated. Temporary
mounts disappear with the private namespace. The complete candidate pipeline
passed at `85c1059` ([41311810820](https://github.com/shahzadlone/agent-swapper/actions/runs/41311810820));
the complete installation-integration pipeline passed at `7dcd61f`
([41312005358](https://github.com/shahzadlone/agent-swapper/actions/runs/41312005358)).
The additional namespace-owner control and complete pipeline passed at `1183acc`
([41312243210](https://github.com/shahzadlone/agent-swapper/actions/runs/41312243210)).
These include native Ubuntu suites, cross-platform tests and independent rebuilds.
An additional hosted probe calls the
actual production `SelectedInstallation::open` in root and full-map child-user
contexts. Both must refuse at the origin check before reaching the deliberately
absent production selector; an absent-file error cannot satisfy that control.

Source-only Opus 5.5 reviews assessed the design and fallback. The separate
implementation/fixture review returned a safety-classifier refusal without a
usable audit conclusion; independent implementation review remains open.

The selected and admitted installation types retain origin across the selector
transition. Rechecking an active generation verifies its original namespace
observation before and after artifact checks. Service policy validates the
selection before reading its unit text. The manager prerequisite check also
establishes origin before trusting root-owned bus paths. Additional final-hop
and ownership controls, independent review and post-exec helper observations
remain separate gates.

## Primary contracts checked

- [Linux pidfd namespace query UAPI](https://github.com/torvalds/linux/blob/v6.11/include/uapi/linux/pidfd.h)
- [Kernel namespace inode reservations](https://github.com/torvalds/linux/blob/v6.11/include/linux/proc_ns.h)
- [Procfs namespace link behavior](https://github.com/torvalds/linux/blob/v6.11/fs/proc/namespaces.c)
- [Magic-link resolution restrictions](https://github.com/torvalds/linux/blob/v6.11/fs/namei.c)
- [Filesystem credential query behavior](https://github.com/torvalds/linux/blob/v6.11/kernel/sys.c)

The reserved initial-user inode is a kernel implementation contract, not a claim
of a stable documented UAPI. Unsupported or changed behavior must refuse; native
qualification is required for each supported platform.
