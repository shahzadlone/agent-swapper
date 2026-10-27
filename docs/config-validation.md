# Preferences validation

Evidence date: 2026-10-27. Scope: the two non-secret display preferences in
[the config guide](config.md). This checkpoint does not change launch permission,
provider routing, credential storage, registry schema or vendor-owned files.

## Local checks

Rust 1.98.0 on Linux/WSL2:

- 122 nextest tests passed; one intentionally ignored custody fixture entry.
- Clippy with warnings denied, formatting, doctests and dependency policy passed.
- No new dependency or lockfile change.
- Existing terminal snapshots remain unchanged; the masked first-frame fixture
  now loads a saved preference through the production dashboard constructor.

New regression coverage establishes read-only defaults, persisted overrides,
source reporting, CLI flag precedence, restoration of defaults, redacted invalid
input (including non-UTF-8 bytes), corruption preservation, future formats,
null/duplicate/unknown fields, bounds, concurrent setters and readers, separate
processes, lock timeout, hardlinks, Unix symlinks/FIFOs/modes, and an injected
post-replacement directory-sync failure. `doctor` distinguishes preference errors
from a healthy registry. Explicit history flags, individual run inspection and
launch previews remain usable with a malformed preferences file.

Windows replacement fixtures cover ordinary read handles, handles without
delete sharing, and exclusive handles blocking pre-publication reads. Each
releases the handle during the bounded retry and checks the applied value. Windows ACL
privacy and power-loss durability are not established by this fixture.

## Review and limits

A read-only Claude Opus 5.5 xhigh design review covered command dispatch,
read-only defaults, strict parsing, file-handle checks, lock/replace behavior,
first-frame masking and explicit overrides. The implementation uses a separate
lock, bounded handle-based reads and same-directory atomic replacement.
A second read-only Opus 5.5 xhigh audit found no implementation blockers,
while flagging a Windows retry gap and durability/error-reporting limits. The
pre-publication handle check now shares the replacement retry budget. Oversized
files get a distinct, preserving size error; bounded reads take priority over
classifying an arbitrarily large future format. First-save parent-directory
power-loss durability is explicitly unverified.

The first CI pass at `93f3de1` exposed two issues: the Unix FIFO fixture used a
rustix API unavailable on Apple targets, and a reader could reject a legitimate
old inode unlinked by atomic replacement. The FIFO fixture now uses the POSIX
`mkfifo` utility. A distinct read-snapshot validator accepts zero links while
retaining all owner/mode/regular-file checks and rejecting multiple links;
lock files retain the strict one-link check. A deterministic retained-handle
regression covers this state. Local concurrency stress passed 50 iterations;
CI now repeats the concurrency fixture 25 times on each platform.

CI at `4eee839` passed Linux and macOS, including the new stress gate. Windows
caught a portability assumption in the deterministic retained-handle fixture:
replacement was denied while an ordinary read handle remained open for the
entire retry budget. The old value was preserved. The zero-link snapshot test
is now Unix-specific; a Windows counterpart verifies completion after the read
handle is released. The implementation keeps bounded retries and failure without
replacing the old document.

The resolved tempfile implementation was inspected locally to verify replacement
and failure ordering; no direct platform-API unsafe code was added.

Cooperating commands are serialized. A process running as the same user can
still edit files outside that protocol; no authentication boundary is claimed.
Preferences remain plaintext non-secret metadata. Windows ACL privacy,
Windows directory synchronization, network filesystems and power-loss crash
injection remain unverified. Automatic recovery never overwrites an unfamiliar
or malformed document.
