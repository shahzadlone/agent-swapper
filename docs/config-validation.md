# Preferences validation

Evidence date: 2026-10-27. Scope: the two non-secret display preferences in
[the config guide](config.md). This checkpoint does not change launch permission,
provider routing, credential storage, registry schema or vendor-owned files.

## Local checks

Rust 1.98.0 on Linux/WSL2:

- 120 nextest tests passed; one intentionally ignored custody fixture entry.
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

The Windows-only replacement test holds the old file without delete sharing,
releases it during the bounded retry, and checks the new setting. Windows ACL
privacy and power-loss durability are not established by this fixture.

## Review and limits

A read-only Claude Opus 5.5 xhigh design review covered command dispatch,
read-only defaults, strict parsing, file-handle checks, lock/replace behavior,
first-frame masking and explicit overrides. The implementation uses a separate
lock, bounded handle-based reads and same-directory atomic replacement.
The resolved tempfile implementation was inspected locally to verify replacement
and failure ordering; no direct platform-API unsafe code was added.

Cooperating commands are serialized. A process running as the same user can
still edit files outside that protocol; no authentication boundary is claimed.
Preferences remain plaintext non-secret metadata. Windows ACL privacy,
Windows directory synchronization, network filesystems and power-loss crash
injection remain unverified. Automatic recovery never overwrites an unfamiliar
or malformed document.
