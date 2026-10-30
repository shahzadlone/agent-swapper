# Windows state privacy: qualification work

Windows state and vendor profile directories are **not yet verified private**.
Handle checks for reparse points and hardlinks do not establish access-control
privacy. File and directory ACLs can be inherited from their parent, so a
successfully created directory alone is not evidence that other principals
cannot read or modify it. See Microsoft's [file security reference](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

## Candidate audit

Source review of `windows-acl` 0.3.0 (MIT, published by Trail of Bits) found
that `ACL::all()` returns an empty entry list when the DACL pointer is null.
That list cannot be treated as evidence of a private ACL: Windows grants access
when the DACL is null or absent, whereas an empty DACL denies access. See the
[upstream implementation](https://github.com/trailofbits/windows-acl/blob/v0.3.0/src/acl.rs)
and Microsoft's [access-check reference](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck).
This observation does not determine whether other APIs in the crate are safe
for our use; it excludes using an empty enumeration as a privacy check. The
crate has not been added to AgentSwapper.

Further source review found a pointer-lifetime concern in
[`name_to_sid`](https://github.com/trailofbits/windows-acl/blob/v0.3.0/src/utils.rs):
when `system` is supplied, matching the owned `Option<Vec<u16>>` moves its vector
into an arm that returns `as_ptr()`. The vector is dropped before the following
`LookupAccountNameW` call uses that pointer. This is a source-level finding,
not an executed exploit. The descriptor and its DACL pointer are also hidden
behind private modules, so a caller cannot simply check nullness before `all()`.

An initial review of `windows-permissions` 0.2.4 at
[`8740e4e`](https://github.com/danieldulaney/windows-permissions-rs/tree/8740e4efbd88dd01046ad9c169894f3a52eb6e2c)
found that `current_process_sid()` casts a `Vec<u8>` buffer to `TOKEN_USER` and
dereferences it without an explicit alignment guarantee. That code needs a
soundness review or correction before relying on it. This is a source-level
concern, not a demonstrated exploit; the crate has not been added.

## Owned boundary decision

`agentswapper-windows-security` is a qualification candidate in the workspace;
neither the core nor CLI depends on it. Its immediate consumer is a disposable
Windows filesystem fixture. This replaces the idea of adopting an incomplete
ACL wrapper with a small owned boundary over the already-locked Microsoft
`windows-sys 0.61.2` bindings. It does not add a third-party package.

The core and CLI keep `unsafe_code = "forbid"`. This candidate uses `deny` with
one explicit exception for `ffi.rs`, and denies undocumented unsafe blocks and
unsafe operations in unsafe functions. Its parser explicitly forbids unsafe
code. This is a deliberate change to the earlier workspace-wide policy, not
unsafe code hidden inside a vendored dependency. Every native call documents
its buffer, ownership and lifetime invariants. Further independent review of
this boundary remains a promotion gate. A requested Opus 5.5 review returned a
session-limit message, not a completed ACL review.

The candidate implements:

- Process-user SID lookup without account-name resolution. Token information
  uses bounded, initialized, word-aligned storage; native pointers are checked
  against that allocation before the safe SID parser copies bytes. Thread
  impersonation is refused before identity selection and creation.
- SDDL conversion through Windows, with a protected DACL granting full control
  only to that user, LocalSystem and built-in Administrators. Those principals
  and other processes of the same user are trusted. Files use explicit ACEs;
  directories use explicit object/container-inheritable ACEs. Unsupported or
  inherited layouts are refused, even if they might otherwise be secure.
- Exclusive file/directory creation through `NtCreateFile`, relative to an
  owned parent handle, with the security descriptor supplied at creation.
  Directory creation and handle acquisition are one operation. The API accepts
  one validated child name, refuses reparse traversal, and verifies the native
  creation result. Returned handles are not inheritable and do not share deletion.
  Existing objects are never adopted or repaired. Failed post-creation checks
  can leave an empty object; cleanup never deletes an uncertain pathname.
- Owner/DACL snapshots via `GetSecurityInfo` on the actual file handle, with
  `LocalFree` ownership. Native descriptors must be self-relative before their
  bounded bytes are read. Owner, DACL presence, nullness, bounds, overlapping
  regions, trustee identities, ACE forms, flags and full-control masks are
  checked in safe Rust. Empty and null DACLs produce different refusals.
- Handle-based file type, reparse, link-count and volume checks. The initial
  candidate requires NTFS with persistent ACL support; other filesystems are
  refused. Path checks reject relative paths, UNC/device prefixes, alternate
  data streams, traversal, reserved devices and ambiguous trailing characters.

The [MS-DTYP descriptor layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d),
[self-relative descriptor contract](https://learn.microsoft.com/en-us/windows/win32/secauthz/absolute-and-self-relative-security-descriptors),
[handle security API](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[SDDL conversion](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw),
and [volume capability API](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew)
define the boundary. No caller-supplied descriptor bytes are passed into native
security APIs.

Relative creation follows Microsoft's user-mode
[`NtCreateFile` contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
and [`OBJECT_ATTRIBUTES` contract](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
Its root handle, UTF-16 buffer, native descriptor and output structures stay
alive through synchronous creation. `FILE_CREATE` never overwrites; no delete
sharing or inherited handle is requested. `create_new_at` first requires a
parent matching the private-directory policy. The absolute-path helper opens
and checks the immediate parent, then uses the same relative primitive; that
helper still requires trusted ancestors and does not qualify them itself.

The portable tests include malformed/truncated descriptors, arbitrary offsets,
null/absent/empty DACLs, broad/duplicate trustees, unfamiliar ACEs, inheritance
and overlapping components. Native fixtures cover actual creation, permissive
parent inheritance, replacement of a filename while retaining its original
handle, hardlink refusal, non-overwrite and Windows-generated descriptor forms.
Additional native fixtures replace a parent's old pathname before creating a
directory and file through its retained handle, verify that the replacement
receives nothing, and refuse traversal/stream/device names and broad parents.
They also refuse parent/child symbolic links without following them and verify
impersonation refusal on a disposable thread impersonating only its own user.
That fixture restores the thread identity on every exit; restoration failure
aborts the owned test process. It is not a separate-user access test.
Compilation is separate from native execution evidence.

An additional **ignored, CI-only** fixture creates a random local standard user
on this repository's disposable GitHub-hosted Windows runner. It requires both
the hosted-runner environment markers and `ASWP_CI_IDENTITY_FIXTURE=1` inside
the account-creation helper. Ordinary test runs skip it; invoking the ignored
test elsewhere refuses before account creation. The fixture calls `NetUserAdd`
with the local server, then `LogonUserW` and `ImpersonateLoggedOnUser` on a
dedicated thread. Its random password stays in zeroizing buffers, never argv,
environment variables, fixture files or output. It changes no existing account
or group. Cleanup owns a name only after successful creation, removes that
account explicitly after the test, and also attempts cleanup on error/unwind.

The other identity must first read and write a permissive control file. The
fixture then requires Windows `ERROR_ACCESS_DENIED` for private reads, writes,
security/delete access, removal, rename, listing and child creation; it finally
checks original file bytes and cleanup. For these ACL-only probes, owner-held
file handles are closed first, so a sharing violation cannot masquerade as an ACL denial. The
control parent grants others read/traverse, **not delete-child** access. A
permissive ancestor with deletion rights remains a separate custody problem.
The fixture also exercises that case explicitly under an additional parent
granting everyone full control. A closed private file must be removable through
parent rights. A closed private directory's result is recorded separately:
success or access denied are observations, not custody receipts. To test the
directory handle independently of ACL denial, an explicitly permissive directory
must be removable as a positive control. Equivalent attempts against a private
file and permissive directory whose creation handles remain open must fail
with access-denied or sharing-violation status. The permissive directory is also
required to fail the private-ACL policy. Actual codes are reported. This measures
a handle's protection during that interval, not a permanent guarantee for the
full path.
At `edcb5ef`, the file control was deleted, but `RemoveDirectoryW` returned
access denied for the closed directory in
[CI run 41001315576](https://github.com/shahzadlone/agent-swapper/actions/runs/41001315576).
The fixture failed before its retained-handle checks; that run does not qualify
directory custody. A subsequent DELETE-only open also returned access denied
at `fdde4bf` in [CI run 41002333737](https://github.com/shahzadlone/agent-swapper/actions/runs/41002333737),
before [file disposition](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
could run. The revised probe distinguishes that private-directory observation
from the successful permissive-directory control. A preexisting ACL denial is
never counted as proof that retaining a handle blocked deletion.
This test does not cover every group policy, filesystem or vendor credential
layout. Its execution result must be recorded before treating it as evidence.

The fixture uses the documented [local account creation API](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd),
[local logon API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
and [thread impersonation API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser).
Impersonation failure stops the probe, and failure to restore the thread's
identity aborts the owned test process. A killed CI job relies on destruction
of its disposable runner; it is not a supported local-machine test procedure.

This is not yet a private-path API. Creation is anchored to the supplied parent
object, but the caller must still establish that parent's identity and custody.
The candidate does not pin or validate the full ancestor chain, establish custody
against parent deletion rights, validate remote/mapped-drive behavior, protect
future vendor-created descendants, or qualify real vendor credential layouts. A handle
snapshot also cannot prevent later changes by trusted principals. Those gaps
must be resolved before storage integration or a privacy claim.

## Required before a privacy claim

The initial candidate's seven native fixtures and portable parser tests passed
at `54c7b19` in [CI run 40999147184](https://github.com/shahzadlone/agent-swapper/actions/runs/40999147184),
including the complete candidate/rebuild/provenance pipeline. This is evidence
for the initial snapshot/creation implementation only. At `444cd71`, the expanded
eleven native fixtures, twelve portable parser tests and full pipeline passed
in [CI run 40999776258](https://github.com/shahzadlone/agent-swapper/actions/runs/40999776258).
That run covers parent-handle creation, replacement, reparse and impersonation
refusal. At `515e519`, the native separate-identity fixture passed in
[CI run 41000440257](https://github.com/shahzadlone/agent-swapper/actions/runs/41000440257):
the temporary standard user read/wrote the permissive control and received
access-denied errors for the protected operations; original bytes and account
removal were checked. That result predates the parent-delete-child experiment
and does not itself establish packaging/rebuild success or production privacy.
Later parent-custody and parser changes need their own results.

The implementation must establish an appropriate owner and restrictive DACL
for the actual opened objects, distinguish null from empty DACLs, handle
inheritance and unknown ACE forms conservatively, and refuse unsupported
filesystems or ambiguous observations. New private directories need protection
at creation, before credentials or sensitive data can be written. Validation
must cover directory traversal and replacement races as well as files; merely
checking a pathname and reopening it is insufficient. Administrative and
system access, existing state migration, and vendor-created descendants need
an explicit policy and measured tests with separate Windows identities. Until
those gates pass, `doctor` continues to report ACL privacy as unverified.
