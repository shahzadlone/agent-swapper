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
- Exclusive file/directory creation with security attributes supplied at
  creation. Returned handles are not inheritable and do not share deletion.
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

The portable tests include malformed/truncated descriptors, arbitrary offsets,
null/absent/empty DACLs, broad/duplicate trustees, unfamiliar ACEs, inheritance
and overlapping components. Native fixtures cover actual creation, permissive
parent inheritance, replacement of a filename while retaining its original
handle, hardlink refusal, non-overwrite and Windows-generated descriptor forms.
Compilation is separate from native execution evidence.

This is not yet a private-path API. Directory creation and opening are separate
operations; the caller must currently supply a trusted, stable parent. The
candidate does not pin or validate the full ancestor chain, establish custody
against parent deletion rights, validate remote/mapped-drive behavior, protect
future vendor-created descendants, or prove denial to a separate user. A handle
snapshot also cannot prevent later changes by trusted principals. Those gaps
must be resolved before storage integration or a privacy claim.

## Required before a privacy claim

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
