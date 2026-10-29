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

An initial review of `windows-permissions` 0.2.4 at
[`8740e4e`](https://github.com/danieldulaney/windows-permissions-rs/tree/8740e4efbd88dd01046ad9c169894f3a52eb6e2c)
found that `current_process_sid()` casts a `Vec<u8>` buffer to `TOKEN_USER` and
dereferences it without an explicit alignment guarantee. That code needs a
soundness review or correction before relying on it. This is a source-level
concern, not a demonstrated exploit; the crate has not been added.

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
