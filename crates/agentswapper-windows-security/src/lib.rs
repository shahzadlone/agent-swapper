//! Experimental Windows ACL primitives, not a complete private-path boundary.
//!
//! No production AgentSwapper crate depends on this qualification candidate.
//! Handle validation is a snapshot, not a guarantee against later ACL changes.
//! Creation requires a trusted, stable parent: ancestor custody, vendor-created
//! descendants and production storage integration remain qualification gates.

mod descriptor;
#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "audited Win32 ownership boundary; see docs/windows-acl.md"
)]
mod ffi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    File,
    Directory,
}

/// Access requested when reopening an existing private file. Neither option
/// creates, truncates, repairs permissions or shares deletion of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or unsupported Windows security descriptor")]
    InvalidDescriptor,
    #[error("the security descriptor has no DACL")]
    AbsentDacl,
    #[error("the security descriptor has a null DACL")]
    NullDacl,
    #[error("the security descriptor has an empty DACL")]
    EmptyDacl,
    #[error("the DACL is not protected from parent inheritance")]
    UnprotectedDacl,
    #[error("the object owner is not allowed by the selected security policy")]
    OwnerMismatch,
    #[error("the DACL does not match the selected restricted policy")]
    UnexpectedDacl,
    #[error("the filesystem object has an unsupported type, link or filesystem")]
    UnsupportedObject,
    #[error("the path is not an absolute, local Windows filesystem path")]
    UnsupportedPath,
    #[error("thread impersonation is unsupported for private object access")]
    Impersonation,
    #[error("Windows security operation failed")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Exact creation policy: process user, LocalSystem and built-in Administrators
/// receive full control. Other trustees, ACE forms and inheritance are refused.
/// Administrators, SYSTEM and other processes of the same user are trusted.
pub struct SecurityPolicy {
    owner: descriptor::Sid,
}

impl SecurityPolicy {
    /// Validate an owned, self-relative descriptor snapshot without pointer
    /// casts. This does not perform a Windows access check or pin a pathname.
    pub fn validate_descriptor(&self, bytes: &[u8], kind: ObjectKind) -> Result<()> {
        descriptor::validate(bytes, &self.owner, kind)
    }

    /// Snapshot-only policy for a file directly inheriting the three exact
    /// grants from a private parent: all ACEs inherited, no explicit additions,
    /// no protection or unknown flags. Owner may be the process user, SYSTEM or
    /// Administrators, all of whom already have full access under this policy.
    /// Flags cannot prove inheritance origin or parent custody. Native callers
    /// should use `open_existing_inherited_file_at` with a protected parent.
    pub fn validate_inherited_file_descriptor(&self, bytes: &[u8]) -> Result<()> {
        descriptor::validate_inherited_file(bytes, &self.owner)
    }

    /// Candidate permission classification for a retained ancestor directory.
    /// This is NOT a privacy or pathname-custody check: it allows reads, new
    /// subdirectories and deletion by other users, which requires retaining the
    /// entire no-delete-shared handle chain. It refuses untrusted in-place
    /// mutation grants and unknown ACE forms. Ancestor owners may additionally
    /// be the Windows TrustedInstaller service. Private root policy is separate.
    pub fn validate_ancestor_descriptor(&self, bytes: &[u8]) -> Result<()> {
        descriptor::validate_ancestor(bytes, &self.owner)
    }
}
