//! Experimental Windows ACL primitives, not a complete private-path boundary.
//!
//! No production AgentSwapper crate depends on this qualification candidate.
//! Handle validation is a snapshot, not a guarantee against later ACL changes.
//! Creation requires a trusted, stable parent: ancestor custody, vendor-created
//! descendants and separate-identity access tests remain integration gates.

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
    #[error("the object is not owned by the selected process identity")]
    OwnerMismatch,
    #[error("the DACL does not match the restricted creation policy")]
    UnexpectedDacl,
    #[error("the filesystem object has an unsupported type, link or filesystem")]
    UnsupportedObject,
    #[error("the path is not an absolute, local Windows filesystem path")]
    UnsupportedPath,
    #[error("thread impersonation is unsupported for private object creation")]
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
}
