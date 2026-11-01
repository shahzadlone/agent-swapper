//! Candidate kernel-backed namespace observations, not launch authority.
//!
//! Installation selection and manager prerequisites capture this before trusting
//! root-owned metadata. Production managed launch remains disabled; this value
//! does not authenticate installed policy, a manager or process custody.

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "fixed read-only syscall boundary, documented in ffi.rs"
)]
mod ffi;
#[cfg(target_os = "linux")]
mod observation;
#[cfg(target_os = "linux")]
pub use observation::{Backend, NamespaceFact, NamespaceKind, Origin};
