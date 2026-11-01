//! Candidate kernel-backed namespace observations, not launch authority.
//!
//! This crate is not yet consumed by the production installation reader.
//! Native qualification and independent review precede that integration.

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
