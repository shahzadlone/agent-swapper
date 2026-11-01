//! Authenticated read-only system-manager transport. No launch or custody receipts.
//! The application does not yet use this crate for production managed execution.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod invocation;
#[cfg(target_os = "linux")]
pub use invocation::require_active as require_active_invocation;
#[cfg(target_os = "linux")]
mod lifecycle;
#[cfg(target_os = "linux")]
pub use invocation::retired as invocation_retired;
#[cfg(target_os = "linux")]
pub use lifecycle::require_direct_lifecycle;
#[cfg(target_os = "linux")]
mod service;
#[cfg(target_os = "linux")]
pub use service::{BoundService, ServiceClaim, ServiceIdentity, ServicePolicy};
