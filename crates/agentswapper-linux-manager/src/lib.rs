//! Authenticated read-only system-manager transport. No launch or custody receipts.
//! The application does not yet use this crate for production managed execution.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
