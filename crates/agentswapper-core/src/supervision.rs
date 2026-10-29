//! Experimental ownership of local process trees, not a credential or filesystem sandbox.
//!
//! Backends must pass provider-free custody fixtures before launch integration.
//! An empty local scope says nothing about work delegated to an external service.

#[cfg(windows)]
pub mod windows_job;

// Shared with the delegated fixtures while the guardian/journal integration
// is being qualified. No production launch calls this module yet.
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "the guardian launch integration is not yet enabled"
)]
pub(crate) mod linux_cgroup;

#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "the guardian launch integration is not yet enabled"
)]
pub(crate) mod linux_admission_transport;

#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "the guardian launch integration is not yet enabled"
)]
pub(crate) mod linux_launch_envelope;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod linux_shim;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod linux_guardian;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod linux_manager;
