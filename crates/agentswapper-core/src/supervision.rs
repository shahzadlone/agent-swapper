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
