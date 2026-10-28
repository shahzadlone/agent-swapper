//! Experimental ownership of local process trees, not a credential or filesystem sandbox.
//!
//! Backends must pass provider-free custody fixtures before launch integration.
//! An empty local scope says nothing about work delegated to an external service.

#[cfg(windows)]
pub mod windows_job;
