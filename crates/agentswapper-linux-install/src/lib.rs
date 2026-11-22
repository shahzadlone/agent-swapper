//! Root installation executor for one fixed AgentSwapper generation. It
//! composes the qualified staging transaction with bounded service control
//! and, for the ordinary caller, verification through the installed readers
//! and the authenticated manager transport. This performs no launch, grants
//! no execution permission, and never places caller data in command
//! arguments.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
pub mod control;
#[cfg(target_os = "linux")]
pub mod executor;
#[cfg(target_os = "linux")]
pub mod launch_client;
