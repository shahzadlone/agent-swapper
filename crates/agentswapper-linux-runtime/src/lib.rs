//! Internal Linux helper building blocks. No process-custody authority.
//!
//! The transport carries bounded private launch data; it does not authenticate
//! an installation, authorize execution, observe exec, or retire a process scope.
//! Production managed execution remains disabled pending those integrations.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod admission_transport;
#[cfg(target_os = "linux")]
pub mod launch_envelope;

#[cfg(target_os = "linux")]
pub mod signals;

#[cfg(target_os = "linux")]
pub mod terminal;

#[cfg(target_os = "linux")]
pub mod scope_observation;

#[cfg(target_os = "linux")]
pub mod child_waiter;

#[cfg(target_os = "linux")]
pub mod installed_image;

#[cfg(target_os = "linux")]
pub mod installed_config;
#[cfg(target_os = "linux")]
pub mod installed_manifest;
#[cfg(target_os = "linux")]
pub mod process_policy;
#[cfg(target_os = "linux")]
mod protected_file;
