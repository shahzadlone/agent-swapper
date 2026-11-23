//! The outer-owner session helper. It wires the launch client's durable
//! journal seam to the real Store: the run intent is committed before the
//! launch gate, the spawn observation before the held-exec release, and the
//! authenticated target exit is committed together with the independently
//! observed scope retirement. The profile lease lifecycle blocks reuse until
//! the run resolves; unresolved runs stay resolved only by the separately
//! qualified restart recovery.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod store_journal;
