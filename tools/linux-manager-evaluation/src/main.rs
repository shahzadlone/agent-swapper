//! The fixture service/writer exist only in this binary, never the client library.
#![forbid(unsafe_code)]

mod activated_guardian;
mod activated_job_control;
mod activated_journal;
mod activated_terminal;
#[allow(
    dead_code,
    reason = "service uses only the shared peer credential decoder"
)]
mod activation_packet;
#[allow(
    dead_code,
    reason = "service uses selected shared transport operations"
)]
#[path = "../../../crates/agentswapper-core/src/supervision/linux_admission_transport.rs"]
mod admission_transport;
mod common;
mod fixture_policy;
mod job_control;
mod journal_protocol;
#[allow(dead_code, reason = "service uses only the shared own-scope witness")]
mod kernel;
mod terminal;
use common::{identity_map, require, valid_invocation};
use std::io;

fn main() {
    if let Some(result) = activated_guardian::dispatch() {
        if let Err(error) = result {
            // Fixture diagnostics only: this role accepts no provider secrets.
            // stdout is the activation socket, which the fault controls inspect.
            let mut diagnostic: String = error.to_string().escape_debug().take(1800).collect();
            while diagnostic.len() > 1800 {
                diagnostic.pop();
            }
            let packet = format!("activation fixture refused: {diagnostic}\n");
            // One bounded record, even when stdout's line writer would split a
            // formatted diagnostic. A full/closed peer must not block cleanup.
            let _ = rustix::net::send(
                io::stdout(),
                packet.as_bytes(),
                rustix::net::SendFlags::NOSIGNAL | rustix::net::SendFlags::DONTWAIT,
            );
            std::process::exit(125);
        }
        return;
    }
    aswp_linux_manager_evaluation::run_cli();
}
