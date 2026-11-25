//! Job-control discipline for fresh Linux launch helpers: the signal
//! dispositions and the stop-signal mask that keep a session-owning helper
//! alive across background terminal-group operations. No process-custody
//! authority and no scope retirement: the caller owns the session lifetime.

use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use std::{fs, io};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// The job-control vocabulary: any helper that owns a session or receives a
/// foreground grant must meet interactive launches with default dispositions
/// for these signals, or a hostile inherited state stays unobservable.
pub const JOB_SIGNALS: [Signal; 7] = [
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTSTP,
    Signal::SIGTTIN,
    Signal::SIGTTOU,
    Signal::SIGCHLD,
];

/// The terminal stop signals whose delivery would stop a session-owning
/// helper that works the terminal in the background. `SIGSTOP` is
/// deliberately absent: it is uncatchable and must never arrive from the
/// terminal discipline, so it is never masked away, only observed.
pub const STOP_SIGNALS: [Signal; 3] = [Signal::SIGTSTP, Signal::SIGTTIN, Signal::SIGTTOU];

fn bits(signals: &[Signal]) -> u64 {
    signals
        .iter()
        .fold(0_u64, |bits, signal| bits | 1 << (*signal as u32 - 1))
}

/// One `/proc/self/status` mask field in its unsigned bit form. Kept as a
/// pure function over the status text so its parsing is independently
/// testable without touching a live process.
fn mask_field(status: &str, name: &str) -> io::Result<u64> {
    let field = status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .ok_or_else(|| io::Error::other("missing signal witness"))?;
    u64::from_str_radix(field.trim(), 16).map_err(io::Error::other)
}

/// Refuse inherited ignored or caught job-control dispositions: a helper
/// that starts with a hostile signal state would silently drop job-control
/// evidence instead of refusing the launch.
pub fn require_default_job_dispositions() -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let wanted = bits(&JOB_SIGNALS);
    let ignored = mask_field(&status, "SigIgn:")?;
    let caught = mask_field(&status, "SigCgt:")?;
    require(
        ignored & wanted == 0 && caught & wanted == 0,
        "helper requires default job-control signal dispositions",
    )
}

fn stop_set() -> SigSet {
    let mut set = SigSet::empty();
    for signal in STOP_SIGNALS {
        set.add(signal);
    }
    set
}

/// Block the terminal stop signals in this thread before any terminal group
/// operation. The kernel's terminal-change check treats a blocked stop
/// signal as ignored, so a background `tcsetpgrp` proceeds instead of
/// pending forever; new threads and spawned children inherit the mask.
pub fn block_stop_signals() -> io::Result<()> {
    stop_set()
        .thread_swap_mask(SigmaskHow::SIG_BLOCK)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

/// Block the whole job-control vocabulary in this thread for a session's
/// launch phase, mirroring the qualified launch fixture. The stop-signal
/// subset keeps terminal-group changes from stopping the only process that
/// mediates the session; the full set additionally keeps the kernel's
/// terminal hangup - which a pre-grant teardown of a freshly bound PTY
/// aims at the binding leader's own group - from ending the launch owner
/// before its refusal diagnostics reach the journal. The shim clears its
/// inherited mask before the target's exec, so the target still meets its
/// own default signal contract, and the mask's presence in the spawned
/// child is the controlled spawn's inheritance witness.
pub fn block_job_signals() -> io::Result<()> {
    let mut mask = SigSet::empty();
    for signal in JOB_SIGNALS {
        mask.add(signal);
    }
    mask.thread_swap_mask(SigmaskHow::SIG_BLOCK)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

/// Whether every job-control signal is blocked in this thread. A spawned
/// child verifies its inherited full-set mask as evidence that its creator
/// owned the launch phase's signal discipline, rather than trusting the
/// creator's claim.
pub fn job_signals_blocked() -> io::Result<bool> {
    let current = SigSet::thread_get_mask().map_err(io::Error::other)?;
    Ok(JOB_SIGNALS.iter().all(|signal| current.contains(*signal)))
}

/// Whether every terminal stop signal is blocked in this thread. A spawned
/// child verifies its inherited mask as evidence that its creator applied
/// the discipline above, rather than trusting the creator's claim.
pub fn stop_signals_blocked() -> io::Result<bool> {
    let current = SigSet::thread_get_mask().map_err(io::Error::other)?;
    Ok(STOP_SIGNALS.iter().all(|signal| current.contains(*signal)))
}

/// Clear the whole inherited signal mask before a final `exec`: the exec
/// preserves the mask, and the target must meet its own signal contract
/// with default unblocked state.
pub fn clear_inherited_mask() -> io::Result<()> {
    SigSet::empty()
        .thread_set_mask()
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_the_witness_fields_and_refuses_stray_bits() -> io::Result<()> {
        let status = "Name:\tfix\nSigIgn:\t0000000000000000\nSigCgt:\t0000000010000c77\n";
        assert_eq!(mask_field(status, "SigIgn:")?, 0);
        assert_eq!(mask_field(status, "SigCgt:")?, 0x10000c77);
        assert!(mask_field(status, "SigBlk:").is_err());
        // SIGHUP, SIGINT and SIGQUIT are all caught in this mock: refused.
        let caught = mask_field(status, "SigCgt:")?;
        assert!(caught & bits(&JOB_SIGNALS) != 0);
        Ok(())
    }

    #[test]
    fn a_live_helper_meets_its_own_disposition_contract() -> io::Result<()> {
        require_default_job_dispositions()
    }

    #[test]
    fn blocking_survives_a_round_trip_through_the_thread_mask() -> io::Result<()> {
        let saved = SigSet::thread_get_mask().map_err(io::Error::other)?;
        assert!(block_stop_signals().is_ok());
        assert!(stop_signals_blocked()?);
        // Restore exactly: the test process must not leak the blocked mask
        // into other tests that rely on default delivery.
        saved
            .thread_set_mask()
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    }

    #[test]
    fn a_fresh_thread_has_unblocked_stop_signals_by_default() -> io::Result<()> {
        assert!(!stop_signals_blocked()?);
        let cleared = clear_inherited_mask();
        let restored = SigSet::thread_get_mask().map_err(io::Error::other)?;
        assert!(cleared.is_ok());
        assert_eq!(restored, SigSet::empty());
        Ok(())
    }
}
