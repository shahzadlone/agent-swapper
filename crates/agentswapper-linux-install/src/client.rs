//! The ordinary launch client. The flow ordering is enforced by this
//! module: the durable run intent is committed before the launch gate, the
//! durable spawn observation before the held-exec release, and the
//! authenticated exit report is audited before the connection closes. The
//! caller supplies the journal implementation; a production Store adapter
//! needs an independent review (see `launch_client::Journal`).
use crate::launch_client::Journal;
use agentswapper_linux_manager::{
    BoundService, LoadedSocket, ServiceClaim, ServicePolicy, SocketPolicy,
};
use agentswapper_linux_runtime::activation_offer::{
    BIND_REQUEST, Offer, RUN_REQUEST, connection_unit,
};
use agentswapper_linux_runtime::signals::Signals;
use agentswapper_linux_runtime::target_exit::TargetExit;
use agentswapper_linux_runtime::{
    activation_packet, admission_transport as transport, installed_selection::SelectedInstallation,
    launch_envelope::LaunchEnvelope, launch_protocol,
};
use rustix::net::SendFlags;
use rustix::termios::Termios;
use std::{
    io::{self, Read, Write},
    os::fd::{AsFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

/// The admission budget covers connect through the terminal-master backhaul
/// only. Everything after it lives in the target's own lifetime: the relay
/// waits the master to its end, each stop exchange and each observation
/// gets a fresh bounded window, and a long session never inherits this
/// deadline.
const LAUNCH_ADMISSION: Duration = Duration::from_secs(60);
/// A fresh bounded window for each active-phase exchange: the stop-notice
/// receive, the resume-grant send, the exit-report receive and the resumed
/// foreground wait.
const ACTIVE_WINDOW: Duration = Duration::from_secs(8);
/// After the authenticated exit report, the master is drained a last bounded
/// stretch: descendants that still hold the slave never extend the session.
const DRAIN_IDLE: Duration = Duration::from_secs(5);
const DRAIN_TOTAL: Duration = Duration::from_secs(15);
/// The original scope's retirement observation gets its own window; no
/// launch deadline stretches across it.
const RETIREMENT_WINDOW: Duration = Duration::from_secs(20);
const RELAY_POLL: Duration = Duration::from_millis(100);
const ACTIVE_POLL: Duration = Duration::from_millis(10);
/// One bounded wait for the feeder's confirmed completion after the
/// shutdown flag: its input and master are nonblocking and every cycle
/// checks the flag, so anything silent past this bound is a lost or
/// panicked feeder and refuses the launch.
const FEEDER_FINAL: Duration = Duration::from_millis(500);

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// How the relay ended, before any retirement or audit is attempted.
#[derive(Debug)]
enum RelayEnd {
    /// The guardian's authenticated exit report arrived and the master was
    /// drained to its bounded end.
    Exited(TargetExit),
    /// The master ended first: the exit report may still be queued.
    MasterEnded,
    /// The control channel closed with no queued report: no exit report can
    /// ever arrive now.
    ControlClosed,
    /// A terminating signal reached the signal owner; the withdrawal is the
    /// clean socket close that follows this return.
    Cancelled(String),
}

/// The outer terminal's modes, exclusively owned by the relay's main
/// thread. The feeder never touches them. Without a tty (hosted controls,
/// pipes) nothing is ever changed and `foreground` never applies.
struct Outer {
    input: OwnedFd,
    saved: Option<Termios>,
    raw_held: bool,
}

impl Outer {
    fn capture() -> io::Result<Self> {
        let input = io::stdin().as_fd().try_clone_to_owned()?;
        let saved = if rustix::termios::isatty(&input) {
            Some(rustix::termios::tcgetattr(&input)?)
        } else {
            None
        };
        Ok(Self {
            input,
            saved,
            raw_held: false,
        })
    }
    fn is_tty(&self) -> bool {
        self.saved.is_some()
    }
    fn enter_raw(&mut self) -> io::Result<()> {
        let Some(saved) = &self.saved else {
            return Ok(());
        };
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&self.input, rustix::termios::OptionalActions::Now, &raw)?;
        self.raw_held = true;
        Ok(())
    }
    fn restore(&mut self) -> io::Result<()> {
        // Only an owner restores: after a suspension already ended raw mode,
        // the foreground may belong to an entirely different job, and a
        // background tcsetattr must not overwrite that job's modes.
        if !self.raw_held {
            return Ok(());
        }
        let Some(saved) = &self.saved else {
            return Ok(());
        };
        rustix::termios::tcsetattr(&self.input, rustix::termios::OptionalActions::Now, saved)?;
        self.raw_held = false;
        Ok(())
    }
    fn foreground(&self) -> io::Result<bool> {
        require(self.is_tty(), "the outer terminal is not a controlling tty")?;
        Ok(rustix::termios::tcgetpgrp(&self.input)? == rustix::process::getpgrp())
    }
}

/// The feeder's single confirmed completion, preserved by whichever
/// observer consumes it first: `drive` may see it while the target still
/// runs (an early stdin end), and `relay` must not wait for a second word
/// that will never come.
#[derive(Debug)]
enum FeederOutcome {
    /// No final word observed yet; the relay's bounded final wait applies.
    Pending,
    /// The feeder's one and only word: a benign end or a failure.
    Ended(Option<io::Error>),
}

/// The feeder plumbing owned by the relay and observed by `drive`: the
/// status channel plus the single completion word `drive` may consume
/// while the target still runs, so the relay never waits twice for one
/// word.
struct FeederScope {
    status: mpsc::Receiver<Option<io::Error>>,
    outcome: FeederOutcome,
}

impl FeederScope {
    /// The feeder's confirmed completion, however it was observed: the
    /// word `drive` already consumed stands as written, an unobserved end
    /// gets the one bounded wait, and any silence - a timeout, or a drop
    /// without the word - refuses the launch rather than guessing about
    /// the relay's own stdin plumbing.
    fn confirmed(self) -> io::Result<Option<io::Error>> {
        match self.outcome {
            FeederOutcome::Ended(word) => Ok(word),
            FeederOutcome::Pending => match self.status.recv_timeout(FEEDER_FINAL) {
                Ok(word) => Ok(word),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => Err(
                    io::Error::other("the stdin feeder did not confirm its shutdown"),
                ),
            },
        }
    }
}

/// The launch client's exclusive init sequence, shared verbatim with its
/// fresh-process regression: the signal owner admits only a fresh process
/// in its default signal state, and the terminal stop signals then join the
/// owner's own blocked mask so every later thread inherits it. Blocking
/// before the admission instead makes every launch refuse: the owner
/// demands its default unblocked witness.
fn claim_signal_ownership() -> io::Result<Signals> {
    Signals::claim_with_terminal_stops()
        .map_err(|error| io::Error::other(format!("signal owner unavailable: {error}")))
}

/// The stdin feeder: the relay's only stdin reader. It forwards bytes
/// unchanged - raw-mode literal suspends and nested jobs' own `^Z` pass
/// through as data - and follows the outer window size. It never owns
/// terminal modes and never touches the control channel. Its stdin is
/// nonblocking and the backhauled master already is, and every cycle
/// checks the shutdown flag, so the feeder always completes within one
/// bounded cycle of the flag and confirms it: exactly one final word
/// reaches the relay on every exit path - a benign end confirms, a
/// failure refuses. The blocking flags it changed on the shared input
/// description are restored before that final word is sent.
fn spawn_feeder(
    input: OwnedFd,
    master_feed: OwnedFd,
    shutdown: std::sync::Arc<AtomicBool>,
    status: mpsc::Sender<Option<io::Error>>,
) -> io::Result<()> {
    let saved_flags = rustix::fs::fcntl_getfl(&input)?;
    if !saved_flags.contains(rustix::fs::OFlags::NONBLOCK) {
        rustix::fs::fcntl_setfl(&input, saved_flags | rustix::fs::OFlags::NONBLOCK)?;
    }
    let tty = rustix::termios::isatty(&input);
    std::thread::spawn(move || {
        let outcome = (|| -> io::Result<()> {
            let mut last_size = None;
            let mut buffer = [0_u8; 4096];
            'feed: loop {
                if shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                // Poll with a short timeout: window-size changes must reach
                // the master even while the target reads nothing, and no read
                // may block this thread past the shutdown flag.
                let mut ready = [rustix::event::PollFd::new(
                    &input,
                    rustix::event::PollFlags::IN,
                )];
                match rustix::event::poll(
                    &mut ready,
                    Some(&rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 100_000_000,
                    }),
                ) {
                    Err(rustix::io::Errno::INTR) => continue,
                    value => value?,
                };
                // The flag can drop between the last check and the poll
                // return; never reach for the terminal after the shutdown.
                if shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                if tty
                    && let Ok(size) = rustix::termios::tcgetwinsize(&input)
                    && last_size != Some(size)
                {
                    last_size = Some(size);
                    // The master is gone: a clean feeder end, not a failure.
                    if rustix::termios::tcsetwinsize(&master_feed, size).is_err() {
                        return Ok(());
                    }
                }
                if !ready[0]
                    .revents()
                    .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)
                {
                    continue;
                }
                let count = match rustix::io::read(&input, &mut buffer) {
                    Ok(count) => count,
                    // The nonblocking stdin can lose a race with the poll it
                    // was announced by: retry the next cycle.
                    Err(rustix::io::Errno::AGAIN) => continue,
                    // SIGTTIN is blocked for this client, so a background read
                    // reports EIO: while this process is not the foreground
                    // job its reads wait, and only the master's real end ends
                    // the feeder.
                    Err(rustix::io::Errno::IO) => {
                        if tty
                            && rustix::termios::tcgetpgrp(&input)
                                .is_ok_and(|pgrp| pgrp != rustix::process::getpgrp())
                        {
                            std::thread::sleep(ACTIVE_POLL);
                            continue 'feed;
                        }
                        return Ok(());
                    }
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(error) => return Err(error.into()),
                };
                if count == 0 {
                    // Outer input ended: the target keeps running; the
                    // relay's main thread owns every other end.
                    return Ok(());
                }
                // The backhauled master is nonblocking: a short write or EAGAIN
                // under backpressure keeps its unsent suffix in flight until
                // every byte the outer terminal offered has been delivered.
                let mut written = 0;
                loop {
                    if shutdown.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    match rustix::io::write(&master_feed, &buffer[written..count]) {
                        Ok(0) => return Ok(()),
                        Ok(bytes) => {
                            written += bytes;
                            if written == count {
                                continue 'feed;
                            }
                        }
                        Err(rustix::io::Errno::IO) => return Ok(()),
                        Err(rustix::io::Errno::INTR) => {}
                        Err(rustix::io::Errno::AGAIN) => {
                            let mut writable = [rustix::event::PollFd::new(
                                &master_feed,
                                rustix::event::PollFlags::OUT,
                            )];
                            match rustix::event::poll(
                                &mut writable,
                                Some(&rustix::event::Timespec {
                                    tv_sec: 0,
                                    tv_nsec: 100_000_000,
                                }),
                            ) {
                                Err(rustix::io::Errno::INTR) => {}
                                Ok(_) => {}
                                Err(error) => return Err(error.into()),
                            };
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        })();
        // The shared input description returns to its caller-owned blocking
        // state before the relay may proceed on this word.
        let mut final_word = outcome.err();
        if let Err(error) = rustix::fs::fcntl_setfl(&input, saved_flags) {
            let error = io::Error::other(error.to_string());
            final_word = final_word.or(Some(error));
        }
        // Exactly one final word reaches the relay, on every return path.
        let _ = status.send(final_word);
    });
    Ok(())
}

/// Relay terminal bytes between the backhauled master and this process's
/// outer terminal. The main thread owns the outer modes, the signal owner
/// and the control channel; the direct target's stops arrive as
/// authenticated notices and the client suspends itself through its signal
/// owner, so the outer shell's job control (or the driving control) is what
/// resumes it: resume grants exist only for the one reported sequence.
fn relay(
    master: &OwnedFd,
    channel: &OwnedFd,
    nonce: &[u8; 16],
    child: u32,
    signals: &Signals,
) -> io::Result<RelayEnd> {
    let mut outer = Outer::capture()?;
    let raw_entry = if outer.is_tty() {
        // Foreground admission: a client started in the background never
        // siezes another job's terminal modes. Raw entry is the only mode
        // change; every later path restores the saved modes below while
        // this owner still holds raw mode.
        (|| -> io::Result<()> {
            require(
                outer.foreground()?,
                "the launch client did not start in the foreground",
            )?;
            outer.enter_raw()
        })()
    } else {
        Ok(())
    };
    if let Err(error) = raw_entry {
        let _ = outer.restore();
        return Err(error);
    }
    // The shutdown flag exists before the feeder: nothing below can strand
    // a detached stdin reader, and no feeder failure path is left unseen.
    let shutdown = std::sync::Arc::new(AtomicBool::new(false));
    let (status_tx, status_rx) = mpsc::channel::<Option<io::Error>>();
    let mut feeder = FeederScope {
        status: status_rx,
        outcome: FeederOutcome::Pending,
    };
    let end = (|| -> io::Result<RelayEnd> {
        // The relay keeps its own sender copy: a drop without the one final
        // word stays visible as silence-to-disconnect, never unnoticed.
        let relay_sender = status_tx.clone();
        let input = io::stdin().as_fd().try_clone_to_owned()?;
        let master_feed = master.as_fd().try_clone_to_owned()?;
        spawn_feeder(
            input,
            master_feed,
            std::sync::Arc::clone(&shutdown),
            status_tx,
        )?;
        let end = drive(
            master,
            channel,
            nonce,
            child,
            signals,
            &mut feeder,
            &mut outer,
        );
        drop(relay_sender);
        end
    })();
    // The exclusive owner stops the feeder and restores the modes on every
    // exit path before the outcome is reported; the shutdown flag lives
    // here so even a failed feeder spawn or a lost clone leaves nothing
    // reading stdin, and the relay's own sender copy is convoyed past the
    // drive end - so a silent final wait means a feeder defect, not a
    // channel close, and refuses.
    shutdown.store(true, Ordering::Release);
    // The feeder's final word cannot be discarded: with nonblocking stdin
    // and a nonblocking master, completion is confirmed, not assumed - one
    // bounded wait covers its last cycle, the flag check inside every cycle
    // bounds the rest, and a word `drive` already consumed while the target
    // still ran stands as the confirmation it is.
    let feeder_word = feeder.confirmed();
    let restored = outer.restore();
    let end = end.and_then(|end| restored.map(|()| end))?;
    // A feeder failure refuses even an authenticated target end: the relay's
    // stdin plumbing cannot be trusted to have delivered the session the
    // user offered. The silent-refusal mapping lives in
    // FeederScope::confirmed.
    feeder_word.and_then(|word| match word {
        None => Ok(end),
        Some(error) => Err(error),
    })
}

fn drive(
    master: &OwnedFd,
    channel: &OwnedFd,
    nonce: &[u8; 16],
    child: u32,
    signals: &Signals,
    feeder: &mut FeederScope,
    outer: &mut Outer,
) -> io::Result<RelayEnd> {
    let mut output = io::stdout();
    let mut buffer = [0_u8; 4096];
    let mut exit: Option<TargetExit> = None;
    let mut drain_started: Option<Instant> = None;
    let mut last_output = Instant::now();
    let mut next_sequence: u64 = 1;
    loop {
        // A feeder failure is never discarded: stdin is the relay's own
        // responsibility, and its loss is an honest end. The one word is
        // preserved for the relay's final wait, whatever `drive` returns.
        match feeder.status.try_recv() {
            Ok(None) => feeder.outcome = FeederOutcome::Ended(None),
            Ok(Some(error)) => {
                // Preserve an equivalent word for the relay's final wait;
                // the original refuses this drive here and now.
                feeder.outcome = FeederOutcome::Ended(Some(io::Error::other(error.to_string())));
                return Err(error);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            // The relay holds its own sender copy, so silence here means
            // the feeder dropped without its one final word: refuse.
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::other(
                    "the stdin feeder dropped without a final word",
                ));
            }
        }
        // The drain is bounded both ways from live evidence: five seconds
        // without master bytes and fifteen seconds total after the
        // authenticated exit report.
        let remaining = if exit.is_none() {
            RELAY_POLL
        } else {
            let started = match drain_started {
                Some(started) => started,
                None => {
                    return Err(io::Error::other(
                        "the authenticated exit report lost its drain window",
                    ));
                }
            };
            DRAIN_IDLE
                .checked_sub(last_output.elapsed())
                .unwrap_or_default()
                .min(
                    DRAIN_TOTAL
                        .checked_sub(started.elapsed())
                        .unwrap_or_default(),
                )
        };
        if remaining.is_zero() {
            break;
        }
        let timeout = rustix::event::Timespec::try_from(remaining)
            .map_err(|_| io::Error::other("relay poll window out of range"))?;
        // After the exit report the control channel is no longer polled:
        // the guardian's close would otherwise end the drain early and
        // discard the terminal's trailing bytes.
        let mut ready = vec![
            rustix::event::PollFd::new(master, rustix::event::PollFlags::IN),
            rustix::event::PollFd::new(signals, rustix::event::PollFlags::IN),
        ];
        if exit.is_none() {
            ready.push(rustix::event::PollFd::new(
                channel,
                rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP,
            ));
        }
        match rustix::event::poll(&mut ready, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        if ready[1].revents().contains(rustix::event::PollFlags::IN) {
            let notices = signals.drain()?;
            if let Some(signal) = notices.terminate {
                return Ok(RelayEnd::Cancelled(format!("{signal:?}")));
            }
            require(
                !notices.stop,
                "out-of-band suspension of the launch client is refused",
            )?;
        }
        if exit.is_none()
            && ready.get(2).is_some_and(|entry| {
                entry
                    .revents()
                    .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)
            })
        {
            match launch_protocol::peek_queued_control(channel)? {
                launch_protocol::QueuedControl::StopNotice if exit.is_none() => {
                    let (signal, sequence) = launch_protocol::receive_stop_notice(
                        channel,
                        nonce,
                        child,
                        Instant::now() + ACTIVE_WINDOW,
                    )?;
                    require(
                        sequence == next_sequence,
                        "the job-stop sequence is not monotonic",
                    )?;
                    next_sequence += 1;
                    eprintln!(
                        "launch: target stopped by signal {signal}, sequence {sequence}; suspending the client"
                    );
                    // Only a controlling outer terminal can hand the modes
                    // back and suspend this client through its signal owner.
                    require(
                        outer.is_tty(),
                        "a job stop without a controlling outer terminal is refused",
                    )?;
                    outer.restore()?;
                    let resumed = signals.suspend()?;
                    if let Some(signal) = resumed.terminate {
                        return Ok(RelayEnd::Cancelled(format!("{signal:?}")));
                    }
                    // The resumer returned the terminal to the foreground
                    // (the outer shell's `fg`, or the driving control):
                    // the halt is bounded so a partial resume cannot wedge
                    // the client.
                    let until = Instant::now() + ACTIVE_WINDOW;
                    loop {
                        if outer.foreground()? {
                            break;
                        }
                        require(
                            Instant::now() < until,
                            "the outer terminal did not return the launch client to the foreground",
                        )?;
                        if let Some(notices) = pending_termination(signals)? {
                            return Ok(RelayEnd::Cancelled(notices));
                        }
                        std::thread::sleep(ACTIVE_POLL);
                    }
                    outer.enter_raw()?;
                    eprintln!("launch: foreground returned; resuming the target");
                    match transport::send_until(
                        channel,
                        &launch_protocol::resume_grant_packet(nonce, sequence),
                        &[],
                        Instant::now() + ACTIVE_WINDOW,
                    ) {
                        Ok(()) => {}
                        // The guardian is gone: a target that died while
                        // stopped has its honest exit report queued or
                        // already sent on this channel. Receive it rather
                        // than declaring it missing; only a channel that
                        // carries no authenticated report refuses.
                        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                            let reported = launch_protocol::receive_exit_report(
                                channel,
                                nonce,
                                Instant::now() + ACTIVE_WINDOW,
                            )
                            .map_err(|report_error| {
                                io::Error::other(format!(
                                    "the launch control channel closed before the grant \
                                     and carries no authenticated exit report: {report_error}"
                                ))
                            })?;
                            eprintln!("launch: authenticated target exit {reported:?}");
                            exit = Some(reported);
                            drain_started = Some(Instant::now());
                            last_output = Instant::now();
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                    continue;
                }
                launch_protocol::QueuedControl::StopNotice => {
                    return Err(io::Error::other(
                        "a job-stop notice arrived after the target's exit report",
                    ));
                }
                launch_protocol::QueuedControl::ExitReport if exit.is_none() => {
                    let reported = launch_protocol::receive_exit_report(
                        channel,
                        nonce,
                        Instant::now() + ACTIVE_WINDOW,
                    )?;
                    eprintln!("launch: authenticated target exit {reported:?}");
                    exit = Some(reported);
                    drain_started = Some(Instant::now());
                    last_output = Instant::now();
                    continue;
                }
                launch_protocol::QueuedControl::ExitReport => {
                    return Err(io::Error::other(
                        "a second exit report arrived for one target",
                    ));
                }
                launch_protocol::QueuedControl::Closed => {
                    return Ok(match exit {
                        Some(exit) => RelayEnd::Exited(exit),
                        None => RelayEnd::ControlClosed,
                    });
                }
                launch_protocol::QueuedControl::Foreign => {
                    return Err(io::Error::other(
                        "the launch control channel carried an invalid record",
                    ));
                }
            }
        }
        if ready[0].revents().contains(rustix::event::PollFlags::IN) {
            match rustix::io::read(master, &mut buffer) {
                // The last slave closed with the target: the master reports
                // EIO rather than EOF, and that is the relay's master end.
                Err(rustix::io::Errno::IO) => break,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
                Ok(0) => break,
                Ok(count) => {
                    output.write_all(&buffer[..count])?;
                    output.flush()?;
                    last_output = Instant::now();
                }
            }
        }
    }
    Ok(match exit {
        Some(exit) => RelayEnd::Exited(exit),
        None => RelayEnd::MasterEnded,
    })
}

/// Drain any pending terminating signal without blocking, for the bounded
/// foreground wait.
fn pending_termination(signals: &Signals) -> io::Result<Option<String>> {
    let mut ready = [rustix::event::PollFd::new(
        signals,
        rustix::event::PollFlags::IN,
    )];
    match rustix::event::poll(
        &mut ready,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    ) {
        Err(rustix::io::Errno::INTR) => return Ok(None),
        value => value?,
    };
    if !ready[0].revents().contains(rustix::event::PollFlags::IN) {
        return Ok(None);
    }
    Ok(signals
        .drain()?
        .terminate
        .map(|signal| format!("{signal:?}")))
}

fn nonce() -> io::Result<[u8; 16]> {
    let mut nonce = [0_u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    require(nonce.iter().any(|byte| *byte != 0), "degenerate run nonce")?;
    Ok(nonce)
}

struct Endpoint {
    manager: agentswapper_linux_manager::Manager,
    owner: String,
    socket: rustix::fd::OwnedFd,
    generation: String,
}

async fn connect_endpoint(selection: &SelectedInstallation) -> io::Result<Endpoint> {
    let generation = selection.artifacts().manifest().generation().to_owned();
    let (manager, owner, _) = agentswapper_linux_manager::connect().await?;
    let socket = {
        let policy = SocketPolicy::installed(selection)?;
        let observed = LoadedSocket::observe(&manager, owner.as_str(), policy).await?;
        observed.connect_endpoint(&manager).await?
    };
    // The guardian's offer carries kernel message credentials; they are
    // delivered only when this end enables SO_PASSCRED first. The packet
    // receive path also requires the nonblocking socket that the connect
    // produced.
    rustix::net::sockopt::set_socket_passcred(&socket, true)?;
    Ok(Endpoint {
        manager,
        owner: owner.as_str().to_owned(),
        socket,
        generation,
    })
}

/// Bind the original service and hand back the retained binding together
/// with its one-use key: the key moves into the durable journal association,
/// and the retained binding observes the original scope's retirement before
/// any retirement commit is authorized.
async fn bind_original(
    manager: &agentswapper_linux_manager::Manager,
    owner: &str,
    offer: &Offer,
    selection: SelectedInstallation,
) -> io::Result<(
    agentswapper_linux_manager::BoundService,
    agentswapper_linux_manager::ServiceKey,
)> {
    let policy = ServicePolicy::installed(selection)?;
    let mut bound = BoundService::bind(
        manager,
        owner,
        policy,
        ServiceClaim {
            unit: &offer.unit,
            invocation: &offer.invocation,
            main_pid: offer.pid,
        },
    )
    .await?;
    let key = bound.claim_key()?;
    Ok((bound, key))
}

/// Bind-only activation: authenticate the endpoint, send the bind request,
/// validate the guardian's offer against the kernel sender, and disconnect
/// cleanly. The guardian then sees the clean disconnect and its instance
/// retires.
pub fn run(user: u32) -> io::Result<String> {
    let group = rustix::process::getgid().as_raw();
    let selection = SelectedInstallation::open()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    runtime.block_on(async {
        let endpoint = connect_endpoint(&selection).await?;
        require(
            net_send(&endpoint.socket, BIND_REQUEST)? == BIND_REQUEST.len(),
            "incomplete activation request",
        )?;
        let (bytes, sender) =
            activation_packet::receive(&endpoint.socket, Instant::now() + Duration::from_secs(4))?;
        let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        offer.client_validate(user, group, std::process::id(), sender)?;
        let closed = endpoint.manager.close().await.map_err(io::Error::other);
        drop(endpoint.socket);
        closed?;
        Ok(format!("activation offer validated {}", offer.unit))
    })
}

fn net_send(socket: &OwnedFd, bytes: &[u8]) -> io::Result<usize> {
    Ok(rustix::net::send(
        socket,
        bytes,
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
    )?)
}

/// The durable-intent-gated launch flow. The target program and its
/// environment travel only inside the zeroizing envelope over the
/// authenticated channel; the target environment applies at its final exec.
pub fn launch(
    user: u32,
    program: &std::ffi::OsStr,
    args: Vec<std::ffi::OsString>,
    journal: &dyn Journal,
) -> io::Result<String> {
    let group = rustix::process::getgid().as_raw();
    let selection = SelectedInstallation::open()?;
    // The signal owner admits only a fresh process in its default signal
    // state, so it comes first. Blocking the terminal stop signals afterwards
    // extends the owner's own blocked mask with the in-band terminal stop
    // signals - SIGTSTP is already part of it - so every later thread, the
    // feeder above all, inherits the full stop-proof mask: background stdin
    // reads and terminal-mode operations report EIO instead of stopping a
    // thread outside its signal owner. The owner restores exactly this mask
    // at its finish.
    let signals = claim_signal_ownership()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    let launched = runtime.block_on(async {
        let deadline = Instant::now() + LAUNCH_ADMISSION;
        let endpoint = connect_endpoint(&selection)
            .await
            .map_err(|error| io::Error::other(format!("endpoint connect failed: {error}")))?;
        require(
            net_send(&endpoint.socket, RUN_REQUEST)? == RUN_REQUEST.len(),
            "incomplete activation request",
        )?;
        let (bytes, sender) = activation_packet::receive(&endpoint.socket, deadline)
            .map_err(|error| io::Error::other(format!("activation offer missing: {error}")))?;
        let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        offer.client_validate(user, group, std::process::id(), sender)?;
        let expected_shape = connection_unit(user, &endpoint.generation, 1, std::process::id());
        let (expected_stem, _) = expected_shape
            .split_once('@')
            .ok_or_else(|| io::Error::other("invalid connection unit shape"))?;
        if !offer.unit.starts_with(&format!("{expected_stem}@")) {
            return Err(io::Error::other(
                "activation offer names another installation",
            ));
        }
        let (mut bound, service_key) =
            bind_original(&endpoint.manager, &endpoint.owner, &offer, selection)
                .await
                .map_err(|error| io::Error::other(format!("service binding failed: {error}")))?;
        // The launch-control frames need the receive timeout, which only
        // applies to a blocking channel, and they refuse any credential
        // control data; the offer above needed the nonblocking
        // credential-enabled socket the connect produced.
        let blocking = rustix::fs::fcntl_getfl(&endpoint.socket)? - rustix::fs::OFlags::NONBLOCK;
        rustix::fs::fcntl_setfl(&endpoint.socket, blocking)?;
        rustix::net::sockopt::set_socket_passcred(&endpoint.socket, false)?;
        // The launch envelope travels only over this authenticated channel.
        let envelope = LaunchEnvelope::capture(
            program,
            std::path::Path::new("/"),
            args,
            Vec::<(std::ffi::OsString, std::ffi::OsString)>::new(),
            Vec::<(std::ffi::OsString, Option<std::ffi::OsString>)>::new(),
        )?;
        envelope
            .send_to_until(&endpoint.socket, deadline)
            .map_err(|error| io::Error::other(format!("envelope transfer failed: {error}")))?;
        let run_nonce = nonce()?;
        let nonce_hex = launch_protocol::encoded(&run_nonce);
        // The durable run intent is the only launch-gate authority; it
        // consumes the one-use key into the durable scope association.
        journal
            .confirm_intent(&offer.invocation, &nonce_hex, service_key)
            .map_err(|error| io::Error::other(format!("run intent failed: {error}")))?;
        net_send(
            &endpoint.socket,
            &launch_protocol::launch_gate_packet(&run_nonce),
        )?;
        let (event_nonce, child) =
            launch_protocol::receive_exec_event_open(&endpoint.socket, deadline)
                .map_err(|error| io::Error::other(format!("exec event missing: {error}")))?;
        require(
            event_nonce == run_nonce,
            "the exec event carried a foreign nonce",
        )?;
        require(child > 1, "the exec event carried a degenerate child")?;
        // The durable spawn observation precedes the held-exec release.
        journal
            .observe_spawn(&offer.invocation, child)
            .map_err(|error| io::Error::other(format!("spawn observation failed: {error}")))?;
        net_send(
            &endpoint.socket,
            &launch_protocol::exec_release_packet(&run_nonce, child),
        )?;
        // The terminal master backhaul: the client owns the master for the
        // target's lifetime and relays its bytes until the target ends.
        let master = transport::receive_until(&endpoint.socket, deadline)
            .map_err(|error| io::Error::other(format!("terminal master missing: {error}")))?;
        // The relay is the active phase: no admission deadline applies. It
        // owns the terminal admission, the feeder, the outer modes and the
        // control channel from here to the target's honest end.
        let end = relay(&master, &endpoint.socket, &run_nonce, child, &signals)
            .map_err(|error| io::Error::other(format!("terminal relay failed: {error}")))?;
        let exit = match end {
            RelayEnd::Exited(exit) => exit,
            RelayEnd::MasterEnded => launch_protocol::receive_exit_report(
                &endpoint.socket,
                &run_nonce,
                Instant::now() + ACTIVE_WINDOW,
            )
            .map_err(|error| io::Error::other(format!("exit report missing: {error}")))?,
            RelayEnd::ControlClosed => {
                return Err(io::Error::other(
                    "exit report missing: the launch control channel closed",
                ));
            }
            RelayEnd::Cancelled(signal) => {
                return Err(io::Error::other(format!("launch cancelled by {signal}")));
            }
        };
        // The channel closes cleanly only here: from the guardian's side a
        // withdrawal mid-session never grants a resume, so dropping it on
        // the error paths above retires the target through the scope.
        drop(endpoint.socket);
        // Independently observe the original scope's retirement on the
        // retained binding and original handles, in its own fresh window; a
        // received exit report alone never authorizes the retirement commit.
        let retired = bound
            .observe_retirement(
                &endpoint.manager,
                tokio::time::Instant::from_std(Instant::now() + RETIREMENT_WINDOW),
            )
            .await
            .map_err(|error| io::Error::other(format!("retirement observation failed: {error}")))?;
        // The audit commits the retirement with the one-use value and
        // records the authenticated target exit; retry-safe in the adapter.
        journal
            .audit_exit(&offer.invocation, exit, retired)
            .map_err(|error| io::Error::other(format!("exit audit failed: {error}")))?;
        let closed = endpoint.manager.close().await.map_err(io::Error::other);
        closed?;
        Ok(format!(
            "target exited: {exit:?} (run {} in {})",
            nonce_hex, offer.invocation
        ))
    });
    // The terminal is restored and the custody handed back before the
    // signal owner finishes: a queued fatal signal still takes precedence
    // over the reported outcome.
    signals.finish_after_cleanup(None)?;
    launched
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::OwnedFd, sync::Arc};

    fn feeder_pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        Ok((read, write))
    }

    /// The regression for a real relay hazard: standard input can end while
    /// the target still runs (piped input). The feeder must confirm its
    /// benign end through the one and only final word, and the input
    /// description must carry exactly the flags its caller owned.
    #[test]
    fn a_stdin_eof_confirms_feeder_completion_and_restores_the_input_flags() -> io::Result<()> {
        let (input_read, input_write) = feeder_pair()?;
        let input_witness = input_read.as_fd().try_clone_to_owned()?;
        let (feed_read, _feed_hold) = feeder_pair()?;
        let before = rustix::fs::fcntl_getfl(&input_witness)?;
        let (status_tx, status_rx) = mpsc::channel::<Option<io::Error>>();
        let shutdown = Arc::new(AtomicBool::new(false));
        spawn_feeder(input_read, feed_read, Arc::clone(&shutdown), status_tx)?;
        // Standard input ends; the target (the holding feed pipe) stays up.
        drop(input_write);
        let word = status_rx
            .recv_timeout(FEEDER_FINAL + ACTIVE_POLL * 5)
            .map_err(|_| io::Error::other("the feeder never confirmed its stdin end"))?;
        assert!(word.is_none());
        assert_eq!(rustix::fs::fcntl_getfl(&input_witness)?, before);
        Ok(())
    }

    /// The shutdown flag ends the feeder within one bounded cycle; no read,
    /// write or mode of the terminal survives it.
    #[test]
    fn a_flagged_feeder_confirms_its_shutdown_within_one_cycle() -> io::Result<()> {
        let (input_read, _input_hold) = feeder_pair()?;
        let (feed_read, _feed_hold) = feeder_pair()?;
        let (status_tx, status_rx) = mpsc::channel::<Option<io::Error>>();
        let shutdown = Arc::new(AtomicBool::new(true));
        spawn_feeder(input_read, feed_read, Arc::clone(&shutdown), status_tx)?;
        let word = status_rx
            .recv_timeout(FEEDER_FINAL)
            .map_err(|_| io::Error::other("the feeder never confirmed the shutdown"))?;
        assert!(word.is_none());
        Ok(())
    }

    /// `drive` may consume the feeder's single confirmation long before the
    /// relay finishes; a delayed successful end must not time out waiting
    /// for a second word that will never come.
    #[test]
    fn an_early_stdin_end_still_counts_as_confirmed_completion_at_the_final_wait() -> io::Result<()>
    {
        let (status_tx, status_rx) = mpsc::channel::<Option<io::Error>>();
        // The word drive would have consumed and preserved in
        // FeederOutcome::Ended: a benign stdin end with the target alive. The
        // production confirmation must accept it without waiting for a
        // second word that the feeder, having spoken once, will never send.
        status_tx
            .send(None)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let feeder = match status_rx.try_recv() {
            Ok(word) => FeederScope {
                status: status_rx,
                outcome: FeederOutcome::Ended(word),
            },
            Err(error) => return Err(io::Error::other(error.to_string())),
        };
        assert!(matches!(feeder.confirmed(), Ok(None)));
        // A feeder still pending whose sender drops without its one word
        // refuses: silence is never accepted as completion.
        let (quiet_tx, quiet_rx) = mpsc::channel::<Option<io::Error>>();
        drop(quiet_tx);
        let quiet = FeederScope {
            status: quiet_rx,
            outcome: FeederOutcome::Pending,
        };
        assert!(quiet.confirmed().is_err());
        Ok(())
    }

    /// Mode restoration is ownership-gated: a chiefly path that failed
    /// without this owner ever entering raw mode - a foreground wait giving
    /// up while another job holds the terminal - must not reach for the
    /// terminal and overwrite that job's modes.
    #[test]
    fn a_non_owner_never_restores_the_outer_modes() -> io::Result<()> {
        let mut outer = Outer::capture()?;
        // A chiefly path that failed without this owner ever entering raw
        // mode must not reach for the terminal at all.
        outer.raw_held = false;
        outer.restore()?;
        // Only a raw owner restores; the flag falls with the restoration, and
        // a second restore stays a no-op. With a pipe-only stdin this also
        // pins the degenerate case: nothing to restore, nothing to overwrite.
        outer.enter_raw()?;
        assert!(outer.raw_held == outer.saved.is_some());
        outer.restore()?;
        assert!(!outer.raw_held);
        outer.restore()?;
        Ok(())
    }
}
