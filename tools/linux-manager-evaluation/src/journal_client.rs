//! Opted-in, synchronous CI client. Observations never authorize journal completion.
//! No method may run inside a Tokio runtime; Drop never drives asynchronous work.
pub use crate::journal_protocol::TargetExit;
use crate::{
    Connection, Expected, UnitFact, UnitKind, activation, activation_packet,
    admission_transport as transport, fixture_policy, journal_protocol, kernel, require,
};
use serde::Deserialize;
use std::{
    io,
    marker::PhantomData,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

struct Control(Option<OwnedFd>);
impl Drop for Control {
    fn drop(&mut self) {
        if let Some(socket) = self.0.take() {
            // Shut down the shared socket description so an in-flight fork
            // cannot postpone disconnect merely by retaining a CLOEXEC copy.
            let _ = rustix::net::shutdown(&socket, rustix::net::Shutdown::Both);
        }
    }
}

struct RuntimeGuard(Option<tokio::runtime::Runtime>);
impl RuntimeGuard {
    fn new() -> io::Result<Self> {
        Ok(Self(Some(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
        )))
    }
    fn get(&self) -> io::Result<&tokio::runtime::Runtime> {
        self.0
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture runtime is closed"))
    }
}
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

struct Session {
    control: Control,
    terminal_requested: bool,
    terminal: Option<OwnedFd>,
    job: Option<JobState>,
    connection: Option<Connection>,
    owner: zbus::names::OwnedUniqueName,
    unit: UnitFact,
    binding: kernel::Binding,
    child: Option<kernel::Child>,
    deadline: Instant,
    phase: Phase,
    runtime: RuntimeGuard,
    _same_thread: PhantomData<Rc<()>>,
}
#[derive(PartialEq, Eq)]
enum Phase {
    Admission,
    Active,
}
#[derive(Default)]
struct JobState {
    child: u32,
    nonce: [u8; 16],
    sequence: u64,
    stopped: bool,
    exec_pending: bool,
    exec_observed: bool,
    exit: Option<TargetExit>,
}
impl Drop for Session {
    fn drop(&mut self) {
        drop(std::mem::replace(&mut self.control, Control(None)));
        if let Some(runtime) = self.runtime.0.as_ref() {
            let _entered = runtime.enter();
            drop(self.connection.take());
        } else {
            drop(self.connection.take());
        }
    }
}

fn outside_runtime() -> io::Result<()> {
    require(
        tokio::runtime::Handle::try_current().is_err(),
        "fixture client cannot run inside an async runtime",
    )
}

impl Session {
    fn socket(&self) -> io::Result<&OwnedFd> {
        self.control
            .0
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture control channel is closed"))
    }
    fn runtime(&self) -> io::Result<&tokio::runtime::Runtime> {
        outside_runtime()?;
        self.runtime.get()
    }
    fn connection(&self) -> io::Result<&Connection> {
        self.connection
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture manager connection is closed"))
    }
    fn recheck(&self) -> io::Result<()> {
        // The absolute admission budget bounds startup only. A running or
        // suspended session keeps its original binding and gets a fresh,
        // bounded observation window; elapsed startup time cannot revoke it.
        let until = match self.phase {
            Phase::Admission => self.deadline,
            Phase::Active => Instant::now() + Duration::from_secs(8),
        };
        let remaining = until
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fixture admission expired"))?;
        self.runtime()?.block_on(async {
            tokio::time::timeout(remaining, async {
                let connection = self.connection()?;
                require(
                    crate::owner(connection).await? == self.owner,
                    "manager owner changed",
                )?;
                let path = crate::unit_path(&self.unit.unit);
                let invocation = Vec::<u8>::try_from(
                    crate::property(
                        connection,
                        self.owner.as_str(),
                        &path,
                        crate::UNIT_INTERFACE,
                        "InvocationID",
                    )
                    .await?,
                )
                .map_err(io::Error::other)?;
                let invocation: String = invocation.iter().map(|b| format!("{b:02x}")).collect();
                let pid = u32::try_from(
                    crate::property(
                        connection,
                        self.owner.as_str(),
                        &path,
                        crate::SERVICE_INTERFACE,
                        "MainPID",
                    )
                    .await?,
                )
                .map_err(io::Error::other)?;
                let active = String::try_from(
                    crate::property(
                        connection,
                        self.owner.as_str(),
                        &path,
                        crate::UNIT_INTERFACE,
                        "ActiveState",
                    )
                    .await?,
                )
                .map_err(io::Error::other)?;
                require(
                    invocation == self.unit.invocation
                        && pid == self.unit.pid
                        && active == "active",
                    "bound guardian invocation changed",
                )?;
                self.binding.observe()?;
                if let Some(child) = &self.child {
                    child.check()?;
                }
                require(
                    crate::owner(connection).await? == self.owner,
                    "manager owner changed after recheck",
                )
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture recheck expired"))?
        })
    }
    fn close(mut self) -> Closed {
        drop(std::mem::replace(&mut self.control, Control(None)));
        Closed(self)
    }
}

pub struct Bound(Session);
pub struct Prepared {
    session: Session,
    pid: u32,
}
pub struct Running(Session);
/// Exact kernel exec event held by the original guardian, before detach.
/// This is not application readiness or a production custody receipt.
pub struct ExecStopped(Session);
/// Fixed-fixture control observations. Closed is transport loss, not a target
/// exit receipt, successful exec observation, or permission to reuse a profile.
#[derive(Debug, PartialEq, Eq)]
pub enum JobEvent {
    Pending,
    Stopped(i32),
    Closed,
    Exited(TargetExit),
}
#[derive(Debug, PartialEq, Eq)]
enum ControlReadiness {
    Pending,
    Packet,
    Closed,
}
fn control_readiness(socket: impl AsFd) -> io::Result<ControlReadiness> {
    let mut byte = [0_u8];
    let mut reset_consumed = false;
    loop {
        match rustix::net::recv(
            &socket,
            &mut byte,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        ) {
            // A peer closing with an unread request sets SO_ERROR before the
            // kernel exposes its queued final reply. Consume that error once,
            // then inspect the actual queue. Reset alone proves no outcome.
            Err(rustix::io::Errno::CONNRESET) if !reset_consumed => reset_consumed = true,
            Ok((0, _)) => {
                require(transport::eof(&socket)?, "empty job control record")?;
                return Ok(ControlReadiness::Closed);
            }
            Ok(_) => return Ok(ControlReadiness::Packet),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                return Ok(ControlReadiness::Pending);
            }
            Err(error) => return Err(error.into()),
        }
    }
}
#[must_use = "closed control retains witnesses; attempt explicit retirement"]
pub struct Closed(Session);
/// Independent read-only witness; it never owns a copy of the activation socket.
pub struct Witness(Session);

/// A failed transition retains the original witnesses for explicit retirement.
#[must_use = "transition failure retains witnesses for explicit retirement"]
pub struct TransitionFailure {
    pub error: io::Error,
    pub closed: Box<Closed>,
}
impl std::fmt::Debug for TransitionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitionFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Transport failure can mean GO was delivered; journal intent remains unresolved.
#[derive(Debug)]
pub enum StartCause<E> {
    Journal(E),
    Transport(io::Error),
}
#[must_use = "start failure retains witnesses; never infer that delivery was withheld"]
pub struct StartFailure<E> {
    pub cause: StartCause<E>,
    pub live_at_refusal: Option<io::Result<()>>,
    pub closed: Box<Closed>,
}
impl<E: std::fmt::Debug> std::fmt::Debug for StartFailure<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartFailure")
            .field("cause", &self.cause)
            .field("live_at_refusal", &self.live_at_refusal)
            .finish_non_exhaustive()
    }
}
#[must_use = "failed observation is unresolved and retains its original witnesses"]
pub struct RetireFailure {
    pub error: io::Error,
    pub closed: Box<Closed>,
}
impl std::fmt::Debug for RetireFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetireFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
/// Original identity plus successful independent retirement observations.
/// Neither this value nor its identity is a production custody receipt.
pub struct Retired {
    pub identity: Identity,
    pub connection_close_error: Option<io::Error>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub unit: String,
    pub invocation: String,
    pub guardian_pid: u32,
    pub directory_device: u64,
    pub directory_inode: u64,
}
fn identity(session: &Session) -> Identity {
    Identity {
        unit: session.unit.unit.clone(),
        invocation: session.unit.invocation.clone(),
        guardian_pid: session.unit.pid,
        directory_device: session.unit.kernel.device,
        directory_inode: session.unit.kernel.inode,
    }
}

fn validate_prepared(
    packet: &activation_packet::Packet,
    guardian: u32,
    uid: u32,
    gid: u32,
    invocation: &str,
) -> io::Result<u32> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Offer {
        kind: String,
        child: u32,
        invocation: String,
    }
    let offer: Offer = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
    require(
        packet.sender.pid() == guardian as i32
            && packet.sender.uid() == uid
            && packet.sender.gid() == gid
            && offer.invocation == invocation
            && offer.kind == "aswp-fixture-prepared-1"
            && offer.child > 1
            && offer.child != guardian,
        "prepared writer sender or framing differs",
    )?;
    Ok(offer.child)
}

struct StopContext<'a> {
    guardian: u32,
    uid: u32,
    gid: u32,
    invocation: &'a str,
    child: u32,
    nonce: &'a [u8; 16],
    sequence: u64,
}
fn validate_stopped(
    packet: &activation_packet::Packet,
    expected: &StopContext<'_>,
) -> io::Result<i32> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Stop {
        kind: String,
        child: u32,
        invocation: String,
        nonce: String,
        sequence: u64,
        signal: i32,
    }
    let stop: Stop = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
    require(
        packet.sender.pid() == expected.guardian as i32
            && packet.sender.uid() == expected.uid
            && packet.sender.gid() == expected.gid
            && stop.kind == "aswp-fixture-stopped-1"
            && stop.child == expected.child
            && stop.invocation == expected.invocation
            && stop.nonce == journal_protocol::encoded(expected.nonce)
            && stop.sequence == expected.sequence
            && (1..=8).contains(&stop.sequence)
            && matches!(stop.signal, 19..=22),
        "job stop sender, identity or sequence differs",
    )?;
    Ok(stop.signal)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Writer,
    Terminal,
    Job,
    Exec,
}

fn validate_exec(packet: &activation_packet::Packet, expected: &StopContext<'_>) -> io::Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Held {
        kind: String,
        child: u32,
        invocation: String,
        nonce: String,
    }
    let held: Held = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
    require(
        packet.sender.pid() == expected.guardian as i32
            && packet.sender.uid() == expected.uid
            && packet.sender.gid() == expected.gid
            && held.kind == "aswp-fixture-exec-held-1"
            && held.child == expected.child
            && held.invocation == expected.invocation
            && held.nonce == journal_protocol::encoded(expected.nonce),
        "exec notice sender or launch binding differs",
    )
}

fn validate_exit(
    packet: &activation_packet::Packet,
    expected: &StopContext<'_>,
) -> io::Result<TargetExit> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Exit {
        kind: String,
        child: u32,
        invocation: String,
        nonce: String,
        sequence: u64,
        status: TargetExit,
    }
    let exit: Exit = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
    require(
        packet.sender.pid() == expected.guardian as i32
            && packet.sender.uid() == expected.uid
            && packet.sender.gid() == expected.gid
            && exit.kind == "aswp-fixture-exit-1"
            && exit.child == expected.child
            && exit.invocation == expected.invocation
            && exit.nonce == journal_protocol::encoded(expected.nonce)
            && exit.sequence == expected.sequence
            && exit.sequence <= 8,
        "target exit sender, launch binding or stop sequence differs",
    )?;
    exit.status.validate()
}

impl Bound {
    pub fn connect(prefix: &str) -> io::Result<Self> {
        Self::connect_mode(prefix, Mode::Writer)
    }
    /// Fixed pre-exec/inner-PTY qualification, never a provider launch API.
    pub fn connect_terminal(prefix: &str) -> io::Result<Self> {
        Self::connect_mode(prefix, Mode::Terminal)
    }
    /// Fixed guardian-session qualification; never an arbitrary provider API.
    pub fn connect_job_control(prefix: &str) -> io::Result<Self> {
        Self::connect_mode(prefix, Mode::Job)
    }
    /// Fixed target held at kernel exec before durable spawn observation.
    pub fn connect_exec_control(prefix: &str) -> io::Result<Self> {
        Self::connect_mode(prefix, Mode::Exec)
    }
    fn connect_mode(prefix: &str, mode: Mode) -> io::Result<Self> {
        outside_runtime()?;
        fixture_policy::gate(prefix)?;
        let paths = crate::prerequisites()?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let (socket, _, offer) = activation::connect(
            prefix,
            match mode {
                Mode::Writer => b"ADMIT\n",
                Mode::Terminal => b"PTY1\n",
                Mode::Job => b"PTY2\n",
                Mode::Exec => b"PTY3\n",
            },
        )?;
        let control = Control(Some(socket));
        let expected = Expected {
            unit: offer.unit,
            user: offer.uid,
            pid: offer.pid,
            invocation: Some(offer.invocation),
            kind: UnitKind::Activated {
                fragment: format!("/run/systemd/system/{prefix}@.service"),
            },
        };
        let runtime = RuntimeGuard::new()?;
        let (connection, owner, report, binding) = runtime.get()?.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                crate::admit(paths, Some(expected)),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture binding expired"))?
        })?;
        let (unit, binding) = match (report.unit, binding) {
            (Some(unit), Some(binding)) => (unit, binding),
            _ => {
                runtime.get()?.block_on(async {
                    let _ = tokio::time::timeout(Duration::from_secs(2), connection.close()).await;
                });
                return Err(io::Error::other(
                    "fixture admission lacks unit or kernel binding",
                ));
            }
        };
        Ok(Self(Session {
            control,
            terminal_requested: mode != Mode::Writer,
            terminal: None,
            job: matches!(mode, Mode::Job | Mode::Exec).then(|| JobState {
                exec_pending: mode == Mode::Exec,
                ..JobState::default()
            }),
            connection: Some(connection),
            owner,
            unit,
            binding,
            child: None,
            deadline,
            phase: Phase::Admission,
            runtime,
            _same_thread: PhantomData,
        }))
    }
    pub fn identity(&self) -> Identity {
        identity(&self.0)
    }
    pub fn close(self) -> Closed {
        self.0.close()
    }
    pub fn prepare(mut self, lease: BorrowedFd<'_>) -> Result<Prepared, TransitionFailure> {
        let result = (|| {
            self.0.recheck()?;
            transport::send_until(self.0.socket()?, transport::GO, &[lease], self.0.deadline)?;
            let (packet, terminal) = if self.0.terminal_requested {
                let (packet, terminal) =
                    activation_packet::receive_terminal(self.0.socket()?, self.0.deadline)?;
                (packet, Some(terminal))
            } else {
                (
                    activation_packet::receive(self.0.socket()?, self.0.deadline)?,
                    None,
                )
            };
            let child_pid = validate_prepared(
                &packet,
                self.0.unit.pid,
                self.0.unit.user,
                rustix::process::getgid().as_raw(),
                &self.0.unit.invocation,
            )?;
            if let Some(terminal) = &terminal {
                crate::terminal::validate_master(terminal)?;
            }
            self.0.child = Some(self.0.binding.child(child_pid, self.0.unit.pid)?);
            if let Some(job) = &mut self.0.job {
                job.child = child_pid;
            }
            self.0.recheck()?;
            self.0.terminal = terminal;
            Ok(child_pid)
        })();
        match result {
            Ok(pid) => Ok(Prepared {
                session: self.0,
                pid,
            }),
            Err(error) => Err(TransitionFailure {
                error,
                closed: Box::new(self.0.close()),
            }),
        }
    }
}

impl Witness {
    /// Claims select an observation only. Manager and kernel facts must match
    /// before this instance can observe retirement of the original invocation.
    pub fn bind(prefix: &str, claimed: &Identity, child_pid: u32) -> io::Result<Self> {
        outside_runtime()?;
        fixture_policy::gate(prefix)?;
        require(
            std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref() == Ok("1"),
            "independent witness requires the activated journal fixture",
        )?;
        require(
            fixture_policy::valid_scope_unit(&claimed.unit)
                && claimed.unit.starts_with(&format!("{prefix}@"))
                && crate::valid_invocation(&claimed.invocation)
                && claimed.guardian_pid > 1,
            "invalid independent witness claims",
        )?;
        let paths = crate::prerequisites()?;
        let expected = Expected {
            unit: claimed.unit.clone(),
            user: rustix::process::getuid().as_raw(),
            pid: claimed.guardian_pid,
            invocation: Some(claimed.invocation.clone()),
            kind: UnitKind::Activated {
                fragment: format!("/run/systemd/system/{prefix}@.service"),
            },
        };
        let runtime = RuntimeGuard::new()?;
        let deadline = Instant::now() + Duration::from_secs(8);
        let (connection, owner, report, binding) = runtime.get()?.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                crate::admit(paths, Some(expected)),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "independent witness binding expired",
                )
            })?
        })?;
        let (unit, binding) = match (report.unit, binding) {
            (Some(unit), Some(binding)) => (unit, binding),
            _ => {
                runtime.get()?.block_on(async {
                    let _ = tokio::time::timeout(Duration::from_secs(2), connection.close()).await;
                });
                return Err(io::Error::other(
                    "independent admission lacks unit or kernel binding",
                ));
            }
        };
        let mut session = Session {
            control: Control(None),
            terminal_requested: false,
            job: None,
            terminal: None,
            connection: Some(connection),
            owner,
            unit,
            binding,
            child: None,
            deadline,
            phase: Phase::Admission,
            runtime,
            _same_thread: PhantomData,
        };
        session.child = Some(session.binding.child(child_pid, claimed.guardian_pid)?);
        require(
            identity(&session) == *claimed,
            "independent manager/kernel facts differ from claims",
        )?;
        session.recheck()?;
        Ok(Self(session))
    }
    pub fn retire(self) -> Result<Retired, RetireFailure> {
        self.0.close().retire()
    }
}

impl Prepared {
    pub(crate) fn admission_deadline(&self) -> Instant {
        self.session.deadline
    }
    pub fn terminal(&self) -> Option<BorrowedFd<'_>> {
        self.session.terminal.as_ref().map(AsFd::as_fd)
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn identity(&self) -> Identity {
        identity(&self.session)
    }
    pub fn close(self) -> Closed {
        self.session.close()
    }
    pub fn observe_ready(&self) -> io::Result<()> {
        self.session.recheck()
    }

    /// The callback runs synchronously, outside any entered async runtime.
    /// The callback must establish durable journal intent before GO (including
    /// confirming an earlier committed intent in exec-gated mode). A transport
    /// failure afterwards must be treated as GO possibly having been delivered.
    pub fn start_after<E>(
        self,
        nonce: [u8; 16],
        journal: impl FnOnce(u32) -> Result<(), E>,
    ) -> Result<Running, StartFailure<E>> {
        self.start_after_checked(nonce, journal, || Ok(()))
    }

    /// Check withdrawal again after manager observation, immediately before GO.
    /// The check must bound its active work. An explicit user suspension may
    /// outlast admission; send_until still checks the original deadline after
    /// the callback returns. A later signal/send race leaves delivery uncertain
    /// and cannot authorize a no-exec inference.
    pub fn start_after_checked<E>(
        mut self,
        nonce: [u8; 16],
        journal: impl FnOnce(u32) -> Result<(), E>,
        permit: impl FnOnce() -> io::Result<()>,
    ) -> Result<Running, StartFailure<E>> {
        if let Err(error) = self.session.recheck() {
            return Err(StartFailure {
                cause: StartCause::Transport(error),
                live_at_refusal: None,
                closed: Box::new(self.session.close()),
            });
        }
        if Instant::now() >= self.session.deadline {
            return Err(StartFailure {
                cause: StartCause::Transport(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "journal callback deadline expired",
                )),
                live_at_refusal: None,
                closed: Box::new(self.session.close()),
            });
        }
        if let Err(error) = journal(self.pid) {
            let live_at_refusal = Some(self.session.recheck());
            return Err(StartFailure {
                cause: StartCause::Journal(error),
                live_at_refusal,
                closed: Box::new(self.session.close()),
            });
        }
        let result = self.session.recheck().and_then(|()| {
            permit()?;
            // The client socket is nonblocking. A full queue fails immediately;
            // send_until bounds the attempt but does not wait for queue space.
            transport::send_until(
                self.session.socket()?,
                &journal_protocol::start_packet(&nonce),
                &[],
                self.session.deadline,
            )
        });
        match result {
            Ok(()) => {
                if let Some(job) = &mut self.session.job {
                    job.nonce = nonce;
                }
                if self
                    .session
                    .job
                    .as_ref()
                    .is_none_or(|job| !job.exec_pending)
                {
                    self.session.phase = Phase::Active;
                }
                Ok(Running(self.session))
            }
            Err(error) => Err(StartFailure {
                cause: StartCause::Transport(error),
                live_at_refusal: None,
                closed: Box::new(self.session.close()),
            }),
        }
    }
}
impl Running {
    pub fn hold_exec(mut self) -> Result<ExecStopped, TransitionFailure> {
        let result = (|| {
            self.0.recheck()?;
            let job = self
                .0
                .job
                .as_ref()
                .filter(|job| job.exec_pending && !job.stopped)
                .ok_or_else(|| io::Error::other("session is not awaiting exec"))?;
            let packet = activation_packet::receive(self.0.socket()?, self.0.deadline)?;
            validate_exec(
                &packet,
                &StopContext {
                    guardian: self.0.unit.pid,
                    uid: self.0.unit.user,
                    gid: rustix::process::getgid().as_raw(),
                    invocation: &self.0.unit.invocation,
                    child: job.child,
                    nonce: &job.nonce,
                    sequence: 0,
                },
            )?;
            self.0.recheck()
        })();
        match result {
            Ok(()) => {
                if let Some(job) = &mut self.0.job {
                    job.exec_observed = true;
                }
                Ok(ExecStopped(self.0))
            }
            Err(error) => Err(TransitionFailure {
                error,
                closed: Box::new(self.0.close()),
            }),
        }
    }
    /// Nonblocking control readiness for the terminal relay. Stop packets still
    /// pass the complete credential, invocation, sequence and live-child checks.
    pub fn poll_job(&mut self) -> io::Result<JobEvent> {
        require(
            self.0.job.as_ref().is_some_and(|job| !job.exec_pending),
            "session is not ready for job control",
        )?;
        match control_readiness(self.0.socket()?)? {
            ControlReadiness::Closed => Ok(JobEvent::Closed),
            ControlReadiness::Packet => self.receive_job_event(),
            ControlReadiness::Pending => Ok(JobEvent::Pending),
        }
    }
    /// Hosted hangup fault; the caller must also release any cloned master.
    /// The control connection remains open to distinguish terminal loss.
    pub fn close_terminal_for_fixture(&mut self) -> io::Result<()> {
        require(
            self.0.job.is_some()
                && std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref() == Ok("1"),
            "terminal hangup requires the hosted job-control fixture",
        )?;
        self.0.recheck()?;
        drop(self.0.terminal.take());
        Ok(())
    }
    /// Wait for one authenticated fixed-job stop. This is an observation, not
    /// user intent. Callers decide whether to resume or close the session.
    pub fn wait_stopped(&mut self) -> io::Result<i32> {
        self.0.recheck()?;
        let job = self
            .0
            .job
            .as_ref()
            .ok_or_else(|| io::Error::other("session has no job-control protocol"))?;
        require(
            !job.exec_pending && !job.stopped && job.exit.is_none(),
            "session is not ready for another job stop",
        )?;
        match self.receive_job_event()? {
            JobEvent::Stopped(signal) => Ok(signal),
            _ => Err(io::Error::other("target exited while awaiting a job stop")),
        }
    }

    pub fn observed_exit(&self) -> Option<TargetExit> {
        self.0.job.as_ref().and_then(|job| job.exit)
    }

    fn receive_job_event(&mut self) -> io::Result<JobEvent> {
        let job = self
            .0
            .job
            .as_ref()
            .filter(|job| !job.exec_pending && job.exit.is_none())
            .ok_or_else(|| io::Error::other("job event phase is closed"))?;
        let packet =
            activation_packet::receive(self.0.socket()?, Instant::now() + Duration::from_secs(4))?;
        #[derive(Deserialize)]
        struct Header {
            kind: String,
        }
        let header: Header = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
        if header.kind == "aswp-fixture-exit-1" {
            require(
                job.exec_observed,
                "target exit requires observed and released exec",
            )?;
            let status = validate_exit(
                &packet,
                &StopContext {
                    guardian: self.0.unit.pid,
                    uid: self.0.unit.user,
                    gid: rustix::process::getgid().as_raw(),
                    invocation: &self.0.unit.invocation,
                    child: job.child,
                    nonce: &job.nonce,
                    sequence: job.sequence,
                },
            )?;
            // The guardian can already have exited. Requiring an active unit
            // here would discard a queued authenticated final report. The
            // original child pidfd must independently corroborate its death;
            // scope retirement remains a separate observation after this.
            require(
                self.0
                    .child
                    .as_ref()
                    .ok_or_else(|| io::Error::other("original child handle absent"))?
                    .exited()?,
                "exit report arrived while original child is live",
            )?;
            let job = self
                .0
                .job
                .as_mut()
                .ok_or_else(|| io::Error::other("job state absent"))?;
            job.exit = Some(status);
            job.stopped = false;
            return Ok(JobEvent::Exited(status));
        }
        require(!job.stopped, "duplicate job stop before resume")?;
        let next = job
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("stop sequence exhausted"))?;
        let signal = validate_stopped(
            &packet,
            &StopContext {
                guardian: self.0.unit.pid,
                uid: self.0.unit.user,
                gid: rustix::process::getgid().as_raw(),
                invocation: &self.0.unit.invocation,
                child: job.child,
                nonce: &job.nonce,
                sequence: next,
            },
        )?;
        let job = self
            .0
            .job
            .as_mut()
            .ok_or_else(|| io::Error::other("job state disappeared"))?;
        job.sequence = next;
        job.stopped = true;
        if let Err(error) = self.0.recheck() {
            // A valid stop may already be followed by death. Preserve its
            // sequence for the final report, but never expose a stale stop as
            // live authority. A second stop is refused by job.stopped above.
            return match self.receive_job_event() {
                Ok(event @ JobEvent::Exited(_)) => Ok(event),
                _ => Err(error),
            };
        }
        Ok(JobEvent::Stopped(signal))
    }
    /// Only the pending stop can be resumed. A transport error can follow
    /// delivery; close and retire instead of treating failure as no resume.
    /// Recheck queued events after foreground reacquisition. If the original
    /// child died during resume validation, accept only its authenticated final
    /// report; no failed resume grants permission to signal a replacement.
    pub fn resume_or_observe(&mut self) -> io::Result<JobEvent> {
        match self.poll_job()? {
            JobEvent::Pending => {}
            event => return Ok(event),
        }
        match self.resume() {
            Ok(()) => Ok(JobEvent::Pending),
            Err(error) => match self.receive_job_event() {
                Ok(event @ JobEvent::Exited(_)) => Ok(event),
                _ => Err(error),
            },
        }
    }

    pub fn resume(&mut self) -> io::Result<()> {
        self.0.recheck()?;
        let job = self
            .0
            .job
            .as_ref()
            .ok_or_else(|| io::Error::other("session has no job-control protocol"))?;
        require(
            !job.exec_pending && job.stopped && job.exit.is_none(),
            "resume requires a pending authenticated job stop",
        )?;
        transport::send_until(
            self.0.socket()?,
            &journal_protocol::resume_packet(&job.nonce, job.sequence),
            &[],
            Instant::now() + Duration::from_secs(1),
        )?;
        self.0
            .job
            .as_mut()
            .ok_or_else(|| io::Error::other("job state disappeared"))?
            .stopped = false;
        Ok(())
    }
    pub fn terminal(&self) -> Option<BorrowedFd<'_>> {
        self.0.terminal.as_ref().map(AsFd::as_fd)
    }
    pub fn identity(&self) -> Identity {
        identity(&self.0)
    }
    pub fn close(self) -> Closed {
        self.0.close()
    }

    /// Original retained guardian only; keep control open to measure whether
    /// loss yields EOF without a fabricated target-exit report.
    pub fn crash_guardian_keep_control_for_fixture(&self) -> io::Result<()> {
        require(
            std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref() == Ok("1"),
            "guardian fault requires the hosted fixture",
        )?;
        self.0.recheck()?;
        self.0.binding.kill_guardian_for_fixture()
    }

    /// Hosted fixture fault injection using only the original retained pidfd.
    pub fn crash_guardian(self) -> Result<Closed, TransitionFailure> {
        let result = (|| {
            require(
                std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref() == Ok("1"),
                "guardian fault injection requires the activated journal fixture",
            )?;
            self.0.recheck()?;
            self.0.binding.kill_guardian_for_fixture()
        })();
        match result {
            Ok(()) => Ok(self.0.close()),
            Err(error) => Err(TransitionFailure {
                error,
                closed: Box::new(self.0.close()),
            }),
        }
    }
}
impl ExecStopped {
    pub fn identity(&self) -> Identity {
        identity(&self.0)
    }
    pub fn terminal(&self) -> Option<BorrowedFd<'_>> {
        self.0.terminal.as_ref().map(AsFd::as_fd)
    }
    pub fn close(self) -> Closed {
        self.0.close()
    }
    pub fn observe_held(&self) -> io::Result<()> {
        self.0.recheck()
    }
    pub fn crash_guardian(self) -> Result<Closed, TransitionFailure> {
        Running(self.0).crash_guardian()
    }

    /// Commit the spawn observation while the kernel exec stop is held. Any
    /// send failure afterwards leaves release uncertain, never safe to retry.
    pub fn release_after<E>(
        self,
        journal: impl FnOnce(u32) -> Result<(), E>,
    ) -> Result<Running, StartFailure<E>> {
        self.release_after_checked(journal, || Ok(()))
    }

    /// Check withdrawal after the final recheck, immediately before releasing
    /// the held exec. This does not make a successful send atomic with signals.
    pub fn release_after_checked<E>(
        mut self,
        journal: impl FnOnce(u32) -> Result<(), E>,
        permit: impl FnOnce() -> io::Result<()>,
    ) -> Result<Running, StartFailure<E>> {
        let before = self.0.recheck().and_then(|()| {
            self.0
                .job
                .as_ref()
                .filter(|job| job.exec_pending)
                .map(|job| job.child)
                .ok_or_else(|| io::Error::other("exec hold state absent"))
        });
        let pid = match before {
            Ok(pid) => pid,
            Err(error) => {
                return Err(StartFailure {
                    cause: StartCause::Transport(error),
                    live_at_refusal: None,
                    closed: Box::new(self.0.close()),
                });
            }
        };
        if let Err(error) = journal(pid) {
            let live_at_refusal = Some(self.0.recheck());
            return Err(StartFailure {
                cause: StartCause::Journal(error),
                live_at_refusal,
                closed: Box::new(self.0.close()),
            });
        }
        let result = self.0.recheck().and_then(|()| {
            let job = self
                .0
                .job
                .as_ref()
                .ok_or_else(|| io::Error::other("exec state absent"))?;
            permit()?;
            transport::send_until(
                self.0.socket()?,
                &journal_protocol::exec_release_packet(&job.nonce, job.child),
                &[],
                self.0.deadline,
            )
        });
        match result {
            Ok(()) => {
                if let Some(job) = &mut self.0.job {
                    job.exec_pending = false;
                }
                self.0.phase = Phase::Active;
                Ok(Running(self.0))
            }
            Err(error) => Err(StartFailure {
                cause: StartCause::Transport(error),
                live_at_refusal: None,
                closed: Box::new(self.0.close()),
            }),
        }
    }
}
impl Closed {
    /// Observation failure retains the witnesses for retry. Connection-close
    /// failure after proven retirement is reported separately from that result.
    pub fn retire(mut self) -> Result<Retired, RetireFailure> {
        let observed = (|| -> io::Result<()> {
            self.0.runtime()?.block_on(crate::watch::retire(
                self.0.connection()?,
                self.0.owner.as_str(),
                &self.0.unit,
                &self.0.binding,
            ))?;
            if let Some(child) = &self.0.child {
                require(
                    child.exited()?,
                    "writer pidfd remains live after retirement",
                )?;
            }
            Ok(())
        })();
        if let Err(error) = observed {
            return Err(RetireFailure {
                error,
                closed: Box::new(self),
            });
        }
        let closed = (|| -> io::Result<()> {
            outside_runtime()?;
            let runtime = self.0.runtime.get()?;
            let connection = self
                .0
                .connection
                .take()
                .ok_or_else(|| io::Error::other("manager connection is closed"))?;
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), connection.close())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "manager close expired"))?
                    .map_err(io::Error::other)
            })
        })();
        Ok(Retired {
            identity: identity(&self.0),
            connection_close_error: closed.err(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn exit_reports_bind_launch_and_preserve_code_or_signal_without_ambiguity() -> io::Result<()> {
        let invocation = "0123456789abcdef0123456789abcdef";
        let nonce = [7; 16];
        let expected = StopContext {
            guardian: 4000,
            uid: 1000,
            gid: 1001,
            invocation,
            child: 4001,
            nonce: &nonce,
            sequence: 2,
        };
        let sender = unix_ancillary::ScmCredentials::new(4000, 1000, 1001);
        let value = serde_json::json!({"kind":"aswp-fixture-exit-1", "child":4001, "invocation":invocation, "nonce":journal_protocol::encoded(&nonce), "sequence":2, "status":{"kind":"code","code":125}});
        let packet = |value: &serde_json::Value, sender| -> io::Result<activation_packet::Packet> {
            Ok(activation_packet::Packet {
                bytes: serde_json::to_vec(value).map_err(io::Error::other)?,
                sender,
            })
        };
        for status in [
            TargetExit::Code { code: 0 },
            TargetExit::Code { code: 125 },
            TargetExit::Code { code: 255 },
            TargetExit::Signal {
                signal: 2,
                core_dumped: false,
            },
            TargetExit::Signal {
                signal: 11,
                core_dumped: true,
            },
            TargetExit::Signal {
                signal: 64,
                core_dumped: false,
            },
        ] {
            let mut changed = value.clone();
            changed["status"] = serde_json::to_value(status).map_err(io::Error::other)?;
            assert_eq!(
                validate_exit(&packet(&changed, sender)?, &expected)?,
                status
            );
        }
        for (field, wrong) in [
            ("kind", serde_json::json!("aswp-fixture-stopped-1")),
            ("child", serde_json::json!(4002)),
            (
                "invocation",
                serde_json::json!("ffffffffffffffffffffffffffffffff"),
            ),
            (
                "nonce",
                serde_json::json!(journal_protocol::encoded(&[8; 16])),
            ),
            ("sequence", serde_json::json!(1)),
            ("sequence", serde_json::json!(3)),
            ("extra", serde_json::json!(true)),
            ("status", serde_json::json!({"kind":"code","code":256})),
            ("status", serde_json::json!({"kind":"code","code":-1})),
            (
                "status",
                serde_json::json!({"kind":"code","code":125,"signal":9}),
            ),
            (
                "status",
                serde_json::json!({"kind":"code","code":125,"core_dumped":false}),
            ),
            (
                "status",
                serde_json::json!({"kind":"signal","signal":0,"core_dumped":false}),
            ),
            (
                "status",
                serde_json::json!({"kind":"signal","signal":65,"core_dumped":false}),
            ),
            ("status", serde_json::json!({"kind":"signal","signal":9})),
            (
                "status",
                serde_json::json!({"kind":"stopped","signal":20,"core_dumped":false}),
            ),
        ] {
            let mut changed = value.clone();
            changed[field] = wrong;
            assert!(
                validate_exit(&packet(&changed, sender)?, &expected).is_err(),
                "accepted {field}"
            );
        }
        for field in ["kind", "child", "invocation", "nonce", "sequence", "status"] {
            let mut changed = value.clone();
            changed
                .as_object_mut()
                .ok_or_else(|| io::Error::other("missing test object"))?
                .remove(field);
            assert!(validate_exit(&packet(&changed, sender)?, &expected).is_err());
        }
        for sender in [
            unix_ancillary::ScmCredentials::new(0, 1000, 1001),
            unix_ancillary::ScmCredentials::new(4002, 1000, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1002, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1000, 1002),
        ] {
            assert!(validate_exit(&packet(&value, sender)?, &expected).is_err());
        }
        Ok(())
    }

    #[test]
    fn exec_notice_binds_original_sender_invocation_child_and_nonce() -> io::Result<()> {
        let invocation = "0123456789abcdef0123456789abcdef";
        let nonce = [7; 16];
        let expected = StopContext {
            guardian: 4000,
            uid: 1000,
            gid: 1001,
            invocation,
            child: 4001,
            nonce: &nonce,
            sequence: 0,
        };
        let sender = unix_ancillary::ScmCredentials::new(4000, 1000, 1001);
        let value = serde_json::json!({"kind":"aswp-fixture-exec-held-1", "child":4001, "invocation":invocation, "nonce":journal_protocol::encoded(&nonce)});
        let packet = |value: &serde_json::Value, sender| -> io::Result<activation_packet::Packet> {
            Ok(activation_packet::Packet {
                bytes: serde_json::to_vec(value).map_err(io::Error::other)?,
                sender,
            })
        };
        validate_exec(&packet(&value, sender)?, &expected)?;
        for (field, wrong) in [
            ("kind", serde_json::json!("aswp-fixture-stopped-1")),
            ("child", serde_json::json!(4002)),
            (
                "invocation",
                serde_json::json!("ffffffffffffffffffffffffffffffff"),
            ),
            (
                "nonce",
                serde_json::json!(journal_protocol::encoded(&[8; 16])),
            ),
            ("sequence", serde_json::json!(1)),
        ] {
            let mut changed = value.clone();
            changed[field] = wrong;
            assert!(validate_exec(&packet(&changed, sender)?, &expected).is_err());
        }
        for field in ["kind", "child", "invocation", "nonce"] {
            let mut changed = value.clone();
            changed
                .as_object_mut()
                .ok_or_else(|| io::Error::other("missing test object"))?
                .remove(field);
            assert!(validate_exec(&packet(&changed, sender)?, &expected).is_err());
        }
        for sender in [
            unix_ancillary::ScmCredentials::new(4002, 1000, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1002, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1000, 1002),
        ] {
            assert!(validate_exec(&packet(&value, sender)?, &expected).is_err());
        }
        Ok(())
    }

    #[test]
    fn queued_final_packet_survives_peer_reset_before_readiness() -> io::Result<()> {
        let (guardian, client) = transport::pair()?;
        rustix::fs::fcntl_setfl(
            &client,
            rustix::fs::fcntl_getfl(&client)? | rustix::fs::OFlags::NONBLOCK,
        )?;
        rustix::net::sockopt::set_socket_passcred(&client, true)?;
        transport::send(&client, b"unread-resume", &[])?;
        transport::send(&guardian, b"final-report", &[])?;
        drop(guardian);
        assert_eq!(control_readiness(&client)?, ControlReadiness::Packet);
        let packet = activation_packet::receive(&client, Instant::now() + Duration::from_secs(1))?;
        assert_eq!(packet.bytes, b"final-report");
        assert_eq!(packet.sender.pid(), std::process::id() as i32);
        assert_eq!(control_readiness(&client)?, ControlReadiness::Closed);
        assert!(rustix::net::sockopt::socket_passcred(&client)?);
        Ok(())
    }

    #[test]
    fn reset_without_a_final_packet_never_fabricates_one() -> io::Result<()> {
        let (guardian, client) = transport::pair()?;
        rustix::net::sockopt::set_socket_passcred(&client, true)?;
        transport::send(&client, b"unread-resume", &[])?;
        drop(guardian);
        assert_eq!(control_readiness(&client)?, ControlReadiness::Closed);
        Ok(())
    }

    #[test]
    fn an_empty_record_before_reset_is_still_not_eof() -> io::Result<()> {
        let (guardian, client) = transport::pair()?;
        rustix::net::sockopt::set_socket_passcred(&client, true)?;
        transport::send(&client, b"unread-resume", &[])?;
        rustix::net::send(&guardian, b"", rustix::net::SendFlags::NOSIGNAL)?;
        drop(guardian);
        assert!(control_readiness(&client).is_err());
        assert!(rustix::net::sockopt::socket_passcred(&client)?);
        Ok(())
    }

    #[test]
    fn relay_readiness_preserves_the_packet_before_reporting_shutdown() -> io::Result<()> {
        let (sender, receiver) = transport::pair()?;
        assert_eq!(control_readiness(&receiver)?, ControlReadiness::Pending);
        transport::send(&sender, transport::GO, &[])?;
        rustix::net::shutdown(&sender, rustix::net::Shutdown::Both)?;
        assert_eq!(control_readiness(&receiver)?, ControlReadiness::Packet);
        transport::receive_control(&receiver, transport::GO)?;
        assert_eq!(control_readiness(&receiver)?, ControlReadiness::Closed);
        Ok(())
    }

    #[test]
    fn relay_readiness_refuses_empty_records_even_after_peer_shutdown() -> io::Result<()> {
        for closed in [false, true] {
            let (sender, receiver) = transport::pair()?;
            rustix::net::send(&sender, b"", rustix::net::SendFlags::empty())?;
            if closed {
                rustix::net::shutdown(&sender, rustix::net::Shutdown::Both)?;
            }
            assert!(control_readiness(&receiver).is_err());
            assert!(!rustix::net::sockopt::socket_passcred(&receiver)?);
        }
        Ok(())
    }

    #[test]
    fn stop_notices_bind_sender_job_nonce_and_monotonic_sequence() -> io::Result<()> {
        let invocation = "0123456789abcdef0123456789abcdef";
        let nonce = [8; 16];
        let expected = StopContext {
            guardian: 4000,
            uid: 1000,
            gid: 1001,
            invocation,
            child: 4001,
            nonce: &nonce,
            sequence: 2,
        };
        let credentials = unix_ancillary::ScmCredentials::new(4000, 1000, 1001);
        let value = serde_json::json!({"kind":"aswp-fixture-stopped-1", "child":4001,
            "invocation":invocation, "nonce":journal_protocol::encoded(&nonce), "sequence":2, "signal":20});
        let packet = |value: &serde_json::Value, sender| -> io::Result<activation_packet::Packet> {
            Ok(activation_packet::Packet {
                bytes: serde_json::to_vec(value).map_err(io::Error::other)?,
                sender,
            })
        };
        assert_eq!(
            validate_stopped(&packet(&value, credentials)?, &expected)?,
            20
        );
        for (field, wrong) in [
            ("kind", serde_json::json!("aswp-fixture-prepared-1")),
            ("child", serde_json::json!(4002)),
            (
                "invocation",
                serde_json::json!("ffffffffffffffffffffffffffffffff"),
            ),
            (
                "nonce",
                serde_json::json!(journal_protocol::encoded(&[9; 16])),
            ),
            ("sequence", serde_json::json!(1)),
            ("sequence", serde_json::json!(3)),
            ("sequence", serde_json::json!(0)),
            ("sequence", serde_json::json!(9)),
            ("signal", serde_json::json!(2)),
            ("extra", serde_json::json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = wrong;
            assert!(
                validate_stopped(&packet(&changed, credentials)?, &expected).is_err(),
                "accepted {field}"
            );
        }
        for sender in [
            unix_ancillary::ScmCredentials::new(4002, 1000, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1002, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1000, 1002),
        ] {
            assert!(validate_stopped(&packet(&value, sender)?, &expected).is_err());
        }
        Ok(())
    }

    #[test]
    fn runtime_guard_drops_inside_another_runtime_without_waiting_for_blocking_work()
    -> io::Result<()> {
        let runtime = RuntimeGuard::new()?;
        let (ready, started) = std::sync::mpsc::channel();
        let (release, held) = std::sync::mpsc::channel();
        let worker = runtime.get()?.spawn_blocking(move || {
            let _ = ready.send(());
            held.recv_timeout(Duration::from_secs(3))
        });
        started
            .recv_timeout(Duration::from_secs(1))
            .map_err(io::Error::other)?;
        let outer = tokio::runtime::Builder::new_current_thread().build()?;
        outer.block_on(async {
            drop(runtime);
        });
        // A blocking destructor could not get here until the receive expired.
        release.send(()).map_err(io::Error::other)?;
        drop(worker);
        Ok(())
    }

    #[test]
    fn prepared_packets_bind_version_sender_invocation_and_child() -> io::Result<()> {
        let invocation = "0123456789abcdef0123456789abcdef";
        let credentials = unix_ancillary::ScmCredentials::new(4000, 1000, 1001);
        let value = serde_json::json!({"kind":"aswp-fixture-prepared-1", "child":4001, "invocation":invocation});
        let packet = |value: &serde_json::Value| -> io::Result<activation_packet::Packet> {
            Ok(activation_packet::Packet {
                bytes: serde_json::to_vec(value).map_err(io::Error::other)?,
                sender: credentials,
            })
        };
        assert_eq!(
            validate_prepared(&packet(&value)?, 4000, 1000, 1001, invocation)?,
            4001
        );
        for (field, changed) in [
            ("child", serde_json::json!(0)),
            ("child", serde_json::json!(1)),
            ("child", serde_json::json!(4000)),
            ("kind", serde_json::json!("other")),
            ("invocation", serde_json::json!("other")),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut bad = value.clone();
            bad[field] = changed;
            assert!(validate_prepared(&packet(&bad)?, 4000, 1000, 1001, invocation).is_err());
        }
        for field in ["kind", "child", "invocation"] {
            let mut bad = value.clone();
            bad.as_object_mut()
                .ok_or_else(|| io::Error::other("test object absent"))?
                .remove(field);
            assert!(validate_prepared(&packet(&bad)?, 4000, 1000, 1001, invocation).is_err());
        }
        for sender in [
            unix_ancillary::ScmCredentials::new(0, 1000, 1001),
            unix_ancillary::ScmCredentials::new(4001, 1000, 1001),
            unix_ancillary::ScmCredentials::new(4000, 0, 1001),
            unix_ancillary::ScmCredentials::new(4000, 1000, 1002),
        ] {
            let mut bad = packet(&value)?;
            bad.sender = sender;
            assert!(validate_prepared(&bad, 4000, 1000, 1001, invocation).is_err());
        }
        let mut bad = packet(&value)?;
        bad.bytes = b"not JSON".to_vec();
        assert!(validate_prepared(&bad, 4000, 1000, 1001, invocation).is_err());
        Ok(())
    }

    #[test]
    fn control_drop_disconnects_even_with_a_retained_socket_duplicate() -> io::Result<()> {
        let (client, guardian) = transport::pair()?;
        let duplicate = client.as_fd().try_clone_to_owned()?;
        drop(Control(Some(client)));
        assert!(transport::eof(&guardian)?);
        assert!(rustix::net::send(&duplicate, b"x", rustix::net::SendFlags::NOSIGNAL).is_err());
        Ok(())
    }

    #[test]
    fn delayed_control_drop_wakes_the_start_gate_as_withdrawal() -> io::Result<()> {
        let (client, guardian) = transport::pair()?;
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(Control(Some(client)));
        });
        let error =
            journal_protocol::receive_start(&guardian, Instant::now() + Duration::from_secs(1))
                .err()
                .ok_or_else(|| io::Error::other("dropped control unexpectedly started writer"))?;
        closer
            .join()
            .map_err(|_| io::Error::other("control closer panicked"))?;
        assert!(journal_protocol::is_withdrawal(&error));
        Ok(())
    }

    #[test]
    fn synchronous_client_refuses_nested_runtime_before_any_activation() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            let error = Bound::connect("not-an-opted-in-prefix")
                .err()
                .ok_or_else(|| io::Error::other("nested runtime unexpectedly admitted"))?;
            assert_eq!(
                error.to_string(),
                "fixture client cannot run inside an async runtime"
            );
            Ok::<(), io::Error>(())
        })?;
        outside_runtime()
    }
}
