//! Opted-in, synchronous CI client. Observations never authorize journal completion.
//! No method may run inside a Tokio runtime; Drop never drives asynchronous work.
use crate::{
    Connection, Expected, UnitFact, UnitKind, activation, activation_packet,
    admission_transport as transport, fixture_policy, journal_protocol, kernel, require,
};
use serde::Deserialize;
use std::{
    io,
    marker::PhantomData,
    os::fd::{BorrowedFd, OwnedFd},
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
    connection: Option<Connection>,
    owner: zbus::names::OwnedUniqueName,
    unit: UnitFact,
    binding: kernel::Binding,
    child: Option<kernel::Child>,
    deadline: Instant,
    runtime: RuntimeGuard,
    _same_thread: PhantomData<Rc<()>>,
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
        let remaining = self
            .deadline
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
pub struct Closed(Session);
/// Independent read-only witness; it never owns a copy of the activation socket.
pub struct Witness(Session);

/// A failed transition retains the original witnesses for explicit retirement.
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

impl Bound {
    pub fn connect(prefix: &str) -> io::Result<Self> {
        outside_runtime()?;
        fixture_policy::gate(prefix)?;
        let paths = crate::prerequisites()?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let (socket, _, offer) = activation::connect(prefix, b"ADMIT\n")?;
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
            connection: Some(connection),
            owner,
            unit,
            binding,
            child: None,
            deadline,
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
            let packet = activation_packet::receive(self.0.socket()?, self.0.deadline)?;
            let child_pid = validate_prepared(
                &packet,
                self.0.unit.pid,
                self.0.unit.user,
                rustix::process::getgid().as_raw(),
                &self.0.unit.invocation,
            )?;
            self.0.child = Some(self.0.binding.child(child_pid, self.0.unit.pid)?);
            self.0.recheck()?;
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
            connection: Some(connection),
            owner,
            unit,
            binding,
            child: None,
            deadline,
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
    /// Only a successful durable journal write may release GO. A transport
    /// failure afterwards must be treated as GO possibly having been delivered.
    pub fn start_after<E>(
        self,
        nonce: [u8; 16],
        journal: impl FnOnce(u32) -> Result<(), E>,
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
            Ok(()) => Ok(Running(self.session)),
            Err(error) => Err(StartFailure {
                cause: StartCause::Transport(error),
                live_at_refusal: None,
                closed: Box::new(self.session.close()),
            }),
        }
    }
}
impl Running {
    pub fn identity(&self) -> Identity {
        identity(&self.0)
    }
    pub fn close(self) -> Closed {
        self.0.close()
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
