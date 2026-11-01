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

struct Session {
    control: Control,
    connection: Option<Connection>,
    owner: zbus::names::OwnedUniqueName,
    unit: UnitFact,
    binding: kernel::Binding,
    child: Option<kernel::Child>,
    deadline: Instant,
    runtime: Option<tokio::runtime::Runtime>,
    _same_thread: PhantomData<Rc<()>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        drop(std::mem::replace(&mut self.control, Control(None)));
        drop(self.connection.take());
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
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
        self.runtime
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture runtime is closed"))
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (connection, owner, report, binding) = runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                crate::admit(paths, Some(expected)),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture binding expired"))?
        })?;
        Ok(Self(Session {
            control,
            connection: Some(connection),
            owner,
            unit: report
                .unit
                .ok_or_else(|| io::Error::other("fixture unit absent"))?,
            binding: binding.ok_or_else(|| io::Error::other("fixture kernel binding absent"))?,
            child: None,
            deadline,
            runtime: Some(runtime),
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
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Offer {
                child: u32,
                invocation: String,
            }
            let offer: Offer = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
            require(
                packet.sender.pid() == self.0.unit.pid as i32
                    && packet.sender.uid() == self.0.unit.user
                    && packet.sender.gid() == rustix::process::getgid().as_raw()
                    && offer.invocation == self.0.unit.invocation,
                "prepared writer sender changed",
            )?;
            self.0.child = Some(self.0.binding.child(offer.child, self.0.unit.pid)?);
            self.0.recheck()?;
            Ok(offer.child)
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let deadline = Instant::now() + Duration::from_secs(8);
        let (connection, owner, report, binding) = runtime.block_on(async {
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
        let binding =
            binding.ok_or_else(|| io::Error::other("independent kernel binding absent"))?;
        let child = binding.child(child_pid, claimed.guardian_pid)?;
        let session = Session {
            control: Control(None),
            connection: Some(connection),
            owner,
            unit: report
                .unit
                .ok_or_else(|| io::Error::other("independent unit absent"))?,
            binding,
            child: Some(child),
            deadline,
            runtime: Some(runtime),
            _same_thread: PhantomData,
        };
        require(
            identity(&session) == *claimed,
            "independent manager/kernel facts differ from claims",
        )?;
        session.recheck()?;
        Ok(Self(session))
    }
    pub fn retire(self) -> io::Result<Identity> {
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
    /// Caller must durably journal the returned PID before invoking this method.
    pub fn start(self, nonce: [u8; 16]) -> Result<Running, TransitionFailure> {
        let result = self.session.recheck().and_then(|()| {
            transport::send_until(
                self.session.socket()?,
                &journal_protocol::start_packet(&nonce),
                &[],
                self.session.deadline,
            )
        });
        match result {
            Ok(()) => Ok(Running(self.session)),
            Err(error) => Err(TransitionFailure {
                error,
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
    /// Return only observed identity, with no conversion to a custody receipt.
    pub fn retire(mut self) -> io::Result<Identity> {
        let result = self.0.runtime()?.block_on(crate::watch::retire(
            self.0.connection()?,
            self.0.owner.as_str(),
            &self.0.unit,
            &self.0.binding,
        ));
        result?;
        if let Some(child) = &self.0.child {
            require(
                child.exited()?,
                "writer pidfd remains live after retirement",
            )?;
        }
        let connection = self
            .0
            .connection
            .take()
            .ok_or_else(|| io::Error::other("manager connection is closed"))?;
        self.0.runtime()?.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), connection.close())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "manager close expired"))?
                .map_err(io::Error::other)
        })?;
        Ok(identity(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

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
    fn synchronous_client_refuses_nested_runtime_before_any_activation() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            assert!(outside_runtime().is_err());
        });
        outside_runtime()
    }
}
