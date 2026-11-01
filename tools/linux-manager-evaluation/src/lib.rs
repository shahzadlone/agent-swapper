//! Manager observation and opted-in fixture activation. No custody receipts.
#![forbid(unsafe_code)]

mod activation;
mod activation_packet;
use agentswapper_linux_runtime::admission_transport;
mod common;
mod fixture_policy;
pub mod journal_client;
#[allow(
    dead_code,
    reason = "client uses only the shared start packet constructor"
)]
mod journal_protocol;
mod kernel;
pub mod managed_terminal_relay;
#[allow(dead_code, reason = "client validates the PTY created by the service")]
mod terminal;
mod watch;
use common::{require, valid_invocation};

use agentswapper_linux_manager::Manager as Connection;
use serde::Serialize;
use std::{
    io::{self, Write},
    time::Duration,
};

use agentswapper_linux_manager::{
    self as manager, PathFact, SERVICE_INTERFACE, UNIT_INTERFACE, owner, prerequisites, property,
    unit_path,
};

#[derive(Debug)]
struct Expected {
    unit: String,
    user: u32,
    pid: u32,
    invocation: Option<String>,
    kind: UnitKind,
}

#[derive(Debug)]
enum UnitKind {
    Transient,
    Activated { fragment: String, image: String },
}

impl Expected {
    fn parse(args: &[String]) -> io::Result<Option<Self>> {
        if args.is_empty() {
            return Ok(None);
        }
        require(
            matches!(args.len(), 3 | 4),
            "expected UNIT USER PID [INVOCATION]",
        )?;
        let unit = &args[0];
        let token = unit
            .strip_prefix("aswp-managed-")
            .and_then(|s| s.strip_suffix(".service"))
            .ok_or_else(|| io::Error::other("only owned fixture unit names are accepted"))?;
        require(
            !token.is_empty()
                && token.len() <= 128
                && !token.starts_with('-')
                && !token.ends_with('-')
                && token
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid fixture unit",
        )?;
        let user = args[1].parse::<u32>().map_err(io::Error::other)?;
        let pid = args[2].parse::<u32>().map_err(io::Error::other)?;
        require(
            user != 0 && pid > 1 && pid <= i32::MAX as u32,
            "invalid fixture user or PID",
        )?;
        let invocation = args.get(3).cloned();
        if let Some(id) = &invocation {
            require(valid_invocation(id), "invalid expected invocation")?;
        }
        Ok(Some(Self {
            unit: unit.clone(),
            user,
            pid,
            invocation,
            kind: UnitKind::Transient,
        }))
    }
}

#[derive(Serialize)]
struct UnitFact {
    unit: String,
    invocation: String,
    user: u32,
    pid: u32,
    control_group: String,
    delegate: bool,
    kill_mode: String,
    invocation_xattr: XattrFact,
    kernel: kernel::Fact,
}

#[derive(Serialize)]
struct XattrFact {
    size: Option<usize>,
    matches_raw: bool,
    matches_hex: bool,
    errno: Option<i32>,
}

fn invocation_xattr(
    dir: &std::os::fd::OwnedFd,
    raw: &[u8],
    encoded: &str,
) -> io::Result<XattrFact> {
    let mut bytes = [0; 256];
    match rustix::fs::fgetxattr(dir, "user.invocation_id", &mut bytes[..]) {
        Ok(size) => Ok(XattrFact {
            size: Some(size),
            matches_raw: &bytes[..size] == raw,
            matches_hex: &bytes[..size] == encoded.as_bytes(),
            errno: None,
        }),
        Err(error) => Ok(XattrFact {
            size: None,
            matches_raw: false,
            matches_hex: false,
            errno: Some(error.raw_os_error()),
        }),
    }
}

async fn snapshot(
    connection: &Connection,
    owner: &str,
    expected: &Expected,
) -> io::Result<(UnitFact, kernel::Binding)> {
    let name_path = manager::get_unit(connection, owner, &expected.unit).await?;
    require(
        name_path.as_str() == unit_path(&expected.unit),
        "unexpected unit object path",
    )?;
    let first = Vec::<u8>::try_from(
        property(
            connection,
            owner,
            &name_path,
            UNIT_INTERFACE,
            "InvocationID",
        )
        .await?,
    )
    .map_err(io::Error::other)?;
    require(
        first.len() == 16 && first.iter().any(|b| *b != 0),
        "invalid invocation bytes",
    )?;
    // systemd intentionally returns an invocation-specific object path here.
    // It differs from GetUnit's name path and expires with this invocation.
    // Bind the properties read through that object, rather than assuming the
    // two path strings must match or continuing to address a reusable name.
    let path = manager::get_invocation(connection, owner, &first).await?;
    let id = String::try_from(property(connection, owner, &path, UNIT_INTERFACE, "Id").await?)
        .map_err(io::Error::other)?;
    let active =
        String::try_from(property(connection, owner, &path, UNIT_INTERFACE, "ActiveState").await?)
            .map_err(io::Error::other)?;
    let transient =
        bool::try_from(property(connection, owner, &path, UNIT_INTERFACE, "Transient").await?)
            .map_err(io::Error::other)?;
    match &expected.kind {
        UnitKind::Transient => require(transient, "expected a transient fixture unit")?,
        UnitKind::Activated { fragment, .. } => {
            let actual = String::try_from(
                property(connection, owner, &path, UNIT_INTERFACE, "FragmentPath").await?,
            )
            .map_err(io::Error::other)?;
            let drop_ins = Vec::<String>::try_from(
                property(connection, owner, &path, UNIT_INTERFACE, "DropInPaths").await?,
            )
            .map_err(io::Error::other)?;
            require(
                !transient && actual == *fragment && drop_ins.is_empty(),
                "activation template or drop-ins differ",
            )?;
            fixture_policy::protected_fragment(fragment)?;
        }
    }
    let pid =
        u32::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "MainPID").await?)
            .map_err(io::Error::other)?;
    let user =
        String::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "User").await?)
            .map_err(io::Error::other)?;
    let group = String::try_from(
        property(connection, owner, &path, SERVICE_INTERFACE, "ControlGroup").await?,
    )
    .map_err(io::Error::other)?;
    let delegate =
        bool::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "Delegate").await?)
            .map_err(io::Error::other)?;
    let kill_mode =
        String::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "KillMode").await?)
            .map_err(io::Error::other)?;
    let service_type =
        String::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "Type").await?)
            .map_err(io::Error::other)?;
    let pid_file =
        String::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "PIDFile").await?)
            .map_err(io::Error::other)?;
    let notify = String::try_from(
        property(connection, owner, &path, SERVICE_INTERFACE, "NotifyAccess").await?,
    )
    .map_err(io::Error::other)?;
    let remain = bool::try_from(
        property(
            connection,
            owner,
            &path,
            SERVICE_INTERFACE,
            "RemainAfterExit",
        )
        .await?,
    )
    .map_err(io::Error::other)?;
    require(
        service_type == "exec" && pid_file.is_empty() && notify == "none" && !remain,
        "fixture service lifecycle differs from direct manager-owned execution",
    )?;
    let last = Vec::<u8>::try_from(
        property(connection, owner, &path, UNIT_INTERFACE, "InvocationID").await?,
    )
    .map_err(io::Error::other)?;
    let invocation = first.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let named_last = Vec::<u8>::try_from(
        property(
            connection,
            owner,
            &name_path,
            UNIT_INTERFACE,
            "InvocationID",
        )
        .await?,
    )
    .map_err(io::Error::other)?;
    require(
        first == last
            && first == named_last
            && expected
                .invocation
                .as_ref()
                .is_none_or(|v| v == &invocation),
        "invocation changed",
    )?;
    require(
        id == expected.unit
            && active == "active"
            && pid == expected.pid
            && user == expected.user.to_string()
            && group == format!("/system.slice/{}", expected.unit)
            && !delegate
            && kill_mode == "control-group",
        "unit snapshot disagrees with expected fixture",
    )?;
    let kernel = kernel::Binding::bind(&id, expected.user, pid)?;
    if let UnitKind::Activated { image, .. } = &expected.kind {
        let image = agentswapper_linux_runtime::installed_image::ProtectedImage::open(
            std::path::Path::new(image),
        )?;
        kernel.require_main_image(&image)?;
    }
    let invocation_xattr = invocation_xattr(kernel.directory(), &first, &invocation)?;
    let bound_pid =
        u32::try_from(property(connection, owner, &path, SERVICE_INTERFACE, "MainPID").await?)
            .map_err(io::Error::other)?;
    let bound_active =
        String::try_from(property(connection, owner, &path, UNIT_INTERFACE, "ActiveState").await?)
            .map_err(io::Error::other)?;
    let corroborated = Vec::<u8>::try_from(
        property(connection, owner, &path, UNIT_INTERFACE, "InvocationID").await?,
    )
    .map_err(io::Error::other)?;
    require(
        corroborated == first && bound_pid == pid && bound_active == "active",
        "manager state changed during kernel observation",
    )?;
    let fact = UnitFact {
        unit: id,
        invocation,
        user: expected.user,
        pid,
        control_group: group,
        delegate,
        kill_mode,
        invocation_xattr,
        kernel: kernel.observe()?,
    };
    Ok((fact, kernel))
}

#[derive(Serialize)]
struct Report {
    phase: &'static str,
    scope: &'static str,
    paths: Vec<PathFact>,
    peer_uid: u32,
    peer_pid: i32,
    manager_uid: u32,
    manager_pid: u32,
    process_fd: bool,
    dbus_override_ignored: bool,
    unit: Option<UnitFact>,
    retirement: Option<kernel::Retirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation: Option<activation::Fact>,
}

async fn admit(
    paths: Vec<PathFact>,
    expected: Option<Expected>,
) -> io::Result<(
    Connection,
    zbus::names::OwnedUniqueName,
    Report,
    Option<kernel::Binding>,
)> {
    let (connection, owner_before, transport) = manager::connect().await?;
    let result = async {
        let (unit, kernel) = match expected {
            Some(e) => {
                let (fact, binding) = snapshot(&connection, owner_before.as_str(), &e).await?;
                (Some(fact), Some(binding))
            }
            None => (None, None),
        };
        require(
            owner(&connection).await? == owner_before,
            "manager bus owner changed",
        )?;
        let report = Report {
            phase: "snapshot",
            scope: "read-only transport measurement; no custody receipt",
            paths,
            peer_uid: transport.peer_uid,
            peer_pid: transport.peer_pid,
            manager_uid: transport.manager_uid,
            manager_pid: transport.manager_pid,
            process_fd: transport.process_fd,
            dbus_override_ignored: transport.dbus_override_ignored,
            unit,
            retirement: None,
            activation: None,
        };
        Ok((owner_before, report, kernel))
    }
    .await;
    match result {
        Ok((owner, report, kernel)) => Ok((connection, owner, report, kernel)),
        Err(error) => {
            // Closing remains bounded by the caller's deadline, but should
            // not replace the observation error with a secondary close error.
            let _ = connection.close().await;
            Err(error)
        }
    }
}

fn write_report(report: &Report) -> io::Result<()> {
    let text = serde_json::to_string(report).map_err(io::Error::other)?;
    let mut output = io::stdout().lock();
    writeln!(output, "{text}")?;
    output.flush()
}

async fn inspect(
    paths: Vec<PathFact>,
    expected: Option<Expected>,
    watch: bool,
) -> io::Result<Report> {
    let (connection, owner, mut report, kernel) =
        tokio::time::timeout(Duration::from_secs(8), admit(paths, expected))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "manager binding deadline exceeded")
            })??;
    let result: io::Result<Report> = async {
        if watch {
            let unit = report
                .unit
                .as_ref()
                .ok_or_else(|| io::Error::other("watch requires a unit"))?;
            let binding = kernel
                .as_ref()
                .ok_or_else(|| io::Error::other("watch requires a kernel binding"))?;
            report.phase = "bound";
            write_report(&report)?;
            report.retirement = Some(
                watch::retire(&connection, owner.as_str(), unit, binding)
                    .await
                    .map_err(|error| {
                        io::Error::other(format!("retirement observation failed: {error}"))
                    })?,
            );
            report.phase = "retired";
        }
        Ok(report)
    }
    .await;
    let closed = connection.close().await.map_err(io::Error::other);
    let report = result?;
    closed?;
    Ok(report)
}

fn run() -> io::Result<Report> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--activation-probe") {
        require(
            args.len() == 2,
            "activation probe requires one fixture prefix",
        )?;
        fixture_policy::gate(&args[1])?;
        let paths = prerequisites()?;
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(35),
                    activation::inspect(paths, &args[1]),
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "activation observation deadline exceeded",
                    )
                })?
            });
    }
    let watch = args.first().is_some_and(|arg| arg == "--watch");
    if watch {
        args.remove(0);
    }
    let expected = Expected::parse(&args)?;
    require(
        !watch || expected.as_ref().is_some_and(|e| e.invocation.is_some()),
        "watch requires UNIT USER PID INVOCATION",
    )?;
    let paths = prerequisites()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(if watch { 30 } else { 10 }),
            inspect(paths, expected, watch),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "manager observation deadline exceeded",
            )
        })?
    })
}

/// Entry for the isolated client/observer executable. No custody receipts.
pub fn run_cli() {
    if let Err(error) = run().and_then(|report| write_report(&report)) {
        let diagnostic: String = error.to_string().escape_debug().take(2000).collect();
        eprintln!("manager observation unavailable or refused: {diagnostic}");
        std::process::exit(125);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_requests_bind_names_and_canonical_invocations() -> io::Result<()> {
        let args = [
            "aswp-managed-test.service",
            "1000",
            "42",
            "0123456789abcdef0123456789abcdef",
        ]
        .map(str::to_owned);
        assert!(Expected::parse(&args)?.is_some());
        assert_eq!(
            unit_path(&args[0]),
            "/org/freedesktop/systemd1/unit/aswp_2dmanaged_2dtest_2eservice"
        );
        for (index, bad) in [
            (0, "system.service"),
            (0, "aswp-managed-../x.service"),
            (1, "0"),
            (2, "1"),
            (3, "00000000000000000000000000000000"),
            (3, "0123456789ABCDEF0123456789ABCDEF"),
        ] {
            let mut bad_args = args.clone();
            bad_args[index] = bad.into();
            assert!(Expected::parse(&bad_args).is_err());
        }
        Ok(())
    }
}
