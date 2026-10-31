//! Read-only transport qualification. No service creation or custody receipt.
#![forbid(unsafe_code)]

mod activation;
mod activation_packet;
mod kernel;
mod watch;

use serde::Serialize;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    num::NonZeroUsize,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
    time::Duration,
};
use zbus::{Connection, Message, OwnedObjectPath, OwnedVariant, connection::AuthMechanism};

const SOCKET: &str = "/run/dbus/system_bus_socket";
const DRIVER: &str = "org.freedesktop.DBus";
const DRIVER_PATH: &str = "/org/freedesktop/DBus";
const MANAGER: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn bounded_file(path: impl AsRef<Path>, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() <= limit, "metadata exceeds bounds")?;
    Ok(bytes)
}

fn identity_map(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| s.split_whitespace().eq(["0", "0", "4294967295"]))
}

#[derive(Serialize)]
struct PathFact {
    path: &'static str,
    uid: u32,
    mode: u32,
}

fn prerequisites() -> io::Result<Vec<PathFact>> {
    require(
        !rustix::process::geteuid().is_root(),
        "ordinary user required",
    )?;
    require(
        Path::new("/run/systemd/system").is_dir(),
        "system manager unavailable",
    )?;
    kernel::initial_namespace()?;
    let mut facts = Vec::new();
    for path in ["/", "/run", "/run/dbus", SOCKET] {
        let meta = fs::symlink_metadata(path)?;
        require(meta.uid() == 0, "bus path is not root-owned")?;
        if path == SOCKET {
            require(
                meta.file_type().is_socket(),
                "system bus path is not a socket",
            )?;
        } else {
            require(
                meta.is_dir() && meta.mode() & 0o022 == 0,
                "system bus ancestor is mutable or not a directory",
            )?;
        }
        facts.push(PathFact {
            path,
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
        });
    }
    Ok(facts)
}

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
    Activated { fragment: String },
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

fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn unit_path(unit: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            path.push(char::from(b));
        } else {
            path.push_str(&format!("_{b:02x}"));
        }
    }
    path
}

fn checked_reply(reply: Message, sender: &str) -> io::Result<Message> {
    require(
        reply
            .header()
            .sender()
            .is_some_and(|s| s.as_str() == sender),
        "reply sender changed",
    )?;
    // This is a post-receive decoding bound. zbus applies its own larger wire
    // limit before allocation; this check is not a custom transport memory cap.
    require(
        reply.data().len() <= 8192,
        "manager reply exceeds decoding bound",
    )?;
    Ok(reply)
}

async fn driver_call<T: serde::Serialize + zbus::DynamicType>(
    connection: &Connection,
    method: &str,
    body: &T,
) -> io::Result<Message> {
    let reply = connection
        .call_method(Some(DRIVER), DRIVER_PATH, Some(DRIVER), method, body)
        .await
        .map_err(io::Error::other)?;
    checked_reply(reply, DRIVER)
}

async fn owner(connection: &Connection) -> io::Result<zbus::names::OwnedUniqueName> {
    driver_call(connection, "GetNameOwner", &(MANAGER,))
        .await?
        .body()
        .deserialize()
        .map_err(io::Error::other)
}

async fn property(
    connection: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
    name: &str,
) -> io::Result<OwnedVariant> {
    // Only the authenticated unique name is a destination. Unique names cannot
    // be auto-activated; no interactive-authorization flag or proxy is used.
    let reply = connection
        .call_method(
            Some(owner),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(interface, name),
        )
        .await
        .map_err(io::Error::other)?;
    checked_reply(reply, owner)?
        .body()
        .deserialize()
        .map_err(io::Error::other)
}

async fn manager_call<T: serde::Serialize + zbus::DynamicType>(
    connection: &Connection,
    owner: &str,
    method: &str,
    body: &T,
) -> io::Result<OwnedObjectPath> {
    let reply = connection
        .call_method(
            Some(owner),
            MANAGER_PATH,
            Some("org.freedesktop.systemd1.Manager"),
            method,
            body,
        )
        .await
        .map_err(io::Error::other)?;
    checked_reply(reply, owner)?
        .body()
        .deserialize()
        .map_err(io::Error::other)
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
    let name_path = manager_call(connection, owner, "GetUnit", &(&expected.unit,)).await?;
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
    let path = manager_call(connection, owner, "GetUnitByInvocationID", &(&first,)).await?;
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
        UnitKind::Activated { fragment } => {
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
            activation::protected_fragment(fragment)?;
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
    let invocation_xattr = invocation_xattr(kernel.directory(), &first, &invocation)?;
    let corroborated = Vec::<u8>::try_from(
        property(connection, owner, &path, UNIT_INTERFACE, "InvocationID").await?,
    )
    .map_err(io::Error::other)?;
    require(
        corroborated == first,
        "invocation changed during kernel observation",
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
    let before = fs::symlink_metadata(SOCKET)?;
    let stream = tokio::net::UnixStream::connect(SOCKET).await?.into_std()?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    let after = fs::symlink_metadata(SOCKET)?;
    require(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "bus path changed while connecting",
    )?;
    require(
        peer.uid.is_root(),
        "bus listener peer is not root; record platform before widening policy",
    )?;
    let connection = zbus::connection::Builder::unix_stream(stream)
        .auth_mechanism(AuthMechanism::External)
        .max_queued(NonZeroUsize::new(4).ok_or_else(|| io::Error::other("invalid queue bound"))?)
        .method_timeout(Duration::from_secs(2))
        .build()
        .await
        .map_err(io::Error::other)?;
    let result = async {
        let owner_before = owner(&connection).await?;
        let credentials: zbus::fdo::ConnectionCredentials =
            driver_call(&connection, "GetConnectionCredentials", &(&owner_before,))
                .await?
                .body()
                .deserialize()
                .map_err(io::Error::other)?;
        require(
            credentials.unix_user_id() == Some(0) && credentials.process_id() == Some(1),
            "manager owner is not root PID 1",
        )?;
        if let Some(fd) = credentials.process_fd() {
            let info = bounded_file(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()), 4096)?;
            let info = std::str::from_utf8(&info).map_err(io::Error::other)?;
            let pids = info
                .lines()
                .filter_map(|l| l.strip_prefix("Pid:"))
                .map(str::trim)
                .collect::<Vec<_>>();
            require(
                pids == ["1"],
                "manager process descriptor does not identify local PID 1",
            )?;
        }
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
            peer_uid: peer.uid.as_raw(),
            peer_pid: peer.pid.as_raw_nonzero().get(),
            manager_uid: 0,
            manager_pid: 1,
            process_fd: credentials.process_fd().is_some(),
            dbus_override_ignored: std::env::var_os("DBUS_SYSTEM_BUS_ADDRESS").is_some(),
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
            connection.close().await.map_err(io::Error::other)?;
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
    let result = async {
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
    connection.close().await.map_err(io::Error::other)?;
    result
}

fn run() -> io::Result<Report> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--activation-probe") {
        require(
            args.len() == 2,
            "activation probe requires one fixture prefix",
        )?;
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

fn main() {
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
    fn replies_require_the_bound_sender_and_bounded_decoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = Message::method_call(MANAGER_PATH, "GetUnit").build(&("fixture",))?;
        for sender in [DRIVER, ":1.42"] {
            let reply = Message::method_return(&request.header())
                .sender(sender)
                .build(&1_u32)?;
            let accepted = checked_reply(reply, sender)?;
            assert_eq!(accepted.body().deserialize::<u32>()?, 1);
        }
        let unsigned = Message::method_return(&request.header()).build(&1_u32)?;
        assert!(checked_reply(unsigned, ":1.42").is_err());
        let other = Message::method_return(&request.header())
            .sender(":1.43")
            .build(&1_u32)?;
        assert!(checked_reply(other, ":1.42").is_err());
        let oversized = Message::method_return(&request.header())
            .sender(":1.42")
            .build(&vec![0_u8; 8192])?;
        assert!(checked_reply(oversized, ":1.42").is_err());
        let wrong_type = Message::method_return(&request.header())
            .sender(":1.42")
            .build(&"1")?;
        assert!(
            checked_reply(wrong_type, ":1.42")?
                .body()
                .deserialize::<u32>()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn namespace_gate_rejects_remapped_and_partial_identity_ranges() {
        assert!(identity_map(b"         0          0 4294967295\n"));
        for bytes in [
            b"0 1000 1".as_slice(),
            b"0 0 65536",
            b"0 0 4294967295\n1 1 1",
            b"0 0 4294967296",
            b"\xff",
        ] {
            assert!(!identity_map(bytes));
        }
    }

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
