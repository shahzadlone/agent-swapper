//! Disposable fixed-user service. Only BIND and a fixed fixture writer exist;
//! this is not the production guardian or a general target-execution API.
use crate::{
    activation_packet, admission_transport, fixture_policy as activation, kernel, require,
};
use rustix::net::{self, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, sockopt};
use std::{
    fs,
    io::{self, IoSliceMut},
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn private_directory(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    require(
        path.is_absolute()
            && meta.is_dir()
            && meta.uid() == rustix::process::getuid().as_raw()
            && meta.mode() & 0o077 == 0,
        "fixture directory is not private to the ordinary user",
    )
}

pub(crate) fn protected_executable(prefix: &str) -> io::Result<()> {
    activation::protected_fragment(&format!("/run/systemd/system/{prefix}@.service"))?;
    let path = format!("/run/{prefix}.guardian");
    require(
        std::env::current_exe()? == Path::new(&path),
        "guardian image is not the installed fixture",
    )?;
    let meta = fs::symlink_metadata(path)?;
    require(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o7777 == 0o755,
        "guardian image is not root-owned and protected",
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Request {
    Bind,
    Run,
    Admit,
    Terminal,
    JobControl,
}

fn request(channel: &OwnedFd) -> io::Result<Request> {
    require(
        sockopt::socket_type(channel)? == net::SocketType::SEQPACKET,
        "activation control socket is not sequenced-packet",
    )?;
    sockopt::set_socket_timeout(
        channel,
        sockopt::Timeout::Recv,
        Some(Duration::from_secs(8)),
    )?;
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut bytes = [0_u8; 6];
    let mut ancillary = RecvAncillaryBuffer::new(&mut []);
    let received = net::recvmsg(
        channel,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let packet = &bytes[..received.bytes];
    require(
        !received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            && Instant::now() < deadline
            && matches!(
                packet,
                b"GO\n" | b"BIND\n" | b"ADMIT\n" | b"PTY1\n" | b"PTY2\n"
            ),
        "invalid fixture activation request",
    )?;
    Ok(match packet {
        b"BIND\n" => Request::Bind,
        b"ADMIT\n" => Request::Admit,
        b"PTY1\n" => Request::Terminal,
        b"PTY2\n" => Request::JobControl,
        _ => Request::Run,
    })
}

pub(crate) fn wait_until(
    deadline: Instant,
    mut ready: impl FnMut() -> io::Result<bool>,
) -> io::Result<()> {
    loop {
        require(
            Instant::now() < deadline,
            "activated fixture deadline expired",
        )?;
        if ready()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn serve(prefix: &str, uid: u32, gid: u32, directory: &Path, unit: &str) -> io::Result<()> {
    activation::gate(prefix)?;
    let started = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    require(
        uid != 0
            && rustix::process::getuid().as_raw() == uid
            && rustix::process::geteuid().as_raw() == uid
            && gid != 0
            && rustix::process::getgid().as_raw() == gid
            && rustix::process::getegid().as_raw() == gid,
        "activated guardian is not the fixed ordinary user",
    )?;
    protected_executable(prefix)?;
    private_directory(directory)?;
    kernel::initial_namespace()?;
    // The role is entered before async runtime/thread initialization. Mark all
    // inherited nonstandard descriptors before spawning the fixed writer.
    fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
    let channel = io::stdin().as_fd().try_clone_to_owned()?;
    let peer = activation_packet::peer(&channel)?;
    require(
        peer.pid() > 0
            && peer.uid() == uid
            && activation::connection_instance(unit, prefix, peer.pid() as u32, uid),
        "activation client identity differs",
    )?;
    let invocation = std::env::var("INVOCATION_ID").map_err(io::Error::other)?;
    require(
        crate::valid_invocation(&invocation),
        "invalid activation invocation",
    )?;
    let _binding = kernel::Binding::bind(unit, uid, std::process::id())?;
    let request = request(&channel)?;
    let bind_only = request == Request::Bind;
    let run = directory.join(&invocation);
    let mut worker = None;
    if request == Request::Run {
        fs::DirBuilder::new().mode(0o700).create(&run)?;
        // A fixed, bounded writer in this same root-owned image. No client
        // command, environment, launch envelope or descriptor is accepted.
        let mut command = Command::new("/proc/self/exe");
        command
            .args(["--activation-writer", prefix])
            .arg(&run)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for key in [
            "GITHUB_ACTIONS",
            "RUNNER_ENVIRONMENT",
            "ASWP_CI_SOCKET_ACTIVATION",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
        ] {
            command.env(key, std::env::var(key).map_err(io::Error::other)?);
        }
        worker = Some(command.spawn()?);
        wait_until(Instant::now() + Duration::from_secs(5), || {
            if let Some(child) = &mut worker
                && let Some(status) = child.try_wait()?
            {
                return Err(io::Error::other(format!(
                    "fixture writer exited before heartbeat: {status}"
                )));
            }
            Ok(run.join("heartbeat").exists())
        })?;
    }
    let offer = serde_json::json!({
        "unit": unit, "invocation": invocation, "pid": std::process::id(), "uid": uid,
        "group": format!("/system.slice/{unit}"), "peer_uid": peer.uid(), "peer_pid": peer.pid(),
        "started": started.tv_sec as f64 + started.tv_nsec as f64 / 1_000_000_000.0
    });
    let mut bytes = serde_json::to_vec(&offer).map_err(io::Error::other)?;
    bytes.push(b'\n');
    sockopt::set_socket_timeout(
        &channel,
        sockopt::Timeout::Send,
        Some(Duration::from_secs(1)),
    )?;
    require(
        net::send(&channel, &bytes, SendFlags::NOSIGNAL)? == bytes.len(),
        "incomplete activation offer",
    )?;
    if request == Request::JobControl {
        return crate::activated_job_control::serve(&channel, prefix, &run, &invocation);
    }
    if matches!(request, Request::Admit | Request::Terminal) {
        return crate::activated_journal::serve(
            &channel,
            prefix,
            &run,
            &invocation,
            request == Request::Terminal,
        );
    }
    if bind_only {
        // The coordinator queues the entire negative-control sequence before
        // releasing this bounded, private fixture barrier.
        wait_until(Instant::now() + Duration::from_secs(5), || {
            Ok(!directory.join("bind-eof-hold").exists())
        })?;
    }
    let refusal = if bind_only {
        "bind-only probe sent launch data"
    } else {
        "unexpected fixture activation command"
    };
    let disconnected = wait_until(
        Instant::now() + Duration::from_secs(if bind_only { 12 } else { 40 }),
        || {
            let eof = admission_transport::eof(&channel).map_err(|error| {
                if admission_transport::is_record_refusal(&error) {
                    io::Error::other(refusal)
                } else {
                    error
                }
            })?;
            if let Some(worker) = &mut worker {
                require(
                    worker.try_wait()?.is_none(),
                    "fixture writer exited before disconnect",
                )?;
            }
            Ok(eof)
        },
    );
    if bind_only
        && disconnected
            .as_ref()
            .is_err_and(|error| error.to_string() == refusal)
    {
        // A close with unread trailing records may reset the peer before it
        // receives our diagnostic. This is fixture attribution, not authority.
        fs::write(
            directory.join(format!("{invocation}.bind-refused")),
            refusal,
        )?;
    }
    disconnected?;
    let marker = if bind_only {
        directory.join(format!("{invocation}.bind-clean-eof"))
    } else {
        run.join("guardian-clean-eof")
    };
    fs::write(marker, invocation)?;
    // The manager owns the scope and kills its remaining processes when this
    // main process exits, on every return path. No numeric PID kill is used.
    Ok(())
}

pub(crate) fn writer_check(prefix: &str, directory: &Path) -> io::Result<()> {
    activation::gate(prefix)?;
    require(
        rustix::process::getuid().as_raw() != 0,
        "fixture writer must be ordinary",
    )?;
    protected_executable(prefix)?;
    private_directory(directory)?;
    // Collect names, not DirEntry objects, so the enumeration descriptor is
    // closed before verifying that exec retained only standard streams.
    // The gated role authenticates its stdin socket and null outputs separately.
    let names = fs::read_dir("/proc/self/fd")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    for name in names {
        let number = name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("invalid fixture descriptor name"))?;
        if number <= 2 {
            continue;
        }
        match fs::symlink_metadata(Path::new("/proc/self/fd").join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "fixture writer inherited an ambient descriptor",
                ));
            }
        }
    }
    Ok(())
}

fn writer(prefix: &str, directory: &Path) -> io::Result<()> {
    writer_check(prefix, directory)?;
    rustix::process::setsid()?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut counter = 0_u64;
    while Instant::now() < deadline {
        fs::write(directory.join("heartbeat.tmp"), counter.to_string())?;
        fs::rename(directory.join("heartbeat.tmp"), directory.join("heartbeat"))?;
        counter += 1;
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(directory.join("voluntary-exit"), "deadline")
}

pub(crate) fn dispatch() -> Option<io::Result<()>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("--activation-guardian") => Some((|| {
            require(
                args.len() == 6,
                "guardian fixture requires prefix, user, group, directory and unit",
            )?;
            let uid = args[2].parse::<u32>().map_err(io::Error::other)?;
            let gid = args[3].parse::<u32>().map_err(io::Error::other)?;
            serve(&args[1], uid, gid, Path::new(&args[4]), &args[5])
        })()),
        Some("--activation-gated-writer") => Some((|| {
            require(
                args.len() == 3,
                "gated writer requires prefix and directory",
            )?;
            crate::activated_journal::writer(&args[1], Path::new(&args[2]))
        })()),
        Some("--activation-terminal-shim" | "--activation-job-shim") => Some((|| {
            require(
                args.len() == 3,
                "terminal shim requires prefix and directory",
            )?;
            crate::activated_terminal::shim(
                &args[1],
                Path::new(&args[2]),
                args[0] == "--activation-job-shim",
            )
        })()),
        Some("--activation-terminal-target" | "--activation-job-target") => Some((|| {
            require(
                args.len() == 4,
                "terminal target requires prefix, directory and nonce",
            )?;
            crate::activated_terminal::target(
                &args[1],
                Path::new(&args[2]),
                &args[3],
                args[0] == "--activation-job-target",
            )
        })()),
        Some("--activation-job-descendant") => Some((|| {
            require(
                args.len() == 3,
                "job descendant requires prefix and directory",
            )?;
            crate::activated_terminal::descendant(&args[1], Path::new(&args[2]))
        })()),
        Some("--activation-writer") => Some((|| {
            require(
                args.len() == 3,
                "writer fixture requires prefix and directory",
            )?;
            writer(&args[1], Path::new(&args[2]))
        })()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_accepts_only_fixed_commands_without_descriptors() -> io::Result<()> {
        for (bytes, descriptor, accepted) in [
            (b"BIND\n".as_slice(), false, true),
            (b"ADMIT\n".as_slice(), false, true),
            (b"PTY1\n".as_slice(), false, true),
            (b"PTY2\n".as_slice(), false, true),
            (b"PTY2\nX".as_slice(), false, false),
            (b"PTY2\n".as_slice(), true, false),
            (b"PTY1\nX".as_slice(), false, false),
            (b"PTY1\n".as_slice(), true, false),
            (b"ADMIT".as_slice(), false, false),
            (b"ADMIT\nX".as_slice(), false, false),
            (b"ADMIT\n".as_slice(), true, false),
            (b"GO\n".as_slice(), false, true),
            (b"".as_slice(), false, false),
            (b"GO\nextra".as_slice(), false, false),
            (b"GO\nab".as_slice(), false, false),
            (b"BIND\nX".as_slice(), false, false),
            (b"BIND".as_slice(), false, false),
            (b"BIND\n".as_slice(), true, false),
        ] {
            let (sender, receiver) = admission_transport::pair()?;
            let file = tempfile::tempfile()?;
            let rights = if descriptor {
                vec![file.as_fd()]
            } else {
                vec![]
            };
            admission_transport::send(&sender, bytes, &rights)?;
            assert_eq!(request(&receiver).is_ok(), accepted);
        }
        Ok(())
    }
}
