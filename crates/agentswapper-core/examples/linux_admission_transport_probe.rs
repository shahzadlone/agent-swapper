//! Provider-free stdin handoff experiment. This does not establish cgroup custody.
#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("Linux-only admission transport probe; no provider launched.");
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = probe::run() {
        let text = error
            .to_string()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        println!("::error title=Linux admission transport::{text}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod probe {
    use rustix::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        io::{FdFlags, fcntl_getfd},
        net::{
            self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
            SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
            sockopt::{self, Timeout},
        },
    };
    use std::{
        fs::{self, File},
        io::{self, IoSlice, IoSliceMut, IsTerminal, Read, Seek, Write},
        mem::MaybeUninit,
        os::unix::process::CommandExt,
        path::Path,
        process::{Child, Command, Stdio},
        time::Duration,
    };
    use wait_timeout::ChildExt;

    const GO: &[u8] = b"ASWP-GO-1";
    const INPUT: &[u8] = b"stdin survives admission\0\xff\n";
    const BUDGET: Duration = Duration::from_secs(10);

    fn require(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let (a, b) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )?;
        sockopt::set_socket_timeout(&a, Timeout::Send, Some(Duration::from_secs(1)))?;
        sockopt::set_socket_timeout(&b, Timeout::Recv, Some(Duration::from_secs(5)))?;
        Ok((a, b))
    }

    fn send(socket: &OwnedFd, packet: &[u8], files: &[BorrowedFd<'_>]) -> io::Result<()> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !files.is_empty() {
            require(
                ancillary.push(SendAncillaryMessage::ScmRights(files)),
                "fixture ancillary buffer too small",
            )?;
        }
        let written = net::sendmsg(
            socket,
            &[IoSlice::new(packet)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )?;
        require(written == packet.len(), "incomplete admission packet")
    }

    fn receive(socket: impl AsFd) -> io::Result<OwnedFd> {
        let mut bytes = [0_u8; 9];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = net::recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        require(
            !received
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
            "truncated admission packet or rights",
        )?;
        require(
            received.bytes == GO.len() && bytes == GO,
            "invalid admission packet",
        )?;
        let mut files = Vec::new();
        for message in ancillary.drain() {
            match message {
                RecvAncillaryMessage::ScmRights(rights) => files.extend(rights),
                _ => return Err(io::Error::other("unexpected ancillary message")),
            }
        }
        require(
            files.len() == 1,
            "admission requires exactly one input descriptor",
        )?;
        let input = files
            .pop()
            .ok_or_else(|| io::Error::other("missing input descriptor"))?;
        require(
            fcntl_getfd(&input)?.contains(FdFlags::CLOEXEC),
            "received descriptor is inheritable",
        )?;
        Ok(input)
    }

    fn command(role: &str, mode: &str, dir: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .arg(role)
            .arg(mode)
            .arg(dir)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }

    struct Guard(Child);
    impl Guard {
        fn status(&mut self) -> io::Result<std::process::ExitStatus> {
            self.0
                .wait_timeout(BUDGET)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fixture timed out"))
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait_timeout(BUDGET);
        }
    }

    fn target(mode: &str, dir: &Path) -> io::Result<()> {
        fs::write(dir.join("executed"), "target ran")?;
        require(
            io::stdin().is_terminal() == (mode == "pty"),
            "stdin terminal identity changed",
        )?;
        for entry in fs::read_dir("/proc/self/fd")? {
            if let Ok(link) = fs::read_link(entry?.path()) {
                require(
                    !link.as_os_str().as_encoded_bytes().starts_with(b"socket:"),
                    "admission socket leaked across exec",
                )?;
            }
        }
        let mut actual = vec![0; INPUT.len()];
        io::stdin().read_exact(&mut actual)?;
        require(actual == INPUT, "stdin contents changed")?;
        if mode != "pty" {
            let mut extra = [0];
            require(io::stdin().read(&mut extra)? == 0, "stdin EOF changed")?;
        }
        Ok(())
    }

    fn valid(mode: &str, input: OwnedFd) -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let (parent, child) = pair()?;
        let mut process = Guard(
            command("shim", mode, dir.path())?
                .stdin(Stdio::from(child))
                .spawn()?,
        );
        let deadline = std::time::Instant::now() + BUDGET;
        while !dir.path().join("shim-ready").exists() {
            require(
                process.0.try_wait()?.is_none(),
                "shim exited before readiness",
            )?;
            require(
                std::time::Instant::now() < deadline,
                "shim never became ready",
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(50));
        require(
            !dir.path().join("executed").exists(),
            "target executed before GO",
        )?;
        send(&parent, GO, &[input.as_fd()])?;
        drop(parent);
        require(
            process.status()?.success(),
            "valid admission or target failed",
        )?;
        require(
            dir.path().join("executed").exists(),
            "target did not execute",
        )
    }

    fn controller() -> io::Result<()> {
        let mut file = tempfile::tempfile()?;
        file.write_all(INPUT)?;
        file.rewind()?;
        valid("file", file.as_fd().try_clone_to_owned()?)?;
        require(
            file.stream_position()? == INPUT.len() as u64,
            "file input was reopened rather than transferred",
        )?;

        let (reader, mut writer) = io::pipe()?;
        writer.write_all(INPUT)?;
        drop(writer);
        valid("pipe", reader.as_fd().try_clone_to_owned()?)?;

        let master = rustix::pty::openpt(
            rustix::pty::OpenptFlags::RDWR
                | rustix::pty::OpenptFlags::NOCTTY
                | rustix::pty::OpenptFlags::CLOEXEC,
        )?;
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let slave_name = rustix::pty::ptsname(&master, Vec::new())?;
        let slave = rustix::fs::open(
            slave_name.as_c_str(),
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let mut attributes = rustix::termios::tcgetattr(&slave)?;
        attributes.make_raw();
        rustix::termios::tcsetattr(&slave, rustix::termios::OptionalActions::Now, &attributes)?;
        let mut master = File::from(master);
        master.write_all(INPUT)?;
        valid("pty", slave)?;
        println!(
            "file offset/EOF, pipe EOF, raw PTY bytes and terminal identity preserved; no gate socket leak"
        );

        for fault in [
            "no-rights",
            "extra-rights",
            "truncated-rights",
            "bad-token",
            "oversized",
            "eof",
            "timeout",
        ] {
            let dir = tempfile::tempdir()?;
            let (parent, child) = pair()?;
            if fault == "timeout" {
                sockopt::set_socket_timeout(
                    &child,
                    Timeout::Recv,
                    Some(Duration::from_millis(250)),
                )?;
            }
            let mut process = Guard(
                command("shim", "file", dir.path())?
                    .stdin(Stdio::from(child))
                    .spawn()?,
            );
            let files = match fault {
                "no-rights" => vec![],
                "extra-rights" => vec![file.as_fd(); 2],
                "truncated-rights" => vec![file.as_fd(); 16],
                _ => vec![file.as_fd()],
            };
            match fault {
                "eof" | "timeout" => {}
                "bad-token" => send(&parent, b"NOT-A-GO!", &files)?,
                "oversized" => send(&parent, b"ASWP-GO-1extra", &files)?,
                _ => send(&parent, GO, &files)?,
            }
            let parent = if fault == "timeout" {
                Some(parent)
            } else {
                drop(parent);
                None
            };
            require(
                process.status()?.code() == Some(77),
                "invalid admission did not refuse",
            )?;
            require(
                !dir.path().join("executed").exists(),
                "invalid admission executed target",
            )?;
            drop(parent);
        }
        println!(
            "missing/extra/truncated descriptors, malformed/oversized packet, EOF and timeout refused before target execution"
        );
        Ok(())
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() == 1 {
            return controller();
        }
        let mode = args
            .get(2)
            .and_then(|v| v.to_str())
            .ok_or_else(|| io::Error::other("missing mode"))?;
        let dir = Path::new(
            args.get(3)
                .ok_or_else(|| io::Error::other("missing directory"))?,
        );
        match args[1].to_str() {
            Some("shim") => {
                fs::write(dir.join("shim-ready"), "ready")?;
                let input = match receive(io::stdin()) {
                    Ok(input) => input,
                    Err(_) => std::process::exit(77),
                };
                // The received descriptor is CLOEXEC; Command::exec duplicates
                // it to fd 0, preserving the original open file description.
                Err(command("target", mode, dir)?
                    .stdin(Stdio::from(input))
                    .exec())
            }
            Some("target") => target(mode, dir),
            _ => Err(io::Error::other("unknown fixture role")),
        }
    }
}
