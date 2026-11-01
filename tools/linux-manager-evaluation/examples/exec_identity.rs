//! Read-only image-change comparison. Positive observations only, no receipts.
#![forbid(unsafe_code)]
#[allow(dead_code, reason = "comparison uses selected private gate operations")]
#[path = "../../../crates/agentswapper-core/src/supervision/linux_admission_transport.rs"]
mod transport;

use std::{
    fs, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const READY: &[u8] = b"ASWP-IMAGE-READY-1";
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn until(deadline: Instant, mut ready: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "image comparison expired",
            ));
        }
        if ready()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Only std::Child reaps these untraced children; cached exits prevent
        // its kill() from signalling a recycled PID.
        let _ = self.0.kill();
        let _ = until(Instant::now() + Duration::from_secs(2), || {
            Ok(self.0.try_wait()?.is_some())
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Image(u64, u64);
fn image(child: &Child) -> io::Result<Image> {
    // The experiment owns this unreaped child and runs on the verified hosted
    // procfs layout. This pathname helper is NOT production manager binding.
    let handle = rustix::fs::open(
        format!("/proc/{}/exe", child.id()),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(handle)?;
    Ok(Image(stat.st_dev, stat.st_ino))
}
fn changed(child: &Child, original: Image) -> io::Result<bool> {
    match image(child) {
        Ok(current) => Ok(current != original),
        Err(error) if matches!(error.raw_os_error(), Some(2 | 13 | 3)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn gate() -> io::Result<OwnedFd> {
    let channel = io::stdin().as_fd().try_clone_to_owned()?;
    require(
        rustix::net::sockopt::socket_type(&channel)? == rustix::net::SocketType::SEQPACKET,
        "image shim requires its private sequenced-packet gate",
    )?;
    let peer = nix::sys::socket::getsockopt(&channel, nix::sys::socket::sockopt::PeerCredentials)?;
    require(
        peer.pid() == rustix::process::getppid().map_or(0, |p| p.as_raw_pid())
            && peer.uid() == rustix::process::getuid().as_raw(),
        "image shim gate parent differs",
    )?;
    Ok(channel)
}
fn shim(mode: &str, directory: &Path) -> io::Result<()> {
    let channel = gate()?;
    require(
        matches!(
            mode,
            "different" | "same" | "fast" | "exit" | "kill" | "missing"
        ),
        "unknown image mode",
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    transport::send_until(&channel, READY, &[], deadline)?;
    transport::receive_control_until(&channel, transport::GO, deadline)?;
    if mode == "exit" {
        std::process::exit(125);
    }
    require(mode != "kill", "kill fault received GO")?;
    let target = match mode {
        "same" => std::env::current_exe()?,
        "missing" => directory.join("not-present"),
        _ => directory.join("image-copy"),
    };
    fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
    let error = Command::new(target)
        .arg("--target")
        .arg(mode)
        .arg(directory)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec();
    fs::write(
        directory.join("exec-error"),
        error.raw_os_error().unwrap_or(0).to_string(),
    )?;
    Err(error)
}
fn target(mode: &str, directory: &Path) -> io::Result<()> {
    if mode != "fast" {
        fs::write(
            directory.join("target-started"),
            std::process::id().to_string(),
        )?;
        until(Instant::now() + Duration::from_secs(5), || {
            Ok(directory.join("release").exists())
        })?;
    }
    std::process::exit(125);
}

fn trial(mode: &str) -> io::Result<bool> {
    let directory = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    if matches!(mode, "different" | "fast") {
        // A distinct inode of exactly the same fixed program; no arbitrary
        // provider executable or script is accepted by this experiment.
        fs::copy(&executable, directory.path().join("image-copy"))?;
        let original = fs::metadata(&executable)?;
        let copied = fs::metadata(directory.path().join("image-copy"))?;
        require(
            (original.dev(), original.ino()) != (copied.dev(), copied.ino()),
            "copied image identity did not change",
        )?;
    }
    let (control, input) = transport::pair()?;
    let mut command = Command::new(executable);
    command
        .args(["--shim", mode])
        .arg(directory.path())
        .env_clear()
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = OwnedChild(command.spawn()?);
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(5);
    transport::receive_control_until(&control, READY, deadline)?;
    let original = image(&child.0)?;
    if mode == "kill" {
        child.0.kill()?;
    } else {
        transport::send_until(&control, transport::GO, &[], deadline)?;
    }
    // The shim retains a CLOEXEC duplicate until exec or death. Its stdin is
    // also replaced at exec. This EOF is only a trigger to inspect the image.
    until(deadline, || transport::eof(&control))?;
    let observed = changed(&child.0, original)?;
    match mode {
        "different" => require(observed, "live distinct image was not observed")?,
        "same" | "exit" | "kill" | "missing" => {
            require(!observed, "unchanged or absent image falsely confirmed")?
        }
        "fast" => {}
        _ => unreachable!(),
    }
    fs::write(directory.path().join("release"), "release fixed target")?;
    let mut status = None;
    until(deadline, || {
        status = child.0.try_wait()?;
        Ok(status.is_some())
    })?;
    let status = status.ok_or_else(|| io::Error::other("target status unavailable"))?;
    use std::os::unix::process::ExitStatusExt;
    if mode == "kill" {
        require(status.signal() == Some(9), "kill status differs")?;
    } else {
        require(status.code() == Some(125), "fixture status differs")?;
    }
    if mode == "missing" {
        require(
            fs::read_to_string(directory.path().join("exec-error"))? == "2",
            "missing target did not report ENOENT",
        )?;
    } else {
        require(
            !directory.path().join("exec-error").exists(),
            "unexpected exec failure",
        )?;
    }
    require(
        directory.path().join("target-started").exists() == matches!(mode, "different" | "same"),
        "fixed target execution marker differs",
    )?;
    Ok(observed)
}
fn experiment() -> io::Result<()> {
    // A fresh executable has no custom SIGCHLD handler or competing waiter.
    let status = fs::read_to_string("/proc/self/status")?;
    let ignored = status
        .lines()
        .find_map(|s| s.strip_prefix("SigIgn:\t"))
        .ok_or_else(|| io::Error::other("signal disposition unavailable"))?;
    require(
        u64::from_str_radix(ignored, 16).map_err(io::Error::other)?
            & (1 << (nix::libc::SIGCHLD - 1))
            == 0,
        "image experiment refuses ignored SIGCHLD",
    )?;
    for mode in ["different", "same", "exit", "kill", "missing"] {
        let observed = trial(mode)?;
        println!(
            "exec identity: {mode}: {}",
            if observed {
                "image change observed"
            } else {
                "unresolved"
            }
        );
    }
    let mut positives = 0;
    for _ in 0..25 {
        positives += usize::from(trial("fast")?);
    }
    println!(
        "::notice title=Linux exec identity comparison::distinct live image confirmed; same-image exec, pre-exec exit, pre-GO SIGKILL and ENOENT unresolved; fast target: {positives}/25 observed, {}/25 unresolved; no custody or provider readiness claim",
        25 - positives
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => experiment(),
        [role, mode, directory] if role == "--shim" => shim(mode, Path::new(directory)),
        [role, mode, directory] if role == "--target" => target(mode, Path::new(directory)),
        _ => Err(io::Error::other("unknown image comparison role")),
    };
    if let Err(error) = result {
        eprintln!("exec identity comparison refused: {error}");
        std::process::exit(125);
    }
}
