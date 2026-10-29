//! Provider-free cgroup v2 spike; requires an explicitly delegated parent.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "support/linux_admission_transport.rs"]
mod admission_transport;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("Linux-only cgroup probe; no native agent was started.");
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux_probe::run() {
        let message = error
            .to_string()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        println!("::error title=Linux custody probe::{message}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
#[path = "../src/supervision/linux_cgroup.rs"]
mod cgroup;

#[cfg(target_os = "linux")]
mod linux_probe {
    mod guardian_cgroup;
    use super::{
        admission_transport,
        cgroup::{Domain, checked_directory, contains, control, populated, require, until},
    };
    use rustix::{
        fd::{AsFd, OwnedFd},
        fs::OFlags,
        process::{Pid, WaitOptions, getpgrp, set_child_subreaper, setsid, waitpid},
    };
    use std::{
        fs::{self, File},
        io::{self, Read, Write},
        os::unix::process::CommandExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    use wait_timeout::ChildExt;
    const BUDGET: Duration = Duration::from_secs(15);
    const LIFETIME: Duration = Duration::from_secs(45);
    const SOCKET_INPUT: &[u8] = b"native input survives cgroup admission\0\xff";

    enum Admission {
        Pipe,
        Socket(OwnedFd, std::io::PipeReader),
    }

    impl Admission {
        fn grant(self, shim: &mut Child) -> io::Result<()> {
            match self {
                Self::Pipe => shim
                    .stdin
                    .take()
                    .ok_or_else(|| io::Error::other("admission pipe missing"))?
                    .write_all(b"GO\n"),
                Self::Socket(socket, input) => {
                    admission_transport::send(&socket, admission_transport::GO, &[input.as_fd()])
                }
            }
        }
    }

    fn socket_shim(directory: &Path, group: &Path) -> io::Result<(OwnedChild, Admission)> {
        let (parent, child) = admission_transport::pair()?;
        let (reader, mut writer) = io::pipe()?;
        writer.write_all(SOCKET_INPUT)?;
        drop(writer);
        let shim = OwnedChild(
            command("admit-socket", directory, group)?
                .stdin(Stdio::from(child))
                .spawn()?,
        );
        Ok((shim, Admission::Socket(parent, reader)))
    }

    fn command(role: &str, directory: &Path, group: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.env_clear();
        for name in [
            "LLVM_PROFILE_FILE",
            "LD_LIBRARY_PATH",
            "ASAN_OPTIONS",
            "UBSAN_OPTIONS",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .args(["--fixture", role])
            .arg(directory)
            .arg(group)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }
    fn publish(directory: &Path, name: &str, value: &str) -> io::Result<()> {
        let temporary = directory.join(format!("{name}.tmp"));
        fs::write(&temporary, value)?;
        fs::rename(temporary, directory.join(name))
    }
    fn heartbeat(directory: &Path, name: &str) -> Option<(u32, u32, u64)> {
        let text = fs::read_to_string(directory.join(name)).ok()?;
        let mut parts = text.split_whitespace();
        let result = (
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        parts.next().is_none().then_some(result)
    }
    fn pid_file(directory: &Path, name: &str) -> Option<u32> {
        fs::read_to_string(directory.join(name)).ok()?.parse().ok()
    }
    fn reap(pid: u32, deadline: Instant) -> io::Result<rustix::process::WaitStatus> {
        let pid = Pid::from_raw(pid.try_into().map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("invalid fixture PID"))?;
        until(deadline, || {
            Ok(waitpid(Some(pid), WaitOptions::NOHANG)?.map(|(_, status)| status))
        })
    }
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait_timeout(Duration::from_secs(3));
        }
    }

    fn failed_creation_rolls_back(domain: &Domain) -> io::Result<()> {
        let children = || -> io::Result<Vec<_>> {
            let mut names = fs::read_dir(domain.path())?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<io::Result<Vec<_>>>()?;
            names.sort();
            Ok(names)
        };
        let before = children()?;
        for _ in 0..3 {
            let error = match domain
                .create_with_check(|_| Err(io::Error::other("injected validation failure")))
            {
                Err(error) => error,
                Ok(_) => return Err(io::Error::other("failed creation unexpectedly succeeded")),
            };
            require(
                error.to_string() == "injected validation failure",
                "creation lost its original failure",
            )?;
            require(
                children()? == before,
                "failed creation left a cgroup directory",
            )?;
        }
        println!(
            "failed cgroup initialization rolls back its empty child; delegated parent preserved"
        );
        Ok(())
    }

    fn admitted_tree(domain: &Domain, use_socket: bool) -> io::Result<()> {
        let deadline = Instant::now() + BUDGET;
        let directory = tempfile::tempdir()?;
        let mut group = domain.create()?;
        let mut control_writer =
            OwnedChild(command("control", directory.path(), group.path())?.spawn()?);
        let (mut shim, admission) = if use_socket {
            socket_shim(directory.path(), group.path())?
        } else {
            (
                OwnedChild(
                    command("admit", directory.path(), group.path())?
                        .stdin(Stdio::piped())
                        .spawn()?,
                ),
                Admission::Pipe,
            )
        };
        // The supervisor admits its still-owned child. The trusted shim cannot
        // execute the target before receiving GO on its private pipe.
        let admitted = shim.0.id();
        control(group.directory(), "cgroup.procs", OFlags::WRONLY)?
            .write_all(format!("{admitted}\n").as_bytes())?;
        require(
            contains(group.directory(), admitted)?,
            "shim admission did not match owned child and kernel membership",
        )?;
        // In production this observation must be journaled before GO. This
        // fixture tests the live admission and retirement kernel primitives.
        admission.grant(&mut shim.0)?;
        let leader = until(deadline, || shim.0.try_wait())?;
        require(leader.success(), "admitted fixture failed")?;
        if use_socket {
            require(
                directory.path().join("stdin-restored").exists(),
                "native stdin was not restored after cgroup admission",
            )?;
        }
        let middle = until(deadline, || Ok(pid_file(directory.path(), "middle-pid")))?;
        require(
            reap(middle, deadline)?.exit_status() == Some(0),
            "intermediate fixture failed",
        )?;
        let leaf = until(deadline, || Ok(heartbeat(directory.path(), "heartbeat")))?;
        let leaf_pid = until(deadline, || Ok(pid_file(directory.path(), "leaf-pid")))?;
        require(leaf.0 == leaf_pid, "heartbeat is not from the spawned leaf")?;
        let control = until(deadline, || {
            Ok(heartbeat(directory.path(), "control-heartbeat"))
        })?;
        require(
            leaf.1 != getpgrp().as_raw_nonzero().get() as u32,
            "writer did not leave the supervisor process group",
        )?;
        require(
            contains(group.directory(), leaf.0)? && !contains(group.directory(), control.0)?,
            "fixture group membership is wrong",
        )?;
        until(deadline, || {
            Ok(heartbeat(directory.path(), "heartbeat")
                .filter(|value| value.0 == leaf.0 && value.2 > leaf.2 + 3))
        })?;
        require(
            populated(group.directory())?,
            "fixture stopped before targeted kill",
        )?;
        group.retire(deadline)?;
        require(!group.path().exists(), "retired cgroup path remains")?;
        require(
            reap(leaf.0, deadline)?.terminating_signal() == Some(9),
            "cgroup writer was not killed",
        )?;
        let after = until(deadline, || {
            Ok(heartbeat(directory.path(), "control-heartbeat"))
        })?;
        until(deadline, || {
            Ok(heartbeat(directory.path(), "control-heartbeat")
                .filter(|value| value.0 == control.0 && value.2 > after.2 + 3))
        })?;
        require(
            !directory.path().join("writer-exited").exists(),
            "writer exited voluntarily",
        )?;
        require(
            !directory.path().join("fixture-failure").exists(),
            "fixture failed during containment test",
        )?;
        control_writer.0.kill()?;
        let _ = control_writer.0.wait()?;
        println!(
            "::notice title=Linux custody probe::cooperative setsid writer killed; cgroup empty and retired; outside control survives; descriptor transport={use_socket}"
        );
        Ok(())
    }

    fn late_admission(domain: &Domain) -> io::Result<()> {
        let deadline = Instant::now() + BUDGET;
        let directory = tempfile::tempdir()?;
        let mut group = domain.create()?;
        let mut late = OwnedChild(command("late", directory.path(), group.path())?.spawn()?);
        until(deadline, || {
            Ok(directory.path().join("late-ready").exists().then_some(()))
        })?;
        require(
            !populated(group.directory())?,
            "late fixture joined before retirement",
        )?;
        group.retire(deadline)?;
        publish(directory.path(), "release-late", "release")?;
        require(
            until(deadline, || late.0.try_wait())?.success(),
            "retired cgroup allowed late admission",
        )?;
        require(
            directory.path().join("late-refused").exists()
                && !directory.path().join("target-started").exists(),
            "late admission was not refused",
        )?;
        println!(
            "::notice title=Linux custody probe::retired cgroup rejects a late shim using a previously opened admission handle"
        );
        Ok(())
    }

    fn socket_requires_membership(domain: &Domain) -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let group = domain.create()?;
        let (mut shim, admission) = socket_shim(directory.path(), group.path())?;
        admission.grant(&mut shim.0)?;
        let status = until(Instant::now() + BUDGET, || shim.0.try_wait())?;
        require(
            !status.success(),
            "socket GO without membership executed target",
        )?;
        require(
            fs::read_to_string(directory.path().join("fixture-failure"))?
                .contains("supervisor did not admit shim into run cgroup"),
            "wrong refusal reason for missing membership",
        )?;
        require(
            !directory.path().join("stdin-restored").exists()
                && !directory.path().join("middle-pid").exists(),
            "unadmitted target ran",
        )?;
        require(
            !populated(group.directory())?,
            "unadmitted group unexpectedly populated",
        )?;
        println!(
            "::notice title=Linux custody probe::descriptor GO without kernel membership refuses target execution"
        );
        Ok(())
    }

    fn admission_requires_private_go(domain: &Domain) -> io::Result<()> {
        for (permission, admit, expected) in [
            (b"".as_slice(), true, "admission pipe closed before GO"),
            (b"NO\n".as_slice(), true, "invalid admission permission"),
            (
                b"GO\n".as_slice(),
                false,
                "supervisor did not admit shim into run cgroup",
            ),
        ] {
            let deadline = Instant::now() + BUDGET;
            let directory = tempfile::tempdir()?;
            let mut group = domain.create()?;
            // A file with the old release name must have no authority.
            publish(directory.path(), "go", "go")?;
            let mut shim = OwnedChild(
                command("admit", directory.path(), group.path())?
                    .stdin(Stdio::piped())
                    .spawn()?,
            );
            if admit {
                control(group.directory(), "cgroup.procs", OFlags::WRONLY)?
                    .write_all(format!("{}\n", shim.0.id()).as_bytes())?;
            }
            let mut pipe = shim
                .0
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("admission pipe missing"))?;
            pipe.write_all(permission)?;
            drop(pipe);
            require(
                !until(deadline, || shim.0.try_wait())?.success(),
                "shim accepted an invalid admission",
            )?;
            require(
                fs::read_to_string(directory.path().join("fixture-failure"))? == expected,
                "shim failed for an unrelated reason",
            )?;
            require(
                !directory.path().join("middle-pid").exists()
                    && !directory.path().join("heartbeat").exists(),
                "target ran without private GO",
            )?;
            group.retire(deadline)?;
        }
        println!(
            "::notice title=Linux custody probe::EOF, invalid GO and missing membership refuse target execution for the expected reasons"
        );
        Ok(())
    }

    fn fixture(role: &str, directory: &Path, group: &Path) -> io::Result<()> {
        let deadline = Instant::now() + BUDGET;
        match role {
            "guardian-parent" | "guardian-scope" => {
                guardian_cgroup::fixture(role, directory, group)
            }
            "admit" => {
                // EOF after supervisor loss refuses execution. Files in the
                // fixture directory cannot authorize target admission.
                let mut permission = [0_u8; 3];
                io::stdin().read_exact(&mut permission).map_err(|error| {
                    if error.kind() == io::ErrorKind::UnexpectedEof {
                        io::Error::other("admission pipe closed before GO")
                    } else {
                        error
                    }
                })?;
                require(permission == *b"GO\n", "invalid admission permission")?;
                let cg = checked_directory(group)?;
                require(
                    contains(&cg, std::process::id())?,
                    "supervisor did not admit shim into run cgroup",
                )?;
                let error = command("worker", directory, group)?.exec();
                Err(error)
            }
            "admit-socket" => {
                let input = admission_transport::receive(io::stdin())?;
                let cg = checked_directory(group)?;
                require(
                    contains(&cg, std::process::id())?,
                    "supervisor did not admit shim into run cgroup",
                )?;
                Err(command("worker-socket", directory, group)?
                    .stdin(Stdio::from(input))
                    .exec())
            }
            "late" => {
                let cg = checked_directory(group)?;
                let mut admission = control(&cg, "cgroup.procs", OFlags::WRONLY)?;
                publish(
                    directory,
                    "late-ready",
                    "admission handle open; still outside",
                )?;
                until(deadline, || {
                    Ok(directory.join("release-late").exists().then_some(()))
                })?;
                match admission.write_all(format!("{}\n", std::process::id()).as_bytes()) {
                    Err(error)
                        if error.raw_os_error()
                            == Some(rustix::io::Errno::NODEV.raw_os_error()) =>
                    {
                        publish(directory, "late-refused", "retired group rejects entry")
                    }
                    Err(error) => Err(error),
                    Ok(()) => {
                        publish(directory, "target-started", "unsafe late entry")?;
                        Err(io::Error::other("late shim entered a retired cgroup"))
                    }
                }
            }
            "worker" | "worker-socket" => {
                if role == "worker-socket" {
                    let mut actual = vec![0; SOCKET_INPUT.len()];
                    io::stdin().read_exact(&mut actual)?;
                    require(
                        actual == SOCKET_INPUT,
                        "stdin contents changed during admission",
                    )?;
                    let mut extra = [0];
                    require(
                        io::stdin().read(&mut extra)? == 0,
                        "stdin EOF changed during admission",
                    )?;
                    publish(
                        directory,
                        "stdin-restored",
                        "native input and EOF preserved",
                    )?;
                }
                setsid()?;
                let middle = command("middle", directory, group)?.spawn()?;
                publish(directory, "middle-pid", &middle.id().to_string())
            }
            "middle" => {
                setsid()?;
                let leaf = command("writer", directory, group)?.spawn()?;
                publish(directory, "leaf-pid", &leaf.id().to_string())
            }
            "writer" | "control" => {
                let started = Instant::now();
                let mut tick = 0_u64;
                let name = if role == "writer" {
                    "heartbeat"
                } else {
                    "control-heartbeat"
                };
                while started.elapsed() < LIFETIME && !directory.join("stop-all").exists() {
                    tick += 1;
                    let _ = publish(
                        directory,
                        name,
                        &format!(
                            "{} {} {tick}",
                            std::process::id(),
                            getpgrp().as_raw_nonzero().get()
                        ),
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                publish(directory, &format!("{role}-exited"), "voluntary exit")
            }
            _ => Err(io::Error::other("unknown fixture role")),
        }
    }

    pub fn run() -> io::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let first = args.next().ok_or_else(|| {
            io::Error::other("provide an owned delegated cgroup; no automatic or privileged setup")
        })?;
        if first == "--fixture" {
            let role = args
                .next()
                .ok_or_else(|| io::Error::other("fixture role missing"))?;
            let directory = PathBuf::from(
                args.next()
                    .ok_or_else(|| io::Error::other("fixture directory missing"))?,
            );
            let group = PathBuf::from(
                args.next()
                    .ok_or_else(|| io::Error::other("fixture group missing"))?,
            );
            let result = fixture(
                role.to_str()
                    .ok_or_else(|| io::Error::other("invalid fixture role"))?,
                &directory,
                &group,
            );
            if let Err(error) = &result {
                let _ = publish(&directory, "fixture-failure", &error.to_string());
            }
            return result;
        }
        let domain = Domain::open(Path::new(&first))?;
        set_child_subreaper(Some(rustix::process::getpid()))?;
        failed_creation_rolls_back(&domain)?;
        guardian_cgroup::run(&domain)?;
        admission_requires_private_go(&domain)?;
        admitted_tree(&domain, false)?;
        admitted_tree(&domain, true)?;
        socket_requires_membership(&domain)?;
        late_admission(&domain)
    }
}
