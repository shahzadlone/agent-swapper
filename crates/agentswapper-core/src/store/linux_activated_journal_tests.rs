//! Real journal/lease integration with the opted-in, root-installed CI fixture.
#![allow(clippy::unwrap_used)]
use super::*;
use aswp_linux_manager_evaluation::journal_client::{
    Bound, Identity, JobEvent, Prepared, StartCause, TargetExit,
};
use std::{fs, os::fd::AsFd, thread};

fn environment() -> (String, PathBuf) {
    assert_eq!(
        std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref(),
        Ok("1")
    );
    let prefix = std::env::var("ASWP_ACTIVATION_PREFIX").unwrap();
    let directory = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_DIRECTORY").unwrap());
    assert!(directory.is_absolute());
    (prefix, directory)
}

fn prepare(store: &mut Store, alias: &str, prefix: &str) -> (ProfileId, String, Prepared) {
    prepare_mode(store, alias, prefix, false)
}

fn prepare_mode(
    store: &mut Store,
    alias: &str,
    prefix: &str,
    terminal: bool,
) -> (ProfileId, String, Prepared) {
    prepare_using(
        store,
        alias,
        prefix,
        if terminal {
            Bound::connect_terminal
        } else {
            Bound::connect
        },
    )
}

fn prepare_using(
    store: &mut Store,
    alias: &str,
    prefix: &str,
    connect: fn(&str) -> std::io::Result<Bound>,
) -> (ProfileId, String, Prepared) {
    let profile = store
        .register(Harness::Claude, alias.parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let bound = connect(prefix).unwrap();
    let logical = Uuid::new_v4();
    assert_ne!(logical.simple().to_string(), bound.identity().invocation);
    let run = store
        .begin_run_with_scope(
            &lease,
            "run",
            None,
            Some(LocalScope::LinuxCgroup { id: logical }),
        )
        .unwrap();
    let prepared = bound.prepare(lease.as_fd()).unwrap();
    // Only the guardian's received copy now retains this lock.
    drop(lease);
    assert!(matches!(store.acquire_lease(profile.id), Err(Error::Busy)));
    (profile.id, run, prepared)
}

fn heartbeat(
    directory: &Path,
    id: &Identity,
    pid: u32,
    nonce: &[u8; 16],
    previous: Option<&str>,
) -> String {
    let prefix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let value = fs::read_to_string(directory.join(&id.invocation).join("heartbeat"));
        if let Ok(value) = value
            && value.starts_with(&format!("{pid}:{prefix}:"))
            && previous != Some(value.as_str())
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "writer did not acknowledge the journaled GO nonce"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn quiescent(prepared: &Prepared, directory: &Path) {
    let run = directory.join(prepared.identity().invocation);
    assert_eq!(
        fs::read_to_string(run.join("ready")).unwrap(),
        prepared.pid().to_string()
    );
    prepared.observe_ready().unwrap();
    thread::sleep(Duration::from_millis(200));
    assert!(!run.join("heartbeat").exists());
    prepared.observe_ready().unwrap();
}

fn journal_while_gated(
    store: &mut Store,
    run: &str,
    pid: u32,
    directory: &Path,
    id: &Identity,
) -> Result<()> {
    store.observe_spawn(run, pid)?;
    thread::sleep(Duration::from_millis(200));
    assert_eq!(store.run(run)?.observed_pid, Some(pid));
    assert_eq!(
        fs::read_to_string(directory.join(&id.invocation).join("ready"))?,
        pid.to_string()
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    Ok(())
}

fn unresolved(store: &Store, profile: ProfileId, run: &str) {
    drop(store.acquire_lease(profile).unwrap());
    assert!(matches!(store.lease(profile), Err(Error::Busy)));
    let record = store.run(run).unwrap();
    assert_eq!(record.custody, ProcessCustody::Unknown);
    assert!(record.exit_code.is_none());
}

fn exec_held(scope: &Path, pid: u32, guardian: u32, master: impl AsFd) {
    assert!(!scope.join("final-exec").exists());
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert_eq!(
        status
            .lines()
            .find_map(|line| line.strip_prefix("TracerPid:"))
            .map(str::trim),
        Some(guardian.to_string().as_str())
    );
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    assert_eq!(
        stat.rsplit_once(") ").unwrap().1.split_whitespace().next(),
        Some("t")
    );
    let args = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert_eq!(
        args.split(|b| *b == 0).nth(1),
        Some(b"--activation-job-target".as_slice())
    );
    let mut watched = [rustix::event::PollFd::new(
        &master,
        rustix::event::PollFlags::IN,
    )];
    assert_eq!(
        rustix::event::poll(
            &mut watched,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0
            })
        )
        .unwrap(),
        0
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn exec_stop_precedes_spawn_journal_and_release_or_retirement() {
    let (prefix, directory) = environment();
    for finish in ["release", "journal", "disconnect", "guardian", "deadline"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let mut store = Store::open(&root).unwrap();
        let (profile, run, prepared) = prepare_using(
            &mut store,
            "exec-gate",
            &prefix,
            Bound::connect_exec_control,
        );
        let id = prepared.identity();
        let pid = prepared.pid();
        let scope = directory.join(&id.invocation);
        let master = prepared.terminal().unwrap().try_clone_to_owned().unwrap();
        quiescent(&prepared, &directory);
        let nonce = *Uuid::new_v4().as_bytes();
        let mut awaiting = prepared
            .start_after(nonce, |child| {
                assert_eq!(child, pid);
                let intent = store.run(&run)?;
                assert!(intent.observed_pid.is_none() && intent.exit_code.is_none());
                assert!(store.verify()?.consistent);
                assert!(!scope.join("final-exec").exists());
                Ok::<(), Error>(())
            })
            .unwrap();
        // Job-control requests must not consume the exec notice or release it.
        assert!(awaiting.poll_job().is_err());
        assert!(awaiting.wait_stopped().is_err());
        assert!(awaiting.resume().is_err());
        let held = awaiting.hold_exec().unwrap();
        assert_eq!(held.identity(), id);
        held.observe_held().unwrap();
        exec_held(&scope, pid, id.guardian_pid, &master);
        assert!(store.run(&run).unwrap().observed_pid.is_none());
        let witness =
            aswp_linux_manager_evaluation::journal_client::Witness::bind(&prefix, &id, pid)
                .unwrap();
        let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
        let closed = match finish {
            "release" => {
                let mut running = held
                    .release_after(|child| {
                        assert_eq!(child, pid);
                        store.observe_spawn(&run, child)?;
                        thread::sleep(Duration::from_millis(100));
                        assert_eq!(store.run(&run)?.observed_pid, Some(pid));
                        assert!(store.verify()?.consistent);
                        exec_held(&scope, pid, id.guardian_pid, &master);
                        Ok::<(), Error>(())
                    })
                    .unwrap();
                let encoded: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(
                    terminal_output(&master, b"\x1b[0m\r\n"),
                    format!("\x1b[32mREADY:{pid}:{encoded}:→\x1b[0m\r\n").as_bytes()
                );
                assert_eq!(
                    fs::read_to_string(scope.join("final-exec")).unwrap(),
                    format!("{pid}:{encoded}")
                );
                let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
                assert_eq!(
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("TracerPid:"))
                        .map(str::trim),
                    Some("0")
                );
                terminal_input(&master, b"suspend\n");
                assert_eq!(
                    terminal_output(&master, b"SUSPEND>"),
                    b"suspend\r\nSUSPEND>"
                );
                assert_eq!(running.wait_stopped().unwrap(), 20);
                job_topology(&master, pid, id.guardian_pid, pid, true);
                running.resume().unwrap();
                assert_eq!(terminal_output(&master, b"RESUMED\r\n"), b"RESUMED\r\n");
                terminal_input(&master, b"size\n");
                assert_eq!(
                    terminal_output(&master, b"SIZE:24:80\r\n"),
                    b"size\r\nSIZE:24:80\r\n"
                );
                terminal_input(&master, b"\x03");
                let until = Instant::now() + Duration::from_secs(3);
                while !scope.join("target-exit").exists() {
                    assert!(Instant::now() < until, "released target did not interrupt");
                    thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    fs::read_to_string(scope.join("target-exit")).unwrap(),
                    "None:Some(2)"
                );
                let event = loop {
                    let event = running.poll_job().unwrap();
                    if event != JobEvent::Pending {
                        break event;
                    }
                    assert!(Instant::now() < until, "target exit report absent");
                    thread::sleep(Duration::from_millis(10));
                };
                assert_eq!(
                    event,
                    JobEvent::Exited(TargetExit::Signal {
                        signal: 2,
                        core_dumped: false
                    })
                );
                running.close()
            }
            "journal" => {
                store.db.busy_timeout(Duration::from_millis(20)).unwrap();
                blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
                let failure = match held.release_after(|child| store.observe_spawn(&run, child)) {
                    Err(failure) => failure,
                    Ok(_) => panic!("failed spawn journal released exec stop"),
                };
                assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
                assert!(
                    matches!(failure.cause, StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _))) if error.code == rusqlite::ErrorCode::DatabaseBusy)
                );
                *failure.closed
            }
            "guardian" => held.crash_guardian().unwrap(),
            "deadline" => {
                // Keep control and master open. Manager retirement must follow
                // the bounded release gate, not client-channel shutdown.
                assert!(witness.retire().unwrap().connection_close_error.is_none());
                let failure = match held.release_after(|_| -> Result<()> {
                    panic!("expired exec gate invoked journal callback")
                }) {
                    Err(failure) => failure,
                    Ok(_) => panic!("expired exec gate accepted release"),
                };
                assert!(matches!(failure.cause, StartCause::Transport(_)));
                assert!(
                    failure
                        .closed
                        .retire()
                        .unwrap()
                        .connection_close_error
                        .is_none()
                );
                terminal_retired(&master, false);
                assert!(!scope.join("final-exec").exists());
                unresolved(&store, profile, &run);
                drop(store);
                let reopened = Store::open(&root).unwrap();
                unresolved(&reopened, profile, &run);
                assert!(reopened.run(&run).unwrap().observed_pid.is_none());
                assert!(reopened.verify().unwrap().consistent);
                continue;
            }
            _ => held.close(),
        };
        assert!(closed.retire().unwrap().connection_close_error.is_none());
        assert!(witness.retire().unwrap().connection_close_error.is_none());
        terminal_retired(&master, finish == "release");
        if finish != "release" {
            assert!(!scope.join("final-exec").exists());
        }
        if finish == "journal" {
            blocker.execute_batch("ROLLBACK").unwrap();
        }
        unresolved(&store, profile, &run);
        drop(blocker);
        drop(store);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile, &run);
        assert_eq!(
            reopened.run(&run).unwrap().observed_pid,
            if finish == "release" { Some(pid) } else { None }
        );
        assert!(reopened.verify().unwrap().consistent);
    }
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn authenticated_target_exit_survives_guardian_retirement_but_loss_stays_unknown() {
    let (prefix, directory) = environment();
    for finish in ["zero", "125", "interrupt", "realtime", "guardian-loss"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let mut store = Store::open(&root).unwrap();
        let (profile, run, prepared) = prepare_using(
            &mut store,
            "exec-exit",
            &prefix,
            Bound::connect_exec_control,
        );
        let id = prepared.identity();
        let pid = prepared.pid();
        let scope = directory.join(&id.invocation);
        let master = prepared.terminal().unwrap().try_clone_to_owned().unwrap();
        let target_fd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        prepared.observe_ready().unwrap();
        let awaiting = prepared
            .start_after(*Uuid::new_v4().as_bytes(), |_| {
                assert!(store.run(&run)?.observed_pid.is_none());
                Ok::<(), Error>(())
            })
            .unwrap();
        let mut running = awaiting
            .hold_exec()
            .unwrap()
            .release_after(|child| store.observe_spawn(&run, child))
            .unwrap();
        terminal_output(&master, b"\x1b[0m\r\n");
        let witness =
            aswp_linux_manager_evaluation::journal_client::Witness::bind(&prefix, &id, pid)
                .unwrap();
        terminal_input(&master, b"spawn\n");
        let until = Instant::now() + Duration::from_secs(3);
        let child: u32 = loop {
            if let Ok(value) = fs::read_to_string(scope.join("descendant-ready")) {
                break value.parse().unwrap();
            }
            assert!(Instant::now() < until, "exit-test descendant absent");
            thread::sleep(Duration::from_millis(10));
        };
        terminal_output(&master, format!("CHILD:{child}\r\n").as_bytes());
        descendant_state(child, pid, &id, false);
        let child_fd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(child as i32).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        let before = descendant_heartbeat(&scope, None);
        descendant_heartbeat(&scope, Some(&before));
        let expected = match finish {
            "zero" => {
                terminal_input(&master, b"finish\n");
                terminal_output(&master, "FINAL:\x1b[34m→\x1b[0m\r\n".as_bytes());
                Some(TargetExit::Code { code: 0 })
            }
            "125" => {
                terminal_input(&master, b"exit-125\n");
                terminal_output(&master, b"exit-125\r\n");
                Some(TargetExit::Code { code: 125 })
            }
            "interrupt" => {
                terminal_input(&master, b"\x03");
                Some(TargetExit::Signal {
                    signal: 2,
                    core_dumped: false,
                })
            }
            "realtime" => {
                // The fixed sender receives the original target capability as
                // stdin. It never looks up a numeric PID or accepts a command.
                let sent = std::process::Command::new("/usr/bin/python3")
                    .args(["-I", "-S", "-c", "import signal; signal.pidfd_send_signal(0, signal.SIGRTMIN); print(int(signal.SIGRTMIN))"])
                    .env_clear()
                    .stdin(std::process::Stdio::from(target_fd))
                    .output().unwrap();
                assert!(sent.status.success(), "fixed realtime sender failed");
                let signal: u8 = std::str::from_utf8(&sent.stdout)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                assert!((34..=64).contains(&signal));
                Some(TargetExit::Signal {
                    signal,
                    core_dumped: false,
                })
            }
            _ => {
                running.crash_guardian_keep_control_for_fixture().unwrap();
                None
            }
        };
        // Deliberately receive only AFTER the original guardian and scope are
        // gone, without closing client control. A queued status must survive;
        // requiring an active guardian now would wrongly discard it.
        assert!(witness.retire().unwrap().connection_close_error.is_none());
        let event = running.poll_job().unwrap();
        match expected {
            Some(status) => assert_eq!(event, JobEvent::Exited(status)),
            None => assert_eq!(event, JobEvent::Closed),
        }
        assert_eq!(running.observed_exit(), expected);
        assert_eq!(running.poll_job().unwrap(), JobEvent::Closed);
        assert!(running.resume().is_err());
        assert!(
            running
                .close()
                .retire()
                .unwrap()
                .connection_close_error
                .is_none()
        );
        terminal_retired(&master, finish == "interrupt");
        let mut watched = [rustix::event::PollFd::new(
            &child_fd,
            rustix::event::PollFlags::IN,
        )];
        assert_eq!(
            rustix::event::poll(
                &mut watched,
                Some(&rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                })
            )
            .unwrap(),
            1
        );
        assert!(
            watched[0]
                .revents()
                .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)
        );
        assert!(!scope.join("descendant-voluntary-exit").exists());
        let retired = descendant_heartbeat(&scope, None);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(descendant_heartbeat(&scope, None), retired);
        unresolved(&store, profile, &run);
        drop(store);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile, &run);
        assert_eq!(reopened.run(&run).unwrap().observed_pid, Some(pid));
        assert!(reopened.verify().unwrap().consistent);
    }
}

fn terminal_output(master: impl AsFd, suffix: &[u8]) -> Vec<u8> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut output = Vec::new();
    while !output.ends_with(suffix) {
        assert!(output.len() < 4096, "terminal output exceeds fixture bound");
        let timeout = Timespec::try_from(
            deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("terminal output expired: {output:?}")),
        )
        .unwrap();
        let mut ready = [PollFd::new(&master, PollFlags::IN)];
        assert_eq!(
            poll(&mut ready, Some(&timeout)).unwrap(),
            1,
            "terminal output timed out: {output:?}"
        );
        let mut bytes = [0; 512];
        let read = rustix::io::read(&master, &mut bytes)
            .unwrap_or_else(|error| panic!("terminal read failed: {error}; output: {output:?}"));
        assert!(
            read > 0,
            "terminal closed before expected output: {output:?}"
        );
        output.extend_from_slice(&bytes[..read]);
    }
    output
}

fn terminal_input(master: impl AsFd, input: &[u8]) {
    assert_eq!(rustix::io::write(master, input).unwrap(), input.len());
}

fn terminal_gated(master: impl AsFd, pid: u32) {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    assert_eq!(
        rustix::termios::tcgetsid(&master).err(),
        Some(rustix::io::Errno::NOTTY)
    );
    let args = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert_eq!(
        args.split(|b| *b == 0).nth(1),
        Some(b"--activation-terminal-shim".as_slice())
    );
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_ne!(fields[3], pid.to_string());
    assert_eq!(fields[4], "0");
    let mut ready = [PollFd::new(&master, PollFlags::IN)];
    let timeout = Timespec::try_from(Duration::from_millis(200)).unwrap();
    assert_eq!(poll(&mut ready, Some(&timeout)).unwrap(), 0);
}

fn terminal_retired(master: impl AsFd, interrupted: bool) {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    assert!(
        rustix::fs::fcntl_getfl(&master)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK)
    );
    // A pending Ctrl-C echo can remain after the last slave closes; drain it
    // within a small bound before requiring the kernel's final EIO.
    let mut drained = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let timeout = Timespec::try_from(
            deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("terminal retirement expired; tail: {drained:?}")),
        )
        .unwrap();
        let mut ready = [PollFd::new(&master, PollFlags::IN)];
        assert_eq!(
            poll(&mut ready, Some(&timeout)).unwrap(),
            1,
            "terminal retirement timed out; tail: {drained:?}"
        );
        let mut bytes = [0; 64];
        match rustix::io::read(&master, &mut bytes) {
            Ok(n) if n > 0 => {
                drained.extend_from_slice(&bytes[..n]);
                assert!(drained.len() < 256);
            }
            Err(rustix::io::Errno::IO) => break,
            Err(rustix::io::Errno::AGAIN) => thread::sleep(Duration::from_millis(1)),
            result => panic!("retired PTY did not reach EIO: {result:?}"),
        }
    }
    assert_eq!(
        rustix::termios::tcgetsid(&master).err(),
        Some(rustix::io::Errno::NOTTY)
    );
    assert!(
        drained.is_empty() || (interrupted && drained == b"^C"),
        "unexpected terminal tail: {drained:?}"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn inner_terminal_exec_is_journal_gated_and_retires_with_master_open() {
    let (prefix, directory) = environment();
    for finish in ["disconnect", "interrupt", "journal", "guardian"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let mut store = Store::open(&root).unwrap();
        let (profile, run, prepared) = prepare_mode(&mut store, "terminal", &prefix, true);
        let id = prepared.identity();
        let pid = prepared.pid();
        let scope = directory.join(&id.invocation);
        // Retain an independent master even across retirement, so a PTY hangup
        // cannot masquerade as successful control-channel cleanup.
        let master = prepared.terminal().unwrap().try_clone_to_owned().unwrap();
        quiescent(&prepared, &directory);
        terminal_gated(&master, pid);
        assert!(!scope.join("final-exec").exists());
        let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
        if finish == "journal" {
            store.db.busy_timeout(Duration::from_millis(20)).unwrap();
            blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        }
        let nonce = *Uuid::new_v4().as_bytes();
        let start = prepared.start_after(nonce, |child| {
            assert_eq!(child, pid);
            journal_while_gated(&mut store, &run, child, &directory, &id)?;
            terminal_gated(&master, child);
            assert!(!scope.join("final-exec").exists());
            if finish == "disconnect" {
                terminal_input(&master, b"size\n");
                assert_eq!(terminal_output(&master, b"size\r\n"), b"size\r\n");
                terminal_gated(&master, child);
            }
            Ok::<(), Error>(())
        });
        if finish == "journal" {
            let failure = match start {
                Err(failure) => failure,
                Ok(_) => panic!("SQLite failure released terminal GO"),
            };
            assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
            assert!(matches!(failure.cause,
                StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
                if error.code == rusqlite::ErrorCode::DatabaseBusy));
            assert!(
                failure
                    .closed
                    .retire()
                    .unwrap()
                    .connection_close_error
                    .is_none()
            );
            assert_eq!(
                fs::read_to_string(scope.join("guardian-withdrawn-before-go")).unwrap(),
                id.invocation
            );
            assert!(!scope.join("final-exec").exists());
            blocker.execute_batch("ROLLBACK").unwrap();
        } else {
            let running = start.unwrap();
            // This independent observer owns no activation control descriptor.
            let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let mut expected = format!("\x1b[32mREADY:{pid}:{nonce}:→\x1b[0m\r\n");
            let suffix = if finish == "disconnect" {
                expected.push_str("SIZE:24:80\r\n");
                b"SIZE:24:80\r\n".as_slice()
            } else {
                b"\x1b[0m\r\n".as_slice()
            };
            assert_eq!(terminal_output(&master, suffix), expected.as_bytes());
            assert_eq!(
                fs::read_to_string(scope.join("final-exec")).unwrap(),
                format!("{pid}:{nonce}")
            );
            let witness =
                aswp_linux_manager_evaluation::journal_client::Witness::bind(&prefix, &id, pid)
                    .unwrap();
            assert_eq!(
                rustix::termios::tcgetsid(&master).unwrap().as_raw_pid(),
                pid as i32
            );
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            let fields: Vec<_> = stat
                .rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .collect();
            assert_eq!(fields[3], pid.to_string());
            assert_ne!(fields[4], "0");
            assert_eq!(fields[5], pid.to_string());
            rustix::termios::tcsetwinsize(
                &master,
                rustix::termios::Winsize {
                    ws_row: 41,
                    ws_col: 113,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                },
            )
            .unwrap();
            terminal_input(&master, b"size\n");
            assert_eq!(
                terminal_output(&master, b"SIZE:41:113\r\n"),
                b"size\r\nSIZE:41:113\r\n"
            );
            terminal_input(&master, b"secret\n");
            terminal_output(&master, b"SECRET>");
            terminal_input(&master, b"fake-password-123\n");
            assert_eq!(terminal_output(&master, b"SECRET-OK\r\n"), b"SECRET-OK\r\n");
            terminal_input(&master, b"raw\n");
            assert_eq!(terminal_output(&master, b"RAW>"), b"raw\r\nRAW>");
            let bytes = "é→\x1b[A\x03\r\x7f\x15\x17\x04\x16\x13\x11\x1c\x1a".as_bytes();
            terminal_input(&master, &[bytes, b"\n"].concat());
            let encoded: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                terminal_output(&master, b"\r\n"),
                format!("RAW:{encoded}\r\n").as_bytes()
            );
            terminal_input(&master, b"size\n");
            assert_eq!(
                terminal_output(&master, b"SIZE:41:113\r\n"),
                b"size\r\nSIZE:41:113\r\n"
            );
            assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
            if finish == "interrupt" {
                terminal_input(&master, b"\x03");
                let deadline = Instant::now() + Duration::from_secs(4);
                while !scope.join("target-exit").exists() {
                    assert!(
                        Instant::now() < deadline,
                        "Ctrl-C did not terminate the foreground target"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    fs::read_to_string(scope.join("target-exit")).unwrap(),
                    "None:Some(2)"
                );
            }
            let closed = if finish == "guardian" {
                terminal_input(&master, b"raw\n");
                assert_eq!(terminal_output(&master, b"RAW>"), b"raw\r\nRAW>");
                running.crash_guardian().unwrap()
            } else {
                running.close()
            };
            assert!(closed.retire().unwrap().connection_close_error.is_none());
            assert!(witness.retire().unwrap().connection_close_error.is_none());
            if finish == "disconnect" {
                assert_eq!(
                    fs::read_to_string(scope.join("guardian-clean-eof")).unwrap(),
                    id.invocation
                );
                assert!(!scope.join("target-exit").exists());
            } else {
                assert!(!scope.join("guardian-clean-eof").exists());
                if finish == "guardian" {
                    assert!(!scope.join("target-exit").exists());
                }
            }
        }
        terminal_retired(&master, finish == "interrupt");
        unresolved(&store, profile, &run);
        drop(blocker);
        drop(store);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile, &run);
        assert_eq!(
            reopened.run(&run).unwrap().observed_pid,
            if finish == "journal" { None } else { Some(pid) }
        );
        assert!(reopened.verify().unwrap().consistent);
        drop(master);
    }
}

fn job_topology(master: impl AsFd, pid: u32, guardian: u32, foreground: u32, stopped: bool) {
    assert_eq!(
        rustix::termios::tcgetsid(&master).unwrap().as_raw_pid(),
        guardian as i32
    );
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_eq!(fields[1], guardian.to_string());
    assert_eq!(fields[2], pid.to_string());
    assert_eq!(fields[3], guardian.to_string());
    assert_ne!(fields[4], "0");
    assert_eq!(fields[5], foreground.to_string());
    assert_eq!(fields[0] == "T", stopped);
}

fn descendant_state(pid: u32, parent: u32, id: &Identity, stopped: bool) {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(fields[1], parent.to_string());
        assert_eq!(fields[2], parent.to_string());
        assert_eq!(fields[3], id.guardian_pid.to_string());
        assert_ne!(fields[4], "0");
        assert_eq!(fields[5], parent.to_string());
        if (fields[0] == "T") == stopped {
            break;
        }
        assert!(
            Instant::now() < until,
            "descendant stop/continue state did not settle"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap(),
        format!("0::/system.slice/{}\n", id.unit)
    );
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .unwrap();
    assert_eq!(
        u64::from_str_radix(mask.trim(), 16).unwrap() & 1,
        1,
        "descendant must block SIGHUP"
    );
}

fn descendant_heartbeat(scope: &Path, previous: Option<&str>) -> String {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(value) = fs::read_to_string(scope.join("descendant-heartbeat"))
            && Some(value.as_str()) != previous
        {
            return value;
        }
        assert!(
            Instant::now() < until,
            "descendant heartbeat did not advance"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn nested_job_stays_inside_target(
    master: impl AsFd,
    scope: &Path,
    target: u32,
    id: &Identity,
    running: &mut aswp_linux_manager_evaluation::journal_client::Running,
) {
    terminal_input(&master, b"nested\n");
    let until = Instant::now() + Duration::from_secs(3);
    let nested: u32 = loop {
        if let Ok(value) = fs::read_to_string(scope.join("nested-ready")) {
            break value.parse().unwrap();
        }
        assert!(Instant::now() < until, "nested job did not become ready");
        thread::sleep(Duration::from_millis(10));
    };
    let suffix = format!("NESTED-RUNNING:{nested}\r\n");
    assert_eq!(
        terminal_output(&master, suffix.as_bytes()),
        format!("nested\r\n{suffix}").as_bytes()
    );
    job_topology(&master, target, id.guardian_pid, nested, false);
    let nested_fd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(nested as i32).unwrap(),
        rustix::process::PidfdFlags::empty(),
    )
    .unwrap();
    terminal_input(&master, b"\x1a");
    let suffix = format!("NESTED-STOPPED:{nested}\r\n");
    assert_eq!(
        terminal_output(&master, suffix.as_bytes()),
        format!("^Z{suffix}").as_bytes()
    );
    job_topology(&master, target, id.guardian_pid, target, false);
    let stat = fs::read_to_string(format!("/proc/{nested}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_eq!(fields[0], "T");
    assert_eq!(fields[1], target.to_string());
    assert_eq!(fields[2], nested.to_string());
    assert_eq!(fields[3], id.guardian_pid.to_string());
    assert_eq!(fields[5], target.to_string());
    // The direct target has handled its own child's stop. It remains running,
    // and no guardian notice may misidentify this as an outer-session stop.
    let error = running.wait_stopped().unwrap_err();
    assert_eq!(
        error.to_string(),
        "activation packet did not arrive before deadline"
    );
    let previous = descendant_heartbeat(scope, None);
    descendant_heartbeat(scope, Some(&previous));
    job_topology(&master, target, id.guardian_pid, target, false);
    terminal_input(&master, b"resume-nested\n");
    assert_eq!(
        terminal_output(&master, b"NESTED-DONE\r\n"),
        b"resume-nested\r\nNESTED-DONE\r\n"
    );
    job_topology(&master, target, id.guardian_pid, target, false);
    let mut watched = [rustix::event::PollFd::new(
        &nested_fd,
        rustix::event::PollFlags::IN,
    )];
    assert_eq!(
        rustix::event::poll(
            &mut watched,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0
            })
        )
        .unwrap(),
        1
    );
    assert!(watched[0].revents().contains(rustix::event::PollFlags::IN));
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn guardian_session_stops_resume_and_retire_without_releasing_journal_policy() {
    let (prefix, directory) = environment();
    for finish in [
        "resume",
        "disconnect",
        "guardian",
        "hangup-running",
        "hangup-stopped",
        "journal",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let mut store = Store::open(&root).unwrap();
        let (profile, run, prepared) = prepare_using(
            &mut store,
            "job-control",
            &prefix,
            Bound::connect_job_control,
        );
        let id = prepared.identity();
        let pid = prepared.pid();
        let scope = directory.join(&id.invocation);
        let master = prepared.terminal().unwrap().try_clone_to_owned().unwrap();
        quiescent(&prepared, &directory);
        job_topology(&master, pid, id.guardian_pid, id.guardian_pid, false);
        let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
        if finish == "journal" {
            store.db.busy_timeout(Duration::from_millis(20)).unwrap();
            blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        }
        let nonce = *Uuid::new_v4().as_bytes();
        let start = prepared.start_after(nonce, |child| {
            journal_while_gated(&mut store, &run, child, &directory, &id)?;
            job_topology(&master, child, id.guardian_pid, id.guardian_pid, false);
            assert!(!scope.join("final-exec").exists());
            let mut output = [rustix::event::PollFd::new(
                &master,
                rustix::event::PollFlags::IN,
            )];
            assert_eq!(
                rustix::event::poll(
                    &mut output,
                    Some(&rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                )
                .unwrap(),
                0
            );
            Ok::<(), Error>(())
        });
        if finish == "journal" {
            let failure = match start {
                Err(failure) => failure,
                Ok(_) => panic!("journal conflict released job GO"),
            };
            assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
            assert!(
                matches!(failure.cause, StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
                if error.code == rusqlite::ErrorCode::DatabaseBusy)
            );
            assert!(
                failure
                    .closed
                    .retire()
                    .unwrap()
                    .connection_close_error
                    .is_none()
            );
            assert_eq!(
                fs::read_to_string(scope.join("guardian-withdrawn-before-go")).unwrap(),
                id.invocation
            );
            assert!(!scope.join("final-exec").exists());
            terminal_retired(&master, false);
            blocker.execute_batch("ROLLBACK").unwrap();
        } else {
            let mut running = start.unwrap();
            let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                terminal_output(&master, b"\x1b[0m\r\n"),
                format!("\x1b[32mREADY:{pid}:{nonce}:→\x1b[0m\r\n").as_bytes()
            );
            assert_eq!(
                fs::read_to_string(scope.join("final-exec")).unwrap(),
                format!("{pid}:{nonce}")
            );
            job_topology(&master, pid, id.guardian_pid, pid, false);
            let witness =
                aswp_linux_manager_evaluation::journal_client::Witness::bind(&prefix, &id, pid)
                    .unwrap();
            terminal_input(&master, b"spawn\n");
            let child_line = terminal_output(&master, b"\r\n");
            // Echo may be delivered before the target's readiness response.
            let child_line = if child_line == b"spawn\r\n" {
                terminal_output(&master, b"\r\n")
            } else {
                child_line.strip_prefix(b"spawn\r\n").unwrap().to_vec()
            };
            let child: u32 = std::str::from_utf8(&child_line)
                .unwrap()
                .strip_prefix("CHILD:")
                .unwrap()
                .strip_suffix("\r\n")
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                fs::read_to_string(scope.join("descendant-ready")).unwrap(),
                child.to_string()
            );
            let descendant_fd = rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(child as i32).unwrap(),
                rustix::process::PidfdFlags::empty(),
            )
            .unwrap();
            descendant_state(child, pid, &id, false);
            let mut child_watch = [rustix::event::PollFd::new(
                &descendant_fd,
                rustix::event::PollFlags::IN,
            )];
            assert_eq!(
                rustix::event::poll(
                    &mut child_watch,
                    Some(&rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                )
                .unwrap(),
                0
            );
            descendant_heartbeat(&scope, None);
            if finish == "resume" {
                nested_job_stays_inside_target(&master, &scope, pid, &id, &mut running);
            }
            assert!(running.resume().is_err(), "resume accepted without a stop");
            if finish != "hangup-running" {
                terminal_input(&master, b"\x1a");
                assert_eq!(running.wait_stopped().unwrap(), 20);
                assert_eq!(terminal_output(&master, b"^Z"), b"^Z");
                job_topology(&master, pid, id.guardian_pid, pid, true);
                descendant_state(child, pid, &id, true);
                let paused = descendant_heartbeat(&scope, None);
                thread::sleep(Duration::from_millis(100));
                assert_eq!(descendant_heartbeat(&scope, None), paused);
                assert!(
                    running.wait_stopped().is_err(),
                    "accepted another stop while one is pending"
                );
                assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
            }
            if finish == "resume" {
                let paused = descendant_heartbeat(&scope, None);
                running.resume().unwrap();
                terminal_input(&master, b"size\n");
                assert_eq!(
                    terminal_output(&master, b"SIZE:24:80\r\n"),
                    b"size\r\nSIZE:24:80\r\n"
                );
                descendant_state(child, pid, &id, false);
                descendant_heartbeat(&scope, Some(&paused));
                terminal_input(&master, b"suspend\n");
                assert_eq!(
                    terminal_output(&master, b"SUSPEND>"),
                    b"suspend\r\nSUSPEND>"
                );
                assert_eq!(running.wait_stopped().unwrap(), 20);
                job_topology(&master, pid, id.guardian_pid, pid, true);
                // Self-suspension stops this process, not every writer. The
                // descendant keeps running, so stop notices are not quiescence.
                let previous = descendant_heartbeat(&scope, None);
                descendant_heartbeat(&scope, Some(&previous));
                assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
                running.resume().unwrap();
                assert_eq!(terminal_output(&master, b"RESUMED\r\n"), b"RESUMED\r\n");
                terminal_input(&master, b"size\n");
                assert_eq!(
                    terminal_output(&master, b"SIZE:24:80\r\n"),
                    b"size\r\nSIZE:24:80\r\n"
                );
                terminal_input(&master, b"\x03");
                let until = Instant::now() + Duration::from_secs(4);
                while !scope.join("target-exit").exists() {
                    assert!(Instant::now() < until, "resumed target did not interrupt");
                    thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    fs::read_to_string(scope.join("target-exit")).unwrap(),
                    "None:Some(2)"
                );
            }
            if finish.starts_with("hangup-") {
                running.close_terminal_for_fixture().unwrap();
                drop(master);
                // The activation control connection remains open. Its EOF
                // therefore cannot explain the observed terminal-loss path.
                assert!(witness.retire().unwrap().connection_close_error.is_none());
                assert_eq!(
                    fs::read_to_string(scope.join("guardian-terminal-hangup")).unwrap(),
                    id.invocation
                );
                assert!(!scope.join("guardian-clean-eof").exists());
                assert!(
                    running
                        .close()
                        .retire()
                        .unwrap()
                        .connection_close_error
                        .is_none()
                );
            } else {
                let closed = if finish == "guardian" {
                    running.crash_guardian().unwrap()
                } else {
                    running.close()
                };
                assert!(closed.retire().unwrap().connection_close_error.is_none());
                assert!(witness.retire().unwrap().connection_close_error.is_none());
                terminal_retired(&master, finish == "resume");
                if finish == "disconnect" {
                    assert_eq!(
                        fs::read_to_string(scope.join("guardian-clean-eof")).unwrap(),
                        id.invocation
                    );
                    assert!(!scope.join("target-exit").exists());
                } else {
                    assert!(!scope.join("guardian-clean-eof").exists());
                }
            }
            let mut child_watch = [rustix::event::PollFd::new(
                &descendant_fd,
                rustix::event::PollFlags::IN,
            )];
            assert_eq!(
                rustix::event::poll(
                    &mut child_watch,
                    Some(&rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                )
                .unwrap(),
                1
            );
            assert!(
                child_watch[0]
                    .revents()
                    .contains(rustix::event::PollFlags::IN)
            );
            assert!(!scope.join("descendant-voluntary-exit").exists());
            let retired = descendant_heartbeat(&scope, None);
            thread::sleep(Duration::from_millis(100));
            assert_eq!(descendant_heartbeat(&scope, None), retired);
        }
        unresolved(&store, profile, &run);
        drop(blocker);
        drop(store);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile, &run);
        assert_eq!(
            reopened.run(&run).unwrap().observed_pid,
            if finish == "journal" { None } else { Some(pid) }
        );
        assert!(reopened.verify().unwrap().consistent);
    }
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn actual_lease_and_journal_gate_two_independent_activations() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let started = Instant::now();
    let (profile_a, run_a, a) = prepare(&mut store, "activation-a", &prefix);
    let id_a = a.identity();
    assert!(!directory.join(&id_a.invocation).join("heartbeat").exists());
    let pid_a = a.pid();
    quiescent(&a, &directory);
    let nonce_a = *Uuid::new_v4().as_bytes();
    let a = a
        .start_after(nonce_a, |pid| {
            journal_while_gated(&mut store, &run_a, pid, &directory, &id_a)
        })
        .unwrap();
    heartbeat(&directory, &id_a, pid_a, &nonce_a, None);
    let (profile_b, run_b, b) = prepare(&mut store, "activation-b", &prefix);
    let id_b = b.identity();
    assert_ne!(id_a.invocation, id_b.invocation);
    assert_ne!(id_a.unit, id_b.unit);
    assert_ne!(
        (id_a.directory_device, id_a.directory_inode),
        (id_b.directory_device, id_b.directory_inode)
    );
    assert!(!directory.join(&id_b.invocation).join("heartbeat").exists());
    let pid_b = b.pid();
    quiescent(&b, &directory);
    let nonce_b = *Uuid::new_v4().as_bytes();
    let b = b
        .start_after(nonce_b, |pid| {
            journal_while_gated(&mut store, &run_b, pid, &directory, &id_b)
        })
        .unwrap();
    heartbeat(&directory, &id_b, pid_b, &nonce_b, None);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(a.close().retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile_a, &run_a);
    let before = heartbeat(&directory, &id_b, pid_b, &nonce_b, None);
    heartbeat(&directory, &id_b, pid_b, &nonce_b, Some(&before));
    assert!(matches!(store.acquire_lease(profile_b), Err(Error::Busy)));
    assert!(b.close().retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile_b, &run_b);
    for id in [&id_a, &id_b] {
        assert!(
            !directory
                .join(&id.invocation)
                .join("voluntary-exit")
                .exists()
        );
        assert_eq!(
            fs::read_to_string(directory.join(&id.invocation).join("guardian-clean-eof")).unwrap(),
            id.invocation
        );
    }
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile_a, &run_a);
    unresolved(&reopened, profile_b, &run_b);
    assert_eq!(reopened.run(&run_a).unwrap().observed_pid, Some(pid_a));
    assert_eq!(reopened.run(&run_b).unwrap().observed_pid, Some(pid_b));
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated journal::two distinct invocations kept real leases, journaled PID before nonce-bound GO, retired independently and retained unresolved intent after reopening"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn sqlite_write_failure_withholds_go_and_keeps_unresolved_intent() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "activation-busy", &prefix);
    let id = prepared.identity();
    quiescent(&prepared, &directory);
    store.db.busy_timeout(Duration::from_millis(20)).unwrap();
    let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let failure = match prepared.start_after(*Uuid::new_v4().as_bytes(), |pid| {
        store.observe_spawn(&run, pid)
    }) {
        Err(failure) => failure,
        Ok(_) => panic!("journal failure unexpectedly released GO"),
    };
    assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
    let result = failure.cause;
    assert!(
        matches!(result, StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
        if error.code == rusqlite::ErrorCode::DatabaseBusy),
        "unexpected journal failure: {result:?}"
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    assert!(
        failure
            .closed
            .retire()
            .unwrap()
            .connection_close_error
            .is_none()
    );
    assert_eq!(
        fs::read_to_string(
            directory
                .join(&id.invocation)
                .join("guardian-withdrawn-before-go")
        )
        .unwrap(),
        id.invocation
    );
    unresolved(&store, profile, &run);
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile, &run);
    assert_eq!(reopened.run(&run).unwrap().observed_pid, None);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated journal refusal::actual SQLite BUSY withheld GO; gated child retired without heartbeat and unresolved intent survived reopening"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn invalid_or_independently_locked_lease_never_spawns_writer() {
    use std::os::unix::fs::PermissionsExt;
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    for reason in ["metadata", "locked"] {
        let profile = store
            .register(Harness::Claude, format!("lease-{reason}").parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let bound = Bound::connect(&prefix).unwrap();
        let id = bound.identity();
        let run = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: Uuid::new_v4() }),
            )
            .unwrap();
        let wrong = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        if reason == "metadata" {
            wrong
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))
                .unwrap();
        } else {
            wrong.as_file().try_lock().unwrap();
        }
        let independent = File::open(wrong.path()).unwrap();
        let failure = match bound.prepare(independent.as_fd()) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid lease spawned a writer"),
        };
        assert!(!directory.join(&id.invocation).exists());
        assert_eq!(
            fs::read_to_string(directory.join(format!("{}.lease-refused", id.invocation))).unwrap(),
            reason
        );
        drop(lease);
        assert!(
            failure
                .closed
                .retire()
                .unwrap()
                .connection_close_error
                .is_none()
        );
        unresolved(&store, profile.id, &run);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile.id, &run);
        assert_eq!(reopened.run(&run).unwrap().observed_pid, None);
        assert!(reopened.verify().unwrap().consistent);
    }
    println!(
        "::notice title=Linux activated lease refusal::invalid metadata and independently locked lease refused before writer creation; real planned runs remain unresolved"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn guardian_sigkill_retires_writer_without_clearing_journal() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "guardian-crash", &prefix);
    let id = prepared.identity();
    let writer = prepared.pid();
    let nonce = *Uuid::new_v4().as_bytes();
    let running = prepared
        .start_after(nonce, |pid| store.observe_spawn(&run, pid))
        .unwrap();
    let before = heartbeat(&directory, &id, writer, &nonce, None);
    heartbeat(&directory, &id, writer, &nonce, Some(&before));
    assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
    // This signal is sent before the sole client channel is closed. No
    // guardian destructor or cooperative EOF path can be responsible.
    let closed = match running.crash_guardian() {
        Ok(closed) => closed,
        Err(failure) => {
            let reason = failure.error.to_string();
            let retirement = failure.closed.retire();
            panic!(
                "guardian fault refused: {reason}; retirement error: {:?}",
                retirement.err()
            );
        }
    };
    assert!(closed.retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile, &run);
    assert!(
        !directory
            .join(&id.invocation)
            .join("guardian-clean-eof")
            .exists()
    );
    assert!(
        !directory
            .join(&id.invocation)
            .join("voluntary-exit")
            .exists()
    );
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile, &run);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated guardian loss::SIGKILL requested through retained pidfd; original scope and writer retired; raw lock released but reopened journal still refuses launch"
    );
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientReport {
    profile: ProfileId,
    run: String,
    unit: String,
    invocation: String,
    guardian: u32,
    writer: u32,
    device: u64,
    inode: u64,
    nonce: [u8; 16],
}

const CLIENT_ROLE: &str = "store::linux_activated_journal_tests::client_crash_role";

#[test]
#[ignore = "private subprocess role for hosted activation client-loss fixture"]
fn client_crash_role() {
    let (prefix, directory) = environment();
    let root = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_CLIENT_ROOT").unwrap());
    let reports = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_REPORTS").unwrap());
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "client-crash", &prefix);
    let id = prepared.identity();
    let writer = prepared.pid();

    let nonce = *Uuid::new_v4().as_bytes();
    let _running = prepared
        .start_after(nonce, |pid| store.observe_spawn(&run, pid))
        .unwrap();
    heartbeat(&directory, &id, writer, &nonce, None);
    let report = ClientReport {
        profile,
        run,
        unit: id.unit,
        invocation: id.invocation,
        guardian: id.guardian_pid,
        writer,
        device: id.directory_device,
        inode: id.directory_inode,
        nonce,
    };
    fs::write(
        reports.join("client-ready.tmp"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    fs::rename(
        reports.join("client-ready.tmp"),
        reports.join("client-ready"),
    )
    .unwrap();
    thread::sleep(Duration::from_secs(60));
    fs::write(reports.join("client-voluntary"), "deadline").unwrap();
    panic!("client fault controller did not kill its owned child");
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn client_sigkill_retires_writer_without_running_client_cleanup() {
    use aswp_linux_manager_evaluation::journal_client::Witness;
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
    };
    use wait_timeout::ChildExt;
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait_timeout(Duration::from_secs(3));
        }
    }
    let (prefix, directory) = environment();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("state");
    let reports = temporary.path().join("reports");
    private_fs::directory(&reports, true).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CLIENT_ROLE, "--ignored", "--nocapture"])
        .env_clear()
        .env("ASWP_ACTIVATION_CLIENT_ROOT", &root)
        .env("ASWP_ACTIVATION_REPORTS", &reports)
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            File::create(temporary.path().join("client.stderr")).unwrap(),
        ));
    for key in [
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "ASWP_CI_ACTIVATED_JOURNAL",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "ASWP_ACTIVATION_PREFIX",
        "ASWP_ACTIVATION_DIRECTORY",
    ] {
        command.env(key, std::env::var_os(key).unwrap());
    }
    let mut client = Owned(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(15);
    while !reports.join("client-ready").exists() {
        assert!(
            client.0.try_wait().unwrap().is_none(),
            "client failed: {}",
            fs::read_to_string(temporary.path().join("client.stderr")).unwrap()
        );
        assert!(Instant::now() < deadline, "client readiness expired");
        thread::sleep(Duration::from_millis(10));
    }
    let bytes = fs::read(reports.join("client-ready")).unwrap();
    assert!(bytes.len() <= 4096);
    let report: ClientReport = serde_json::from_slice(&bytes).unwrap();
    let id = Identity {
        unit: report.unit.clone(),
        invocation: report.invocation.clone(),
        guardian_pid: report.guardian,
        directory_device: report.device,
        directory_inode: report.inode,
    };
    // No activation socket is duplicated into this controller. Its independent
    // witness corroborates every claim before the client is killed.
    let mut wrong = id.clone();
    wrong.invocation = Uuid::new_v4().simple().to_string();
    assert_eq!(
        Witness::bind(&prefix, &wrong, report.writer)
            .err()
            .unwrap()
            .to_string(),
        "invocation changed"
    );
    wrong = id.clone();
    wrong.directory_inode ^= 1;
    assert_eq!(
        Witness::bind(&prefix, &wrong, report.writer)
            .err()
            .unwrap()
            .to_string(),
        "independent manager/kernel facts differ from claims"
    );
    assert_eq!(
        Witness::bind(&prefix, &id, std::process::id())
            .err()
            .unwrap()
            .to_string(),
        "main process is outside the bound cgroup"
    );
    assert_eq!(
        Witness::bind(&prefix, &id, report.guardian)
            .err()
            .unwrap()
            .to_string(),
        "writer is not the bound guardian's direct child"
    );
    let witness = Witness::bind(&prefix, &id, report.writer).unwrap();
    let store = Store::open(&root).unwrap();
    assert_eq!(
        store.run(&report.run).unwrap().observed_pid,
        Some(report.writer)
    );
    assert!(matches!(
        store.acquire_lease(report.profile),
        Err(Error::Busy)
    ));
    let before = heartbeat(&directory, &id, report.writer, &report.nonce, None);
    heartbeat(&directory, &id, report.writer, &report.nonce, Some(&before));
    assert!(
        !directory
            .join(&id.invocation)
            .join("guardian-clean-eof")
            .exists()
    );
    client.0.kill().unwrap();
    let status = client
        .0
        .wait_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(status.signal(), Some(9));
    assert!(witness.retire().unwrap().connection_close_error.is_none());
    assert_eq!(
        fs::read_to_string(directory.join(&id.invocation).join("guardian-clean-eof")).unwrap(),
        id.invocation
    );
    assert!(
        !directory
            .join(&id.invocation)
            .join("voluntary-exit")
            .exists()
    );
    assert!(!reports.join("client-voluntary").exists());
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, report.profile, &report.run);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated client loss::owned client SIGKILL ran no client cleanup; independent witnesses observed writer retirement and reopened unresolved journal still refuses launch"
    );
}
