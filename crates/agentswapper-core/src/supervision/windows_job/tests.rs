#![allow(clippy::unwrap_used)]
use super::*;
use process_wrap::std::CommandWrapper;
use std::{fs, path::Path, process::Stdio};

#[derive(Debug)]
struct RefuseWrapping;

impl CommandWrapper for RefuseWrapping {
    fn wrap_child(
        &mut self,
        _child: Box<dyn ChildWrapper>,
        _core: &CommandWrap,
    ) -> io::Result<Box<dyn ChildWrapper>> {
        // Intentionally drop a plain std Child without killing it. The outer
        // backend's kill-on-close must own cleanup after callback success.
        Err(io::Error::other("injected failure after admission"))
    }
}

fn command(marker: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.env_clear();
    for key in ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .args([
            "--exact",
            "supervision::windows_job::tests::fixture_entry",
            "--ignored",
        ])
        .env("ASWP_FIXTURE_MARKER", marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn empty(observer: &Job) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !observer.query_process_id_list().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "admitted process leaked on an error path"
        );
        thread::sleep(POLL);
    }
}

#[test]
#[ignore = "fixture entry invoked by Windows supervision failure tests"]
fn fixture_entry() {
    let marker = std::env::var_os("ASWP_FIXTURE_MARKER").unwrap();
    fs::write(marker, "target executed").unwrap();
    thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "fixture supervisor invoked by the root Job crash test"]
fn root_gap_supervisor() {
    let dir = std::path::PathBuf::from(std::env::var_os("ASWP_ROOT_GAP_DIR").unwrap());
    fs::write(dir.join("ready"), b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !dir.join("go").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(POLL);
    }
    install_process_root().unwrap();
    let mut configured = CommandWrap::from(command(&dir.join("executed")));
    configured.wrap(JobObject);
    let _: io::Result<Box<dyn ChildWrapper>> = configured.spawn_with(|command| {
        let child = command.spawn()?;
        // This is the same suspended-create / per-run assignment interval as
        // the backend. The controller kills this process while it holds Child.
        fs::write(dir.join("suspended"), child.id().to_string())?;
        loop {
            thread::sleep(POLL);
        }
    });
    panic!("suspended fixture unexpectedly returned");
}

#[test]
fn process_root_retires_child_if_supervisor_dies_before_per_run_assignment() {
    struct Supervisor(Child);
    impl Drop for Supervisor {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut limits = ExtendedLimitInfo::new();
    limits.limit_kill_on_job_close();
    // The outer observer's independent handle lets the controller measure
    // emptiness; its kill-on-close is only a failure-path cleanup backstop.
    let observer = Job::create_with_limit_info(&limits).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "supervision::windows_job::tests::root_gap_supervisor",
            "--ignored",
        ])
        .env("ASWP_ROOT_GAP_DIR", dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut supervisor = Supervisor(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(15);
    while !dir.path().join("ready").exists() {
        assert!(supervisor.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline, "supervisor did not become ready");
        thread::sleep(POLL);
    }
    observer
        .assign_process(supervisor.0.as_raw_handle() as isize)
        .unwrap();
    fs::write(dir.path().join("go"), b"go").unwrap();
    while !dir.path().join("suspended").exists() {
        assert!(supervisor.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline, "suspended child was not created");
        thread::sleep(POLL);
    }
    assert_eq!(observer.query_process_id_list().unwrap().len(), 2);
    assert!(!dir.path().join("executed").exists());
    supervisor.0.kill().unwrap();
    supervisor.0.wait().unwrap();
    empty(&observer);
    assert!(!dir.path().join("executed").exists());
}

#[test]
fn failure_after_admission_callback_cleans_suspended_target_without_execution() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("started");
    let observer = Job::create().unwrap();
    let mut configured = CommandWrap::from(command(&marker));
    configured.wrap(RefuseWrapping).wrap(JobObject);
    let mut admitted = false;
    let result = WindowsJob::create()
        .unwrap()
        .spawn_wrapped(configured, |child| {
            observer
                .assign_process(child.as_raw_handle() as isize)
                .map_err(job_error)?;
            assert_eq!(
                observer.query_process_id_list().unwrap(),
                [child.id() as usize]
            );
            admitted = true;
            Ok(())
        });
    assert!(admitted);
    assert!(result.is_err());
    empty(&observer);
    assert!(!marker.exists());
}

#[test]
fn rejection_and_unwind_drain_admitted_process_in_independent_kernel_observer() {
    for unwind in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("started");
        let observer = Job::create().unwrap();
        let mut configured = CommandWrap::from(command(&marker));
        configured.wrap(JobObject);
        let mut admitted = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            WindowsJob::create()
                .unwrap()
                .spawn_wrapped(configured, |child| {
                    observer
                        .assign_process(child.as_raw_handle() as isize)
                        .map_err(job_error)?;
                    admitted = true;
                    assert!(!unwind, "injected admission unwind");
                    Err(io::Error::other("injected admission refusal"))
                })
        }));
        assert!(admitted);
        match result {
            Ok(result) => {
                assert!(!unwind);
                assert!(result.is_err());
            }
            Err(_) => assert!(unwind),
        }
        empty(&observer);
        assert!(!marker.exists());
    }
}

#[test]
fn query_error_and_expired_cleanup_return_no_receipt_and_still_stop_scope() {
    for timeout in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("started");
        let observer = Job::create().unwrap();
        let mut configured = CommandWrap::from(command(&marker));
        configured.wrap(JobObject);
        let child = WindowsJob::create()
            .unwrap()
            .spawn_wrapped(configured, |native| {
                observer
                    .assign_process(native.as_raw_handle() as isize)
                    .map_err(job_error)
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "target never started");
            thread::sleep(POLL);
        }
        let pid = child.id() as usize;
        let result = child.stop_with(Instant::now(), |_| {
            if timeout {
                Ok(vec![pid])
            } else {
                Err(io::Error::other("injected membership query error"))
            }
        });
        let error = result.unwrap_err();
        assert_eq!(
            error.kind(),
            if timeout {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Other
            }
        );
        empty(&observer);
    }
}
