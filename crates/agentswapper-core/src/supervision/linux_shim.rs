//! Internal pre-exec entry for the experimental Linux guardian under development.
use rustix::fs::fstatfs;
use std::{
    fs::File,
    io,
    os::fd::AsFd,
    os::unix::process::CommandExt,
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};

use super::{
    linux_admission_transport as transport, linux_cgroup, linux_launch_envelope::LaunchEnvelope,
};

/// Private protocol selector shared by the CLI and the guardian.
#[doc(hidden)]
pub const INTERNAL_ARG: &str = "__agentswapper_internal_linux_shim_v1";

fn validate_stream(stream: &File) -> io::Result<()> {
    // A cgroup control file opened outside a future namespace can retain the
    // opening namespace's migration authority when passed as a standard fd.
    // Refuse both cgroup filesystem types, without assuming this is a sandbox.
    let kind = fstatfs(stream)?.f_type;
    if kind == 0x6367_7270 || kind == 0x0027_e0eb {
        return Err(io::Error::other(
            "cgroup control files cannot be standard streams",
        ));
    }
    Ok(())
}

/// Internal CLI entry. The standard input must be the guardian's private
/// admission socket; invalid capabilities or a missing GO refuse execution.
/// This is not a standalone containment API or a production stop receipt.
#[doc(hidden)]
pub fn run_stdio(scope: &Path) -> io::Result<()> {
    exec_until(io::stdin(), scope, Instant::now() + Duration::from_secs(30))
}

/// Receive capabilities, launch data and standard streams, then require GO.
/// The caller must start this helper in a neutral environment and keep it in
/// the intended cgroup until exec. Every receive shares one startup deadline.
pub(crate) fn exec_until(channel: impl AsFd, scope: &Path, deadline: Instant) -> io::Result<()> {
    let parent = File::from(transport::receive_until(&channel, deadline)?);
    let leaf = File::from(transport::receive_until(&channel, deadline)?);
    linux_cgroup::validate_admitted(&parent, &leaf, scope)?;
    let launch = LaunchEnvelope::receive_from_until(&channel, deadline)?;
    let input = File::from(transport::receive_until(&channel, deadline)?);
    let output = File::from(transport::receive_until(&channel, deadline)?);
    let diagnostic = File::from(transport::receive_until(&channel, deadline)?);
    transport::receive_control_until(&channel, transport::GO, deadline)?;
    for stream in [&input, &output, &diagnostic] {
        validate_stream(stream)?;
    }
    linux_cgroup::validate_admitted(&parent, &leaf, scope)?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "guardian startup deadline expired",
        ));
    }
    // This role is entered as a fresh, single-threaded CLI process. Mark
    // inherited descriptors for closure at exec, including descriptors opened
    // before the guardian existed. Keep them usable during exec preparation;
    // Command will duplicate the validated streams onto descriptors 0..2.
    fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
    let error = launch
        .command()
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(diagnostic))
        .exec();
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs,
        os::fd::{AsFd, AsRawFd},
        process::Command,
        time::Duration,
    };
    use wait_timeout::ChildExt;

    #[test]
    fn standard_stream_validation_refuses_cgroup_files() -> io::Result<()> {
        validate_stream(&tempfile::tempfile()?)?;
        let (first, second) = transport::pair()?;
        validate_stream(&File::from(first))?;
        validate_stream(&File::from(second))?;
        if let Ok(cgroup_file) = File::open("/sys/fs/cgroup/cgroup.controllers") {
            assert!(validate_stream(&cgroup_file).is_err());
        }
        Ok(())
    }

    fn receiver_role() -> String {
        let path = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, path)| path);
        format!("{path}::refusing_shim_fixture")
    }

    fn cloexec_role() -> String {
        let path = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, path)| path);
        format!("{path}::cloexec_process_fixture")
    }

    #[test]
    #[ignore = "subprocess role for inherited descriptor exec test"]
    fn cloexec_process_fixture() -> io::Result<()> {
        let path =
            std::env::var_os("ASWP_FD_CANARY").ok_or_else(|| io::Error::other("missing canary"))?;
        if let Some(fd) = std::env::var_os("ASWP_FD_NUMBER") {
            let fd = fd.to_string_lossy();
            let inherited = fs::read_link(format!("/proc/self/fd/{fd}")).ok();
            assert_ne!(inherited.as_deref(), Some(Path::new(&path)));
            fs::write(Path::new(&path).with_extension("done"), b"done")?;
            return Ok(());
        }
        let file = File::open(&path)?;
        let inherited = fuxix::io::duplicate_inheritable(&file).map_err(io::Error::from)?;
        assert!(!rustix::io::fcntl_getfd(&inherited)?.contains(rustix::io::FdFlags::CLOEXEC));
        let number = inherited.as_raw_fd().to_string();
        fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
        assert!(rustix::io::fcntl_getfd(&inherited)?.contains(rustix::io::FdFlags::CLOEXEC));
        let executable = std::env::current_exe()?;
        Err(Command::new(executable)
            .args(["--exact", &cloexec_role(), "--ignored"])
            .env("ASWP_FD_NUMBER", number)
            .exec())
    }

    #[test]
    fn inherited_descriptors_do_not_cross_exec() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let canary = temp.path().join("canary");
        fs::write(&canary, b"data")?;
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", &cloexec_role(), "--ignored"])
            .env("ASWP_FD_CANARY", &canary)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let status = child.wait_timeout(Duration::from_secs(10))?;
        if status.is_none() {
            child.kill()?;
            child.wait()?;
        }
        assert!(status.is_some_and(|status| status.success()));
        assert!(canary.with_extension("done").exists());
        Ok(())
    }

    #[test]
    #[ignore = "shim role invoked by the invalid-scope subprocess test"]
    fn refusing_shim_fixture() {
        let scope = Path::new("aswp-probe-00000000-0000-4000-8000-000000000001");
        assert!(exec_until(io::stdin(), scope, Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn invalid_scope_never_executes_queued_target() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let parent = File::open(temp.path())?;
        let child_dir = temp.path().join("child");
        fs::create_dir(&child_dir)?;
        let leaf = File::open(child_dir)?;
        let marker = temp.path().join("executed");
        let envelope = LaunchEnvelope::capture(
            "/bin/sh".as_ref(),
            Path::new("/"),
            [
                OsString::from("-c"),
                OsString::from("printf x > \"$MARKER\""),
            ],
            [],
            [(
                OsString::from("MARKER"),
                Some(marker.as_os_str().to_owned()),
            )],
        )?;
        let (channel, receiver) = transport::pair()?;
        transport::send(&channel, transport::GO, &[parent.as_fd()])?;
        transport::send(&channel, transport::GO, &[leaf.as_fd()])?;
        envelope.send_to(&channel)?;
        let input = File::open("/dev/null")?;
        for _ in 0..3 {
            transport::send(&channel, transport::GO, &[input.as_fd()])?;
        }
        transport::send(&channel, transport::GO, &[])?;
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", &receiver_role(), "--ignored"])
            .stdin(Stdio::from(receiver))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        drop(channel);
        let status = child.wait_timeout(Duration::from_secs(10))?;
        if status.is_none() {
            child.kill()?;
            child.wait()?;
        }
        assert!(status.is_some_and(|status| status.success()));
        assert!(!marker.exists());
        Ok(())
    }
}
