//! Loaded service lifecycle checks, separate from installation and kernel custody.
use crate::linux::{Manager, SERVICE_INTERFACE, property, require};
use std::io;

struct Lifecycle {
    service_type: String,
    pid_file: String,
    notify: String,
    remain: bool,
    pam: String,
    restart: String,
}
impl Lifecycle {
    fn require_direct(&self) -> io::Result<()> {
        require(
            self.service_type == "exec"
                && self.pid_file.is_empty()
                && self.notify == "none"
                && !self.remain
                && self.pam.is_empty()
                && self.restart == "no",
            "service lifecycle differs from direct manager-owned execution",
        )
    }
}

/// Require Type=exec with no PIDFile, notification ownership, retained-active
/// state, automatic restart or PAM session. PAM can move descendants into a
/// separate session scope; automatic restart creates another invocation.
/// Use an already bound invocation path and a caller-owned operation deadline.
/// This read does not establish installation, UID, cgroup policy or retirement.
pub async fn require_direct_lifecycle(
    connection: &Manager,
    sender: &str,
    path: &zbus::OwnedObjectPath,
) -> io::Result<()> {
    connection.require_sender(sender)?;
    let text = async |name| -> io::Result<String> {
        String::try_from(property(connection, sender, path, SERVICE_INTERFACE, name).await?)
            .map_err(io::Error::other)
    };
    Lifecycle {
        service_type: text("Type").await?,
        pid_file: text("PIDFile").await?,
        notify: text("NotifyAccess").await?,
        remain: bool::try_from(
            property(
                connection,
                sender,
                path,
                SERVICE_INTERFACE,
                "RemainAfterExit",
            )
            .await?,
        )
        .map_err(io::Error::other)?,
        pam: text("PAMName").await?,
        restart: text("Restart").await?,
    }
    .require_direct()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indirect_ownership_and_pam_sessions_refuse_admission() -> io::Result<()> {
        let direct = || Lifecycle {
            service_type: "exec".into(),
            pid_file: String::new(),
            notify: "none".into(),
            remain: false,
            pam: String::new(),
            restart: "no".into(),
        };
        direct().require_direct()?;
        for mutation in 0..9 {
            let mut observed = direct();
            match mutation {
                0 => observed.service_type = "forking".into(),
                1 => observed.pid_file = "/run/other.pid".into(),
                2 => observed.notify = "main".into(),
                3 => observed.notify = "all".into(),
                4 => observed.remain = true,
                5 => observed.pam = "login".into(),
                6 => observed.pam = " ".into(),
                7 => observed.restart = "always".into(),
                _ => observed.restart = "on-failure".into(),
            }
            assert!(observed.require_direct().is_err());
        }
        Ok(())
    }
}
