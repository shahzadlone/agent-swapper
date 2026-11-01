//! Fixed native CI terminal consumer using the real Store and profile lease.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use agentswapper_core::store::qualification::FixtureJournal;
    use aswp_linux_manager_evaluation::managed_terminal_relay::{self, AdmissionJournal};
    use std::{io, os::fd::BorrowedFd, path::Path};
    struct Journal(FixtureJournal);
    impl AdmissionJournal for Journal {
        fn open(directory: &Path) -> io::Result<Self> {
            FixtureJournal::open(directory)
                .map(Self)
                .map_err(io::Error::other)
        }
        fn lease(&self) -> io::Result<BorrowedFd<'_>> {
            self.0.lease().map_err(io::Error::other)
        }
        fn bind_scope(&mut self, key: agentswapper_linux_manager::ServiceKey) -> io::Result<()> {
            self.0.bind_scope(key).map_err(io::Error::other)
        }
        fn confirm_intent(&mut self, pid: u32) -> io::Result<()> {
            self.0.confirm_intent(pid).map_err(io::Error::other)
        }
        fn observe_spawn(&mut self, pid: u32) -> io::Result<()> {
            self.0.observe_spawn(pid).map_err(io::Error::other)
        }
        fn release_lease(&mut self) {
            self.0.release_lease();
        }
        fn audit_retired(
            &mut self,
            retired: agentswapper_linux_manager::RetiredService,
        ) -> io::Result<()> {
            self.0.audit_retired(retired).map_err(io::Error::other)
        }
    }
    managed_terminal_relay::entry::<Journal>()
}
#[cfg(not(target_os = "linux"))]
fn main() {
    println!("Linux-only, fixed-target journal qualification fixture.");
}
