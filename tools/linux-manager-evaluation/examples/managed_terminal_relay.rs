//! Fixed hosted terminal fixture with the synced-file journal consumer.
#![forbid(unsafe_code)]
use aswp_linux_manager_evaluation::managed_terminal_relay::{self, FileJournal};
fn main() -> std::process::ExitCode {
    managed_terminal_relay::entry::<FileJournal>()
}
