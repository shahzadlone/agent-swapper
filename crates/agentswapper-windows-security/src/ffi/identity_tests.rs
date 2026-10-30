//! Explicit, ignored fixture for disposable GitHub-hosted Windows runners.
//! Creates only its own random local user; never accepts account names/passwords
//! from the environment, command line or a user's credential store.
#![allow(clippy::unwrap_used)]

use super::*;
use std::{io::Write, marker::PhantomData, os::windows::fs::OpenOptionsExt, rc::Rc};
use windows_sys::Win32::{
    NetworkManagement::NetManagement::{
        NetUserAdd, NetUserDel, UF_NORMAL_ACCOUNT, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
    },
    Security::{
        ImpersonateLoggedOnUser, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
        RevertToSelf,
    },
    Storage::FileSystem::{DELETE, WRITE_DAC, WRITE_OWNER},
};
use zeroize::Zeroizing;

struct FixtureAccount {
    name: Vec<u16>,
    active: bool,
}

impl FixtureAccount {
    fn create() -> io::Result<(Self, OwnedHandle)> {
        // This guard is inside the mutating helper, not only the test runner.
        for (key, expected) in [
            ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("RUNNER_OS", "Windows"),
            ("GITHUB_REPOSITORY", "shahzadlone/agent-swapper"),
            ("ASWP_CI_IDENTITY_FIXTURE", "1"),
        ] {
            if std::env::var(key).ok().as_deref() != Some(expected) {
                return Err(io::Error::other(
                    "identity fixture requires explicit disposable Windows CI execution",
                ));
            }
        }
        let mut nonce = [0_u8; 6];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut name = String::from("aswp-");
        for byte in nonce {
            name.push_str(&format!("{byte:02x}"));
        }
        let mut name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut entropy = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *entropy).map_err(io::Error::other)?;
        let mut password = Zeroizing::new(Vec::with_capacity(69));
        password.extend("Aa!9".encode_utf16());
        for byte in entropy.iter() {
            for nibble in [byte >> 4, byte & 15] {
                password.push(u16::from(b"0123456789abcdef"[usize::from(nibble)]));
            }
        }
        password.push(0);
        let info = USER_INFO_1 {
            usri1_name: name.as_mut_ptr(),
            usri1_password: password.as_mut_ptr(),
            usri1_priv: USER_PRIV_USER,
            usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT,
            ..Default::default()
        };
        // SAFETY: level 1 matches the initialized USER_INFO_1, whose strings
        // remain live and NUL-terminated. Null server means local machine only.
        // A non-admin user is added, with no group/privilege changes requested.
        let status =
            unsafe { NetUserAdd(null(), 1, (&info as *const USER_INFO_1).cast(), null_mut()) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // Ownership begins only after successful creation. A name collision
        // above never creates a cleanup guard for somebody else's account.
        let account = Self { name, active: true };
        let domain = [u16::from(b'.'), 0];
        let mut token = null_mut();
        // SAFETY: live NUL-terminated local username/domain/password and a
        // writable handle output. The password is never printed or persisted
        // by this fixture and both its buffers zeroize when this scope ends.
        if unsafe {
            LogonUserW(
                account.name.as_ptr(),
                domain.as_ptr(),
                password.as_ptr(),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if token.is_null() || token == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("identity fixture received no logon token"));
        }
        // SAFETY: successful LogonUserW transferred this real token handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        Ok((account, token))
    }

    fn remove(mut self) -> io::Result<()> {
        // SAFETY: this exact random local account was successfully created by
        // this guard. The NUL-terminated name is owned; no remote server used.
        let status = unsafe { NetUserDel(null(), self.name.as_ptr()) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for FixtureAccount {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: same ownership invariant as remove(); covers login/test
            // errors and panic unwinding without touching preexisting accounts.
            let status = unsafe { NetUserDel(null(), self.name.as_ptr()) };
            if status != 0 {
                eprintln!(
                    "::error title=Windows ACL fixture cleanup::owned temporary account removal failed with OS code {status}"
                );
            }
        }
    }
}

// This guard cannot move between threads. Restoration must occur on the thread
// whose identity it changed, including during an assertion's panic unwind.
struct RestoreIdentity(PhantomData<Rc<()>>);

impl Drop for RestoreIdentity {
    fn drop(&mut self) {
        // SAFETY: revert the identity of the current fixture thread. A failure
        // must not continue executing code under an uncertain user identity.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn denied<T>(result: io::Result<T>, operation: &str) {
    match result {
        Err(error) if error.raw_os_error() == Some(5) => {}
        Err(error) => panic!("{operation}: expected access denied, got {error}"),
        Ok(_) => panic!("{operation}: another user unexpectedly received access"),
    }
}

#[test]
#[ignore = "creates/removes a disposable local account; explicit GitHub-hosted Windows CI only"]
fn separate_identity_cannot_access_private_objects() {
    let (account, token) = FixtureAccount::create().unwrap();
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    // Everyone can read/traverse this parent, but cannot delete children. A
    // permissive control file proves the new user can actually reach the tree.
    let parent_sd = LocalDescriptor::from_sddl(&format!(
        "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;WD)",
        policy.owner.sddl(),
        policy.owner.sddl()
    ))
    .unwrap();
    let parent_path = root.path().join("fixture");
    let parent = create(&parent_path, ObjectKind::Directory, &parent_sd).unwrap();
    let control_sd =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;;FA;;;WD)", policy.owner.sddl())).unwrap();
    let control_path = parent_path.join("control.txt");
    let mut control = create(&control_path, ObjectKind::File, &control_sd).unwrap();
    control.write_all(b"public fixture control").unwrap();
    drop(control);
    let private_path = parent_path.join("private.txt");
    let mut private = policy.create_new(&private_path, ObjectKind::File).unwrap();
    private.write_all(b"private fixture canary").unwrap();
    drop(private);
    let private_directory = parent_path.join("private-directory");
    let directory = policy
        .create_new(&private_directory, ObjectKind::Directory)
        .unwrap();
    let mut nested = policy
        .create_new_at(&directory, OsStr::new("nested.txt"), ObjectKind::File)
        .unwrap();
    nested.write_all(b"nested fixture canary").unwrap();
    drop(nested);
    drop(directory);
    drop(parent);

    let control_for_thread = control_path.clone();
    let private_for_thread = private_path.clone();
    let directory_for_thread = private_directory.clone();
    let checked = std::thread::spawn(move || {
        // SAFETY: token is the owned result of this fixture's explicit local
        // login. Check success before any access attempt, then immediately arm
        // thread-bound restoration. No privileged handle is passed to probes.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        let restore = RestoreIdentity(PhantomData);
        assert_eq!(
            std::fs::read(&control_for_thread).unwrap(),
            b"public fixture control"
        );
        std::fs::write(&control_for_thread, b"other user control write").unwrap();
        denied(File::open(&private_for_thread), "read private file");
        denied(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&private_for_thread),
            "write private file",
        );
        for access in [WRITE_DAC, WRITE_OWNER, DELETE] {
            denied(
                std::fs::OpenOptions::new()
                    .access_mode(access)
                    .open(&private_for_thread),
                "open private security/delete rights",
            );
        }
        denied(
            std::fs::remove_file(&private_for_thread),
            "delete private file",
        );
        denied(
            std::fs::rename(
                &private_for_thread,
                private_for_thread.with_extension("moved"),
            ),
            "rename private file",
        );
        denied(
            std::fs::read_dir(&directory_for_thread),
            "list private directory",
        );
        denied(
            File::create(directory_for_thread.join("injected.txt")),
            "create private child",
        );
        denied(
            File::open(directory_for_thread.join("nested.txt")),
            "read nested private file",
        );
        denied(
            std::fs::remove_file(directory_for_thread.join("nested.txt")),
            "delete nested private file",
        );
        drop(restore);
        drop(token);
    })
    .join();
    // Delete the account even if an access assertion failed. The logon token
    // and impersonation guard are gone before this explicit cleanup.
    account.remove().unwrap();
    checked.unwrap();
    assert_eq!(
        std::fs::read(control_path).unwrap(),
        b"other user control write"
    );
    assert_eq!(
        std::fs::read(private_path).unwrap(),
        b"private fixture canary"
    );
    assert_eq!(
        std::fs::read(private_directory.join("nested.txt")).unwrap(),
        b"nested fixture canary"
    );
    assert!(!private_directory.join("injected.txt").exists());
    println!(
        "::notice title=Windows ACL separate identity::temporary standard user read/wrote the permissive control but was denied private reads, writes, security changes, deletion, rename, listing and child creation; original bytes preserved and owned account removed"
    );
}
