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
    Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle, WRITE_DAC,
        WRITE_OWNER,
    },
};
use zeroize::Zeroizing;

mod chain;
mod drive_alias;
mod publication;
mod registry;
mod remote_device;
mod reparse;

fn require_hosted_fixture() -> io::Result<()> {
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
    Ok(())
}

struct FixtureAccount {
    name: Vec<u16>,
    active: bool,
}

impl FixtureAccount {
    fn create() -> io::Result<(Self, OwnedHandle)> {
        // This guard is inside the mutating helper, not only the test runner.
        require_hosted_fixture()?;
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

fn guarded_deletion(result: io::Result<()>, operation: &str) {
    match result {
        Err(error) if matches!(error.raw_os_error(), Some(5 | 32)) => {
            println!(
                "::notice title=Windows ACL owned handle::{operation} refused with OS code {}",
                error.raw_os_error().unwrap()
            );
        }
        Err(error) => panic!("{operation}: unexpected failure {error}"),
        Ok(()) => panic!("{operation}: deletion succeeded while the creation handle was retained"),
    }
}

fn delete_empty_directory_by_handle(path: &Path) -> io::Result<()> {
    // The generic RemoveDirectoryW control returned access denied on the
    // measured runner. Request only DELETE, then exercise disposition through
    // that actual handle, to test the parent-rights/handle-sharing boundary.
    let directory = std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .inspect_err(|error| {
            eprintln!(
                "directory DELETE-only open: OS code {:?}",
                error.raw_os_error()
            )
        })?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: directory owns a live DELETE-capable handle; the initialized
    // fixed-size input matches FileDispositionInfo and lives through this
    // synchronous call. Only an owned, empty fixture directory is targeted.
    if unsafe {
        SetFileInformationByHandle(
            directory.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        eprintln!(
            "directory handle disposition: OS code {:?}",
            error.raw_os_error()
        );
        return Err(error);
    }
    Ok(()) // Closing the delete-marked handle completes directory removal.
}

#[test]
#[ignore = "creates/removes a disposable local account; explicit GitHub-hosted Windows CI only"]
fn separate_identity_cannot_access_private_objects() {
    let (account, token) = FixtureAccount::create().unwrap();
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    drive_alias::probe(&policy);
    remote_device::probe(&policy);
    let (chain, chain_custody) = chain::Fixture::prepare(&policy);
    let (registry, registry_custody) = registry::Fixture::prepare(&policy);
    let (publication, publication_custody) = publication::Fixture::prepare(&policy);
    let (reparse, _reparse_custody) = reparse::Fixture::prepare(root.path(), &policy);
    let reparse_for_thread = reparse.clone();
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
    // A reachable control inside the same directory prevents a traversal
    // denial from masquerading as the inherited child's own ACL protection.
    let mut traversal_control = create_at(
        &directory,
        OsStr::new("traversal-control.txt"),
        ObjectKind::File,
        &control_sd,
    )
    .unwrap();
    traversal_control
        .write_all(b"nested public control")
        .unwrap();
    drop(traversal_control);
    std::fs::write(
        private_directory.join("inherited.txt"),
        b"inherited fixture canary",
    )
    .unwrap();
    drop(
        policy
            .open_existing_inherited_file_at(
                &directory,
                OsStr::new("inherited.txt"),
                FileAccess::ReadOnly,
            )
            .unwrap(),
    );
    drop(directory);
    drop(parent);

    // Parent delete-child rights can override a child's restrictive DACL.
    // Measure this explicitly, alongside the no-delete-share creation handles.
    let delete_parent_sd =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let delete_parent_path = root.path().join("delete-child-parent");
    let delete_parent = create(
        &delete_parent_path,
        ObjectKind::Directory,
        &delete_parent_sd,
    )
    .unwrap();
    let released_file = delete_parent_path.join("released.txt");
    let released_directory = delete_parent_path.join("released-directory");
    drop(policy.create_new(&released_file, ObjectKind::File).unwrap());
    drop(
        policy
            .create_new(&released_directory, ObjectKind::Directory)
            .unwrap(),
    );
    let held_file_path = delete_parent_path.join("held.txt");
    let held_directory_path = delete_parent_path.join("held-directory");
    let released_public_directory = delete_parent_path.join("released-permissive-directory");
    drop(
        create(
            &released_public_directory,
            ObjectKind::Directory,
            &delete_parent_sd,
        )
        .unwrap(),
    );
    let held_file = policy
        .create_new(&held_file_path, ObjectKind::File)
        .unwrap();
    // A permissive directory supplies a successful deletion control, so a
    // private directory's ACL denial cannot masquerade as a handle-sharing gate.
    let held_directory = create(
        &held_directory_path,
        ObjectKind::Directory,
        &delete_parent_sd,
    )
    .unwrap();

    let control_for_thread = control_path.clone();
    let private_for_thread = private_path.clone();
    let directory_for_thread = private_directory.clone();
    let checked = std::thread::spawn(move || {
        // SAFETY: token is the owned result of this fixture's explicit local
        // login. Check success before any access attempt, then immediately arm
        // thread-bound restoration. No privileged handle is passed to probes.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        let restore = RestoreIdentity(PhantomData);
        chain.probe_as_other_user();
        registry.probe_as_other_user();
        publication.probe_as_other_user();
        let reparse_results = reparse_for_thread.probe_as_other_user();
        assert_eq!(
            std::fs::read(&control_for_thread).unwrap(),
            b"public fixture control"
        );
        std::fs::write(&control_for_thread, b"other user control write").unwrap();
        assert_eq!(std::fs::read(directory_for_thread.join("traversal-control.txt")).unwrap(), b"nested public control");
        std::fs::write(directory_for_thread.join("traversal-control.txt"), b"nested control updated").unwrap();
        let inherited = directory_for_thread.join("inherited.txt");
        denied(File::open(&inherited), "read inherited private file");
        denied(std::fs::OpenOptions::new().write(true).open(&inherited), "write inherited private file");
        for access in [WRITE_DAC, WRITE_OWNER, DELETE] {
            denied(std::fs::OpenOptions::new().access_mode(access).open(&inherited), "open inherited security/delete rights");
        }
        denied(std::fs::remove_file(&inherited), "delete inherited private file");
        denied(std::fs::rename(&inherited, directory_for_thread.join("moved-inherited.txt")), "rename inherited private file");
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
        // The private-file and permissive-directory controls must be removable.
        // Record the private directory separately: parent rights did not grant
        // DELETE for it on the previously measured Windows runner.
        std::fs::remove_file(&released_file).unwrap();
        let private_directory_removed = match delete_empty_directory_by_handle(&released_directory) {
            Ok(()) => {
                println!("::notice title=Windows private directory deletion::closed private directory removed through parent rights");
                true
            }
            Err(error) if error.raw_os_error() == Some(5) => {
                println!("::notice title=Windows private directory deletion::closed private directory refused DELETE access with OS code 5; this does not establish handle protection");
                false
            }
            Err(error) => panic!("closed private directory deletion: unexpected error {error}"),
        };
        delete_empty_directory_by_handle(&released_public_directory).unwrap();
        guarded_deletion(
            std::fs::remove_file(&held_file_path),
            "delete retained private file",
        );
        guarded_deletion(
            delete_empty_directory_by_handle(&held_directory_path),
            "delete retained permissive directory",
        );
        drop(restore);
        drop(token);
        (private_directory_removed, reparse_results)
    })
    .join();
    // Delete the account even if an access assertion failed. The logon token
    // and impersonation guard are gone before this explicit cleanup.
    account.remove().unwrap();
    let (private_directory_removed, reparse_results) = checked.unwrap();
    chain_custody.verify();
    registry_custody.verify();
    publication_custody.verify();
    reparse.verify_and_remove_junction(&reparse_results);
    policy
        .validate_handle(&held_file, ObjectKind::File)
        .unwrap();
    validate_object(&held_directory, ObjectKind::Directory).unwrap();
    assert!(matches!(
        policy.validate_handle(&held_directory, ObjectKind::Directory),
        Err(Error::UnexpectedDacl)
    ));
    drop(held_file);
    drop(held_directory);
    drop(delete_parent);
    assert!(!delete_parent_path.join("released.txt").exists());
    assert_eq!(
        delete_parent_path.join("released-directory").exists(),
        !private_directory_removed
    );
    assert!(
        !delete_parent_path
            .join("released-permissive-directory")
            .exists()
    );
    assert!(delete_parent_path.join("held.txt").is_file());
    assert!(delete_parent_path.join("held-directory").is_dir());
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
    assert_eq!(
        std::fs::read(private_directory.join("inherited.txt")).unwrap(),
        b"inherited fixture canary"
    );
    assert_eq!(
        std::fs::read(private_directory.join("traversal-control.txt")).unwrap(),
        b"nested control updated"
    );
    assert!(!private_directory.join("moved-inherited.txt").exists());
    println!(
        "::notice title=Windows inherited ACL separate identity::other user read/wrote the control in the same private directory but was denied inherited file data, security and deletion access; original inherited bytes preserved"
    );
    println!(
        "::notice title=Windows ACL separate identity::temporary standard user read/wrote the permissive control but was denied private reads, writes, security changes, deletion, rename, listing and child creation; original bytes preserved and owned account removed"
    );
    println!(
        "::notice title=Windows ACL ancestor limit::the temporary user deleted a closed private file through parent rights and a permissive directory through its own rights; retained creation handles blocked both equivalent attempts; complete ancestor custody remains a gate"
    );
}
