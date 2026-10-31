//! A measurement on the verified root of a newly owned disposable volume.
//! No result here automatically changes the production ancestor policy.

use super::super::super::reparse;
use super::*;
use windows_sys::Win32::{
    Security::{
        Authorization::SetSecurityInfo, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::{
        FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, FILE_ID_INFO, FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA, FILE_WRITE_EA, FileIdInfo, GetFileInformationByHandleEx,
    },
    System::{
        Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_SET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT_EX},
        SystemServices::MAXIMUM_ALLOWED,
    },
};

fn fixture_sid(token: &OwnedHandle) -> Sid {
    // Same bounded, word-aligned layout as process identity lookup. This token
    // belongs only to the random account created by this fixture.
    let mut storage = [0_usize; 32];
    let mut length = 0;
    // SAFETY: live token; initialized aligned buffer and length output remain
    // stable through the synchronous call. Oversized output is a refusal.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut length,
        )
    };
    assert_ne!(ok, 0);
    let length = length as usize;
    assert!((size_of::<TOKEN_USER>()..=size_of_val(&storage)).contains(&length));
    // SAFETY: successful query initialized TOKEN_USER within checked bounds.
    let user = unsafe { storage.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    let start = (user.User.Sid as usize)
        .checked_sub(storage.as_ptr() as usize)
        .unwrap();
    assert!((size_of::<TOKEN_USER>()..length).contains(&start));
    // SAFETY: all storage bytes are initialized; view is derived from our own
    // allocation, never from the unchecked native SID pointer.
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length) };
    Sid::parse(sid_prefix(&bytes[start..]).unwrap()).unwrap()
}

fn identity(file: &File) -> (u64, [u8; 16]) {
    let mut id = FILE_ID_INFO::default();
    // SAFETY: live file handle; initialized/aligned fixed-size SDK output.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    assert_ne!(ok, 0);
    (id.VolumeSerialNumber, id.FileId.Identifier)
}

struct InstalledTag<'a> {
    file: &'a File,
    payload: &'a [u8],
    active: bool,
}

impl InstalledTag<'_> {
    fn remove(&mut self) -> io::Result<()> {
        reparse::set_reparse(self.file, self.payload, FSCTL_DELETE_REPARSE_POINT)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for InstalledTag<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.remove()
        {
            eprintln!(
                "::error title=Owned volume tag cleanup::OS code {:?}",
                error.raw_os_error()
            );
        }
    }
}

fn measure_tag(file: &File, payload: &[u8], input: &[u8], operation: u32) -> io::Result<()> {
    assert_eq!(
        file.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0
    );
    reparse::set_reparse(file, input, operation)?;
    let mut installed = InstalledTag {
        file,
        payload,
        active: true,
    };
    assert_ne!(
        file.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0
    );
    // Only failure of the SET operation is a measurement result. Cleanup or
    // observation failures must fail the fixture, not masquerade as refusal.
    installed.remove().unwrap();
    assert_eq!(
        file.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0
    );
    Ok(())
}

// Only this private method can change a root DACL. Its receiver was constructed
// from the new-image factory plus CIM, native extent and root-identity checks.
impl OwnedNtfsVolume {
    fn admit_fixture_user(&self, descriptor: &LocalDescriptor) -> io::Result<()> {
        require_volume_fixture()?;
        if std::env::var("ASWP_CI_ROOT_MUTATION_FIXTURE")
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(io::Error::other(
                "owned-volume root mutation opt-in missing",
            ));
        }
        let mut dacl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        // SAFETY: Windows-created descriptor remains owned and live through
        // both calls; initialized outputs receive a borrowed DACL pointer.
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor.0.as_ptr(),
                &mut present,
                &mut dacl,
                &mut defaulted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other("fixture DACL is absent/null"));
        }
        // SAFETY: retained WRITE_DAC handle names only our verified new-volume
        // root. Borrowed DACL lives through the synchronous call; no SACL or
        // owner is changed, and no existing machine-volume pathname is used.
        let status = unsafe {
            SetSecurityInfo(
                self.root.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

#[test]
#[ignore = "mutates only its own newly formatted volume root; fourth explicit hosted CI opt-in"]
fn owned_volume_root_directory_tag_behavior_has_matched_other_user_controls() {
    require_volume_fixture().unwrap();
    assert_eq!(
        std::env::var("ASWP_CI_ROOT_MUTATION_FIXTURE")
            .ok()
            .as_deref(),
        Some("1")
    );
    let policy = SecurityPolicy::for_current_process().unwrap();
    let (account, token) = FixtureAccount::create().unwrap();
    let other = fixture_sid(&token);
    let fixture = OwnedNtfsVolume::create(&policy, RootAccess::SetFixtureDacl(&other)).unwrap();
    // Fixture-user read/traverse plus AD4, with no other mutation grant.
    // No inheritable test grants. Any OS-created children belong to this same
    // newly owned volume; no existing machine volume receives this DACL.
    let public = LocalDescriptor::from_sddl(&format!(
        "O:{}D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200ad;;;{})",
        policy.owner.sddl(),
        policy.owner.sddl(),
        other.sddl()
    ))
    .unwrap();
    fixture.admit_fixture_user(&public).unwrap();
    let control = create_at(
        &fixture.root,
        OsStr::new("nonempty-ad4"),
        ObjectKind::Directory,
        &public,
    )
    .unwrap();
    let public_file = LocalDescriptor::from_sddl(&format!(
        "O:{}D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{})",
        policy.owner.sddl(),
        policy.owner.sddl(),
        other.sddl()
    ))
    .unwrap();
    for (parent, name) in [
        (&fixture.root, "root-canary.txt"),
        (&control, "child-canary.txt"),
    ] {
        let mut file = create_at(parent, OsStr::new(name), ObjectKind::File, &public_file).unwrap();
        file.write_all(b"owned root fixture").unwrap();
    }
    let mut private = create_at(
        &fixture.root,
        OsStr::new("private.txt"),
        ObjectKind::File,
        &policy.creation_descriptor(ObjectKind::File).unwrap(),
    )
    .unwrap();
    private.write_all(b"private root fixture").unwrap();
    drop(private);
    let root_id = identity(&fixture.root);
    let control_id = identity(&control);
    // Match the retained owner handle's access and sharing at both objects.
    let matched = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(fixture.path.join("nonempty-ad4"))
        .unwrap();
    assert_eq!(identity(&matched), control_id);
    drop(control);
    let control = matched;
    let path = fixture.path.clone();
    let results = std::thread::spawn(move || {
        // SAFETY: this fixture owns the fresh standard-user logon token. The
        // thread-bound guard restores its identity before any result/unwind.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        let _restore = RestoreIdentity(PhantomData);
        assert_eq!(
            std::fs::read(path.join("root-canary.txt")).unwrap(),
            b"owned root fixture"
        );
        assert_eq!(
            std::fs::read(path.join("nonempty-ad4/child-canary.txt")).unwrap(),
            b"owned root fixture"
        );
        denied(
            std::fs::read(path.join("private.txt")),
            "owned-volume private canary",
        );
        let rights = FILE_GENERIC_READ | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY;
        let mutations = FILE_WRITE_DATA
            | FILE_ADD_SUBDIRECTORY
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | FILE_DELETE_CHILD
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER;
        for (target, expected) in [(&path, root_id), (&path.join("nonempty-ad4"), control_id)] {
            let probe = reparse::open_directory(target, MAXIMUM_ALLOWED).unwrap();
            assert_eq!(identity(&probe), expected);
            assert_eq!(
                reparse::granted_access(&probe) & mutations,
                FILE_ADD_SUBDIRECTORY
            );
        }
        let root = reparse::open_directory(&path, rights).unwrap();
        let control = reparse::open_directory(&path.join("nonempty-ad4"), rights).unwrap();
        assert_eq!(identity(&root), root_id);
        assert_eq!(identity(&control), control_id);
        for file in [&root, &control] {
            assert_eq!(
                reparse::granted_access(file) & mutations,
                FILE_ADD_SUBDIRECTORY
            );
        }
        let mut payload = vec![0_u8; 24];
        payload[..4].copy_from_slice(&0x1000_0042_u32.to_le_bytes());
        getrandom::fill(&mut payload[8..]).unwrap();
        payload[8] |= 1;
        let mut extended = vec![0_u8; 32];
        extended.extend_from_slice(&payload);
        let mut results = Vec::new();
        for (label, operation, input) in [
            ("basic", FSCTL_SET_REPARSE_POINT, &payload),
            ("extended", FSCTL_SET_REPARSE_POINT_EX, &extended),
        ] {
            // A matching operation must work on a nonempty directory on this
            // same volume, under this same token and exact mutation grant.
            measure_tag(&control, &payload, input, operation).unwrap();
            let result = match measure_tag(&root, &payload, input, operation) {
                Ok(()) => 0,
                Err(error) => {
                    let code = error.raw_os_error().unwrap();
                    assert_ne!(code, 0, "SET failure without an OS code");
                    code
                }
            };
            assert_eq!(
                root.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
                0
            );
            measure_tag(&control, &payload, input, operation).unwrap();
            results.push((label, result));
        }
        results
    })
    .join();
    account.remove().unwrap();
    let results = results.unwrap();
    for path in [
        fixture.path.join("root-canary.txt"),
        fixture.path.join("nonempty-ad4/child-canary.txt"),
    ] {
        assert_eq!(std::fs::read(path).unwrap(), b"owned root fixture");
    }
    assert_eq!(
        std::fs::read(fixture.path.join("private.txt")).unwrap(),
        b"private root fixture"
    );
    drop(control);
    fixture.finish().unwrap();
    for (label, code) in results {
        println!(
            "::notice title=Owned volume root reparse measurement::{label}: OS result {code} (0 means installed and removed); matched nonempty directory control succeeded under standard user with AD4-only mutation grant; canaries and cleanup passed; tested tag/OS only, no policy promotion"
        );
    }
}
