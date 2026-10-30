//! Disposable CI-only SUBST-equivalent alias. Exact-target removal preserves
//! any other definition, and the mutation helper itself enforces CI opt-in.

use super::*;
use windows_sys::Win32::Storage::FileSystem::{
    DDD_EXACT_MATCH_ON_REMOVE, DDD_NO_BROADCAST_SYSTEM, DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION,
    DefineDosDeviceW, QueryDosDeviceW,
};

struct Alias {
    name: [u16; 3],
    target: Vec<u16>,
    active: bool,
}

impl Alias {
    fn create(target: &Path) -> io::Result<Self> {
        require_hosted_fixture()?;
        // LocalSystem would use the global DOS namespace. Refuse it even if
        // all hosted-runner markers were supplied; process_user also refuses
        // thread impersonation before any namespace mutation.
        if process_user().map_err(io::Error::other)?.sddl() == "S-1-5-18" {
            return Err(io::Error::other(
                "drive fixture requires a local user namespace",
            ));
        }
        let mut units = wide_path(target).map_err(io::Error::other)?;
        if units.starts_with(&[92, 92, 63, 92]) {
            units.drain(..4);
        }
        let target: Vec<_> = [92, 63, 63, 92].into_iter().chain(units).collect();
        for letter in (b'P'..=b'Z').rev() {
            let name = [u16::from(letter), 58, 0];
            if !name_absent(&name)? {
                continue;
            }
            // SAFETY: both strings are bounded, owned and NUL-terminated.
            // Only a free drive letter in this disposable user's DOS namespace
            // is selected. Target is this fixture's directory, not a volume;
            // no persistent mount or broadcast is requested.
            if unsafe {
                DefineDosDeviceW(
                    DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                    name.as_ptr(),
                    target.as_ptr(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            return Ok(Self {
                name,
                target,
                active: true,
            });
        }
        Err(io::Error::other(
            "no unused disposable fixture drive letter",
        ))
    }

    fn remove(&mut self) -> io::Result<()> {
        // SAFETY: this guard owns the exact definition created above. Exact
        // matching plus the original raw target cannot pop another mapping.
        // Buffers stay live; removal is attempted only while active.
        if unsafe {
            DefineDosDeviceW(
                DDD_REMOVE_DEFINITION
                    | DDD_EXACT_MATCH_ON_REMOVE
                    | DDD_RAW_TARGET_PATH
                    | DDD_NO_BROADCAST_SYSTEM,
                self.name.as_ptr(),
                self.target.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for Alias {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.remove()
        {
            eprintln!(
                "::error title=Windows drive fixture cleanup::owned alias removal failed with OS code {:?}",
                error.raw_os_error()
            );
        }
    }
}

fn name_absent(name: &[u16; 3]) -> io::Result<bool> {
    let mut buffer = [0_u16; 512];
    // SAFETY: fixed NUL-terminated name, initialized output and exact capacity;
    // existing mappings are inspected only to avoid choosing occupied letters.
    if unsafe { QueryDosDeviceW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) } != 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(2) => Ok(true),
        Some(122) => Ok(false), // Existing mapping exceeds our bounded buffer.
        _ => Err(error),
    }
}

pub(super) fn probe(policy: &SecurityPolicy) {
    require_hosted_fixture().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(fixture.path().join("canary.txt"), b"drive alias control").unwrap();
    let target = std::fs::canonicalize(fixture.path()).unwrap();
    let mut alias = Alias::create(&target).unwrap();
    let alias_path = std::path::PathBuf::from(format!("{}:\\", char::from(alias.name[0] as u8)));
    assert_eq!(
        std::fs::read(alias_path.join("canary.txt")).unwrap(),
        b"drive alias control"
    );
    assert!(matches!(
        policy.open_or_create_private_root(&alias_path.join("refused")),
        Err(Error::UnsupportedPath)
    ));
    assert!(!fixture.path().join("refused").exists());
    alias.remove().unwrap();
    assert!(name_absent(&alias.name).unwrap());
    assert_eq!(
        std::fs::read(fixture.path().join("canary.txt")).unwrap(),
        b"drive alias control"
    );
    println!(
        "::notice title=Windows drive alias refusal::fresh SUBST-equivalent directory alias was readable as a positive control; private root constructor refused the omitted ancestry before creation; exact alias removal and target preservation verified"
    );
}
