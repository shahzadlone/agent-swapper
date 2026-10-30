//! CI-only loopback SMB control. Shares only a fresh directory with fictional
//! bytes; never changes an existing share, service, firewall or account policy.

use super::*;
use windows_sys::Win32::{
    NetworkManagement::NetManagement::{NERR_NetNameNotFound, NetApiBufferFree},
    Storage::FileSystem::{
        NetShareAdd, NetShareDel, NetShareGetInfo, SHARE_INFO_502, STYPE_DISKTREE, STYPE_TEMPORARY,
    },
};

struct Share {
    name: Vec<u16>,
    text: String,
    active: bool,
}

impl Share {
    fn create(path: &Path, policy: &SecurityPolicy) -> io::Result<Self> {
        require_hosted_fixture()?;
        reject_impersonation().map_err(io::Error::other)?;
        let mut path = wide_path(path).map_err(io::Error::other)?;
        if path.starts_with(&[92, 92, 63, 92]) {
            path.drain(..4);
        }
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut text = String::from("aswp-fixture-");
        for byte in nonce {
            text.push_str(&format!("{byte:02x}"));
        }
        text.push('$');
        let mut name: Vec<u16> = text.encode_utf16().chain([0]).collect();
        // The fixture owner's SID can read its fictional data through SMB.
        // Other identities receive no share-level grant.
        let sd = LocalDescriptor::from_sddl(&format!(
            "O:{}D:P(A;;GR;;;{})",
            policy.owner.sddl(),
            policy.owner.sddl()
        ))
        .map_err(io::Error::other)?;
        let info = SHARE_INFO_502 {
            shi502_netname: name.as_mut_ptr(),
            shi502_type: STYPE_DISKTREE | STYPE_TEMPORARY,
            shi502_max_uses: 1,
            shi502_path: path.as_mut_ptr(),
            shi502_security_descriptor: sd.0.as_ptr(),
            ..Default::default()
        };
        // SAFETY: level502 matches the initialized SDK structure. Its owned
        // NUL-terminated strings and Windows-created SD remain live until this
        // synchronous local-server call returns. No password or policy change.
        let status = unsafe {
            NetShareAdd(
                null(),
                502,
                (&info as *const SHARE_INFO_502).cast(),
                null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // A collision/error never acquires ownership of an existing share.
        Ok(Self {
            name,
            text,
            active: true,
        })
    }

    fn remove(&mut self) -> io::Result<()> {
        // SAFETY: this unique name was successfully created by this guard.
        // Delete that local definition only; filesystem data is not deleted.
        let status = unsafe { NetShareDel(null(), self.name.as_ptr(), 0) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.remove()
        {
            eprintln!(
                "::error title=Windows SMB fixture cleanup::owned share removal failed with OS code {:?}",
                error.raw_os_error()
            );
        }
    }
}

pub(super) fn probe(policy: &SecurityPolicy) {
    require_hosted_fixture().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let path = fixture.path().join("private.txt");
    let mut local = policy.create_new(&path, ObjectKind::File).unwrap();
    local.write_all(b"loopback SMB fixture").unwrap();
    local.sync_all().unwrap();
    policy.validate_handle(&local, ObjectKind::File).unwrap();
    drop(local);
    let mut share = Share::create(fixture.path(), policy).unwrap();
    let remote_path = std::path::PathBuf::from(format!(r"\\localhost\{}\private.txt", share.text));
    let mut remote = File::open(&remote_path).unwrap();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut remote, &mut bytes).unwrap();
    assert_eq!(bytes, b"loopback SMB fixture");
    // A successful network read is required: a failed connection cannot count
    // as evidence that the handle-based device classification refused SMB.
    assert!(matches!(
        validate_local_device(&remote),
        Err(Error::UnsupportedObject)
    ));
    assert!(matches!(
        policy.validate_handle(&remote, ObjectKind::File),
        Err(Error::UnsupportedObject)
    ));
    drop(remote);
    share.remove().unwrap();
    let mut buffer = null_mut();
    // SAFETY: owned NUL-terminated name and initialized output; local read-only
    // share lookup after explicit removal, with no filesystem data mutation.
    let status = unsafe { NetShareGetInfo(null(), share.name.as_ptr(), 0, &mut buffer) };
    if status == 0 && !buffer.is_null() {
        // SAFETY: successful level0 query returned a NetAPI-owned allocation.
        // Free it before reporting that the share unexpectedly still exists.
        unsafe {
            NetApiBufferFree(buffer.cast());
        }
    }
    assert_eq!(status, NERR_NetNameNotFound);
    assert_eq!(std::fs::read(&path).unwrap(), b"loopback SMB fixture");
    println!(
        "::notice title=Windows remote device refusal::local protected file passed validation; same file was readable over a disposable loopback SMB share but refused by actual-handle device classification; share removed and original data preserved"
    );
}
