//! Read-only parser for the bounded MS-DTYP self-relative representation.
//! Creation goes through Windows' SDDL converter, never these byte helpers.
#![forbid(unsafe_code)]

use crate::{Error, ObjectKind, Result};

pub(crate) const MAX_DESCRIPTOR: usize = 128 * 1024;
const HEADER: usize = 20;
const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const DACL_PROTECTED: u16 = 0x1000;
const DACL_AUTO_INHERITED: u16 = 0x0400;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
// S-1-3-4 represents the object's actual owner, not its creator or group.
// Only ancestor checks use it, after independently validating the owner SID.
const OWNER_RIGHTS: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
// NT SERVICE\TrustedInstaller. Accepted only for OS-managed ancestors, never
// added to private object owners or grants. See docs/windows-acl.md.
const TRUSTED_INSTALLER: &[u8] = &[
    1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 181, 137, 251, 56, 25, 132, 194, 203, 92, 108, 35, 109,
    87, 0, 119, 110, 192, 2, 100, 135,
];
// Read/list/traverse and SYNCHRONIZE only. A native junction probe disproved
// the broader create-subdirectory/delete combination; no such rights are
// accepted until individually qualified. This is still only a snapshot.
const GUARDED_ANCESTOR_RIGHTS: u32 = 0x0012_00a9;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Sid(Vec<u8>);

impl Sid {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let sid = sid_prefix(bytes)?;
        if sid.len() != bytes.len() {
            return Err(Error::InvalidDescriptor);
        }
        Ok(Self(sid.to_vec()))
    }

    #[cfg(windows)]
    pub(crate) fn sddl(&self) -> String {
        // A SID authority is a six-byte big-endian number; subauthorities are
        // four-byte little-endian numbers. parse() established all lengths.
        let authority = self.0[2..8]
            .iter()
            .fold(0_u64, |a, b| (a << 8) | u64::from(*b));
        let mut text = format!("S-1-{authority}");
        for part in self.0[8..].as_chunks::<4>().0 {
            let value = u32::from_le_bytes(*part);
            text.push_str(&format!("-{value}"));
        }
        text
    }
}

pub(crate) fn sid_prefix(bytes: &[u8]) -> Result<&[u8]> {
    let header = bytes.get(..8).ok_or(Error::InvalidDescriptor)?;
    if header[0] != 1 || header[1] > 15 {
        return Err(Error::InvalidDescriptor);
    }
    bytes
        .get(..8 + usize::from(header[1]) * 4)
        .ok_or(Error::InvalidDescriptor)
}

fn word(bytes: &[u8], offset: usize) -> Result<u16> {
    let v = bytes
        .get(offset..offset + 2)
        .ok_or(Error::InvalidDescriptor)?;
    Ok(u16::from_le_bytes([v[0], v[1]]))
}

fn dword(bytes: &[u8], offset: usize) -> Result<u32> {
    let v = bytes
        .get(offset..offset + 4)
        .ok_or(Error::InvalidDescriptor)?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn offset(bytes: &[u8], field: usize) -> Result<usize> {
    let offset = dword(bytes, field)? as usize;
    if offset < HEADER || !offset.is_multiple_of(4) || offset >= bytes.len() {
        return Err(Error::InvalidDescriptor);
    }
    Ok(offset)
}

pub(crate) fn validate(bytes: &[u8], owner: &Sid, kind: ObjectKind) -> Result<()> {
    validate_layout(bytes, owner, kind, Layout::Protected)
}

pub(crate) fn validate_inherited_file(bytes: &[u8], owner: &Sid) -> Result<()> {
    validate_layout(bytes, owner, ObjectKind::File, Layout::Inherited)
}

pub(crate) fn validate_inherited_directory(bytes: &[u8], owner: &Sid) -> Result<()> {
    validate_layout(bytes, owner, ObjectKind::Directory, Layout::Inherited)
}

// Only a handle with zero links may use this policy. NTFS can clear inherited
// ACE flags when retiring the final name without changing the effective grants.
#[cfg(any(windows, test))]
pub(crate) fn validate_detached_file(bytes: &[u8], owner: &Sid) -> Result<()> {
    validate_layout(bytes, owner, ObjectKind::File, Layout::DetachedFile)
}

pub(crate) fn validate_ancestor(bytes: &[u8], owner: &Sid) -> Result<()> {
    validate_layout(bytes, owner, ObjectKind::Directory, Layout::Ancestor)
}

// Only the full path constructor may use this classification. Its retained,
// independently validated child and write/delete sharing exclusion establish
// its custody conditions. This parser alone cannot establish those invariants.
#[cfg(any(windows, test))]
pub(crate) fn validate_traversed_ancestor(bytes: &[u8], owner: &Sid) -> Result<()> {
    validate_layout(
        bytes,
        owner,
        ObjectKind::Directory,
        Layout::TraversedAncestor,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    Protected,
    Inherited,
    #[cfg(any(windows, test))]
    DetachedFile,
    Ancestor,
    #[cfg(any(windows, test))]
    TraversedAncestor,
}

fn validate_layout(bytes: &[u8], owner: &Sid, kind: ObjectKind, layout: Layout) -> Result<()> {
    let is_ancestor = match layout {
        Layout::Ancestor => true,
        #[cfg(any(windows, test))]
        Layout::TraversedAncestor => true,
        _ => false,
    };
    let ancestor_rights = match layout {
        #[cfg(any(windows, test))]
        Layout::TraversedAncestor => GUARDED_ANCESTOR_RIGHTS | 4, // FILE_ADD_SUBDIRECTORY
        _ => GUARDED_ANCESTOR_RIGHTS,
    };
    if !(HEADER..=MAX_DESCRIPTOR).contains(&bytes.len()) || bytes[0] != 1 || bytes[1] != 0 {
        return Err(Error::InvalidDescriptor);
    }
    let control = word(bytes, 2)?;
    if control & SELF_RELATIVE == 0 {
        return Err(Error::InvalidDescriptor);
    }
    if control & DACL_PRESENT == 0 {
        return Err(Error::AbsentDacl);
    }
    if dword(bytes, 16)? == 0 {
        return Err(Error::NullDacl);
    }
    let acl_start = offset(bytes, 16)?;
    let tail = &bytes[acl_start..];
    let acl_size = usize::from(word(tail, 2)?);
    let acl = tail
        .get(..acl_size)
        .filter(|v| v.len() >= 8)
        .ok_or(Error::InvalidDescriptor)?;
    if acl[0] != 2 || acl[1] != 0 || word(acl, 6)? != 0 || !acl_size.is_multiple_of(4) {
        return Err(Error::InvalidDescriptor);
    }
    let count = word(acl, 4)?;
    if count == 0 {
        return Err(Error::EmptyDacl);
    }
    match layout {
        Layout::Protected if control & DACL_PROTECTED == 0 => return Err(Error::UnprotectedDacl),
        Layout::Inherited if control & DACL_PROTECTED != 0 => {
            return Err(Error::UnexpectedDacl);
        }
        _ => {}
    }
    // Snapshot requests cover owner and DACL only. Permit Windows' group-
    // defaulted and auto-inherited bookkeeping; no pending inheritance or
    // resource-manager interpretation, defaulted DACL, or supplied SACL.
    // A system-created inherited child can have a defaulted owner. Its actual
    // SID must still be one of the already-trusted principals below.
    let allowed_control = SELF_RELATIVE
        | DACL_PRESENT
        | DACL_PROTECTED
        | DACL_AUTO_INHERITED
        | 0x0002
        | if layout != Layout::Protected { 1 } else { 0 };
    if control & !allowed_control != 0 || dword(bytes, 12)? != 0 {
        return Err(Error::InvalidDescriptor);
    }
    let owner_start = offset(bytes, 4)?;
    let actual_owner = sid_prefix(&bytes[owner_start..])?;
    if actual_owner != owner.0
        && !(layout != Layout::Protected
            && (actual_owner == SYSTEM || actual_owner == ADMINISTRATORS))
        && !(is_ancestor && actual_owner == TRUSTED_INSTALLER)
    {
        return Err(Error::OwnerMismatch);
    }
    let mut regions = vec![
        owner_start..owner_start + actual_owner.len(),
        acl_start..acl_start + acl_size,
    ];
    if dword(bytes, 8)? != 0 {
        let group_start = offset(bytes, 8)?;
        let group = sid_prefix(&bytes[group_start..])?;
        regions.push(group_start..group_start + group.len());
    }
    for (i, a) in regions.iter().enumerate() {
        if regions[i + 1..]
            .iter()
            .any(|b| a.start < b.end && b.start < a.end)
        {
            return Err(Error::InvalidDescriptor);
        }
    }
    if (!is_ancestor && count != 3) || owner.0 == SYSTEM || owner.0 == ADMINISTRATORS {
        return Err(Error::UnexpectedDacl);
    }
    let trustees = [owner.0.as_slice(), SYSTEM, ADMINISTRATORS];
    let mut seen = [false; 3];
    let mut cursor = 8;
    for _ in 0..count {
        let remaining = acl.get(cursor..).ok_or(Error::InvalidDescriptor)?;
        let ace_size = usize::from(word(remaining, 2)?);
        let ace = remaining
            .get(..ace_size)
            .filter(|v| v.len() >= 16)
            .ok_or(Error::InvalidDescriptor)?;
        if ace[0] != 0 {
            return Err(Error::UnexpectedDacl);
        }
        let sid = Sid::parse(&ace[8..])?;
        let mask = dword(ace, 4)?;
        if is_ancestor {
            let trusted = trustees.contains(&sid.0.as_slice())
                || sid.0 == TRUSTED_INSTALLER
                || sid.0 == OWNER_RIGHTS;
            // Inherit-only entries grant nothing on this directory. Each
            // descendant must be independently validated before it is used.
            if ace[1] & !0x1f != 0
                || (!trusted && ace[1] & 0x08 == 0 && mask & !ancestor_rights != 0)
            {
                return Err(Error::UnexpectedDacl);
            }
        } else {
            let expected_flags = match layout {
                // Require a uniform explicit or inherited file layout. Neither
                // form adds rights; all trustees/masks/counts remain exact.
                #[cfg(any(windows, test))]
                Layout::DetachedFile => *acl
                    .get(9)
                    .filter(|&&flags| matches!(flags, 0 | 0x10))
                    .ok_or(Error::UnexpectedDacl)?,
                _ => {
                    (if layout == Layout::Inherited { 0x10 } else { 0 })
                        | (if kind == ObjectKind::Directory { 3 } else { 0 })
                }
            };
            if ace[1] != expected_flags || mask != FILE_ALL_ACCESS {
                return Err(Error::UnexpectedDacl);
            }
            let index = trustees
                .iter()
                .position(|allowed| *allowed == sid.0)
                .ok_or(Error::UnexpectedDacl)?;
            if seen[index] {
                return Err(Error::UnexpectedDacl);
            }
            seen[index] = true;
        }
        cursor += ace_size;
    }
    // An ACL can reserve unused bytes. Refuse nonzero unaccounted data rather
    // than accepting an unsupported extension to our exact creation format.
    if acl[cursor..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidDescriptor);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
