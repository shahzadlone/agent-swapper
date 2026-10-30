#![allow(clippy::unwrap_used)]

use super::*;
use crate::SecurityPolicy;
use proptest::prelude::*;

const USER: &[u8] = &[
    1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0, 233, 3, 0, 0,
];
const EVERYONE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

fn policy() -> SecurityPolicy {
    SecurityPolicy {
        owner: Sid::parse(USER).unwrap(),
    }
}

// Small independent MS-DTYP corpus builder. Native tests additionally use the
// Windows SDDL converter and actual filesystem descriptors, not this builder.
fn descriptor(kind: ObjectKind, trustees: &[&[u8]]) -> Vec<u8> {
    descriptor_with_owner(kind, trustees, USER)
}

fn descriptor_with_owner(kind: ObjectKind, trustees: &[&[u8]], owner: &[u8]) -> Vec<u8> {
    let mut acl = vec![2, 0, 0, 0, trustees.len() as u8, 0, 0, 0];
    for sid in trustees {
        acl.extend([0, if kind == ObjectKind::Directory { 3 } else { 0 }]);
        acl.extend(((8 + sid.len()) as u16).to_le_bytes());
        acl.extend([255, 1, 31, 0]); // FA = file full control.
        acl.extend(*sid);
    }
    let size = (acl.len() as u16).to_le_bytes();
    acl[2..4].copy_from_slice(&size);
    let mut descriptor = vec![1, 0, 4, 144, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    descriptor.extend(((20 + owner.len()) as u32).to_le_bytes());
    descriptor.extend(owner);
    descriptor.extend(acl);
    descriptor
}

fn inherited(trustees: &[&[u8]], owner: &[u8]) -> Vec<u8> {
    let mut bytes = descriptor_with_owner(ObjectKind::File, trustees, owner);
    bytes[3] = 0x84; // self-relative + auto-inherited, not protected.
    let mut ace = 20 + owner.len() + 8;
    for trustee in trustees {
        bytes[ace + 1] = 0x10;
        ace += 8 + trustee.len();
    }
    bytes
}

fn ancestor(owner: &[u8], flags: u8, mask: u32) -> Vec<u8> {
    let mut bytes = descriptor_with_owner(
        ObjectKind::Directory,
        &[USER, SYSTEM, ADMINISTRATORS, EVERYONE],
        owner,
    );
    let ace =
        20 + owner.len() + 8 + (8 + USER.len()) + (8 + SYSTEM.len()) + (8 + ADMINISTRATORS.len());
    bytes[ace + 1] = flags;
    bytes[ace + 4..ace + 8].copy_from_slice(&mask.to_le_bytes());
    bytes
}

fn valid(kind: ObjectKind) -> Vec<u8> {
    descriptor(kind, &[USER, SYSTEM, ADMINISTRATORS])
}

#[test]
fn accepts_exact_policy_in_any_trustee_order_for_both_object_types() {
    for kind in [ObjectKind::File, ObjectKind::Directory] {
        for order in [
            [USER, SYSTEM, ADMINISTRATORS],
            [ADMINISTRATORS, USER, SYSTEM],
            [SYSTEM, ADMINISTRATORS, USER],
        ] {
            policy()
                .validate_descriptor(&descriptor(kind, &order), kind)
                .unwrap();
        }
    }
}

#[test]
fn absent_null_and_empty_dacls_are_distinct_refusals() {
    let mut absent = valid(ObjectKind::File);
    absent[2] = 0;
    assert!(matches!(
        policy().validate_descriptor(&absent, ObjectKind::File),
        Err(Error::AbsentDacl)
    ));
    let mut null = valid(ObjectKind::File);
    null[16..20].fill(0);
    assert!(matches!(
        policy().validate_descriptor(&null, ObjectKind::File),
        Err(Error::NullDacl)
    ));
    assert!(matches!(
        policy().validate_descriptor(&descriptor(ObjectKind::File, &[]), ObjectKind::File),
        Err(Error::EmptyDacl)
    ));
}

#[test]
fn refuses_broad_duplicate_missing_or_extra_trustees() {
    for trustees in [
        vec![USER, SYSTEM, EVERYONE],
        vec![USER, USER, ADMINISTRATORS],
        vec![USER, SYSTEM],
        vec![USER, SYSTEM, ADMINISTRATORS, EVERYONE],
    ] {
        assert!(matches!(
            policy()
                .validate_descriptor(&descriptor(ObjectKind::File, &trustees), ObjectKind::File),
            Err(Error::UnexpectedDacl)
        ));
    }
}

#[test]
fn refuses_wrong_owner_and_owner_overlapping_the_acl() {
    let mut bytes = valid(ObjectKind::File);
    bytes[44] ^= 1;
    assert!(matches!(
        policy().validate_descriptor(&bytes, ObjectKind::File),
        Err(Error::OwnerMismatch)
    ));
    // Point owner at the same valid user SID embedded in the first allow ACE.
    bytes = valid(ObjectKind::File);
    let embedded = (20 + USER.len() + 16) as u32;
    bytes[4..8].copy_from_slice(&embedded.to_le_bytes());
    assert!(matches!(
        policy().validate_descriptor(&bytes, ObjectKind::File),
        Err(Error::InvalidDescriptor)
    ));
}

#[test]
fn refuses_inherited_unprotected_and_inherit_only_permissions() {
    let original = valid(ObjectKind::Directory);
    let mut unprotected = original.clone();
    unprotected[3] &= !0x10;
    assert!(matches!(
        policy().validate_descriptor(&unprotected, ObjectKind::Directory),
        Err(Error::UnprotectedDacl)
    ));
    for flag in [0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
        let mut bytes = original.clone();
        bytes[20 + USER.len() + 9] |= flag;
        assert!(matches!(
            policy().validate_descriptor(&bytes, ObjectKind::Directory),
            Err(Error::UnexpectedDacl)
        ));
    }
    assert!(
        policy()
            .validate_descriptor(&original, ObjectKind::File)
            .is_err()
    );
}

#[test]
fn refuses_deny_object_callback_and_unknown_ace_forms() {
    for ace_type in 1..=255 {
        let mut bytes = valid(ObjectKind::File);
        bytes[20 + USER.len() + 8] = ace_type;
        assert!(matches!(
            policy().validate_descriptor(&bytes, ObjectKind::File),
            Err(Error::UnexpectedDacl)
        ));
    }
}

#[test]
fn refuses_non_full_control_and_generic_rights() {
    for mask in [0_u32, 1, 0x0012_0089, 0x1000_0000, u32::MAX] {
        let mut bytes = valid(ObjectKind::File);
        let mask_offset = 20 + USER.len() + 12;
        bytes[mask_offset..mask_offset + 4].copy_from_slice(&mask.to_le_bytes());
        assert!(matches!(
            policy().validate_descriptor(&bytes, ObjectKind::File),
            Err(Error::UnexpectedDacl)
        ));
    }
}

#[test]
fn refuses_all_truncated_prefixes_and_out_of_bounds_offsets() {
    let original = valid(ObjectKind::File);
    for end in 0..original.len() {
        assert!(
            policy()
                .validate_descriptor(&original[..end], ObjectKind::File)
                .is_err(),
            "prefix {end}"
        );
    }
    for field in [4, 8, 12, 16] {
        for value in [1_u32, 4, 19, 21, original.len() as u32, u32::MAX] {
            let mut bytes = original.clone();
            bytes[field..field + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                policy()
                    .validate_descriptor(&bytes, ObjectKind::File)
                    .is_err()
            );
        }
    }
}

#[test]
fn refuses_forged_acl_and_ace_lengths_counts_and_sid_payloads() {
    let original = valid(ObjectKind::File);
    let acl = 20 + USER.len();
    for field in [acl + 2, acl + 4, acl + 10] {
        for value in [0_u16, 1, 7, 65535] {
            let mut bytes = original.clone();
            bytes[field..field + 2].copy_from_slice(&value.to_le_bytes());
            assert!(
                policy()
                    .validate_descriptor(&bytes, ObjectKind::File)
                    .is_err()
            );
        }
    }
    for value in [0_u8, 2, 255] {
        let mut bytes = original.clone();
        bytes[acl + 16] = value; // SID revision.
        assert!(
            policy()
                .validate_descriptor(&bytes, ObjectKind::File)
                .is_err()
        );
    }
    let mut bytes = original;
    bytes[acl + 17] = 255; // SID subauthority count.
    assert!(
        policy()
            .validate_descriptor(&bytes, ObjectKind::File)
            .is_err()
    );
}

#[test]
fn accepts_reordered_descriptor_regions_but_refuses_absolute_format() {
    let original = valid(ObjectKind::File);
    let acl = &original[20 + USER.len()..];
    let mut moved = original[..20].to_vec();
    moved[4..8].copy_from_slice(&((20 + acl.len()) as u32).to_le_bytes());
    moved[16..20].copy_from_slice(&20_u32.to_le_bytes());
    moved.extend(acl);
    moved.extend(USER);
    policy()
        .validate_descriptor(&moved, ObjectKind::File)
        .unwrap();
    moved[3] &= !0x80;
    assert!(matches!(
        policy().validate_descriptor(&moved, ObjectKind::File),
        Err(Error::InvalidDescriptor)
    ));
}

#[test]
fn every_single_bit_change_to_owner_or_permissions_is_refused() {
    // The exact policy must not accept a changed SID, right, ACE form, flag,
    // ACL length/count or reserved field after otherwise-valid framing.
    for kind in [ObjectKind::File, ObjectKind::Directory] {
        let original = valid(kind);
        for index in 20..original.len() {
            for bit in 0..8 {
                let mut changed = original.clone();
                changed[index] ^= 1 << bit;
                assert!(
                    policy().validate_descriptor(&changed, kind).is_err(),
                    "accepted changed byte {index}, bit {bit}, kind {kind:?}"
                );
            }
        }
    }
}

#[test]
fn refuses_oversized_descriptors_and_unrecognized_revisions() {
    let mut oversized = valid(ObjectKind::File);
    oversized.resize(MAX_DESCRIPTOR + 1, 0);
    assert!(matches!(
        policy().validate_descriptor(&oversized, ObjectKind::File),
        Err(Error::InvalidDescriptor)
    ));
    for revision in [0, 2, 3, 4, 255] {
        let mut bytes = valid(ObjectKind::File);
        bytes[0] = revision;
        assert!(
            policy()
                .validate_descriptor(&bytes, ObjectKind::File)
                .is_err()
        );
    }
    for revision in [0, 1, 3, 4, 255] {
        let mut bytes = valid(ObjectKind::File);
        bytes[20 + USER.len()] = revision;
        assert!(
            policy()
                .validate_descriptor(&bytes, ObjectKind::File)
                .is_err()
        );
    }
}

#[test]
fn inherited_file_policy_requires_exact_inherited_grants_and_an_already_trusted_owner() {
    for owner in [USER, SYSTEM, ADMINISTRATORS] {
        for order in [
            [USER, SYSTEM, ADMINISTRATORS],
            [ADMINISTRATORS, SYSTEM, USER],
        ] {
            let mut bytes = inherited(&order, owner);
            policy().validate_inherited_file_descriptor(&bytes).unwrap();
            // The same snapshot must never qualify as an explicitly protected file.
            assert!(matches!(
                policy().validate_descriptor(&bytes, ObjectKind::File),
                Err(Error::UnprotectedDacl)
            ));
            bytes[2] |= 1; // A defaulted owner remains subject to the SID check.
            policy().validate_inherited_file_descriptor(&bytes).unwrap();
            // Newly inherited files can omit propagation bookkeeping while
            // their individual ACEs are still all marked inherited.
            bytes[3] &= !0x04;
            policy().validate_inherited_file_descriptor(&bytes).unwrap();
        }
    }
    assert!(matches!(
        policy().validate_inherited_file_descriptor(&inherited(
            &[USER, SYSTEM, ADMINISTRATORS],
            EVERYONE
        )),
        Err(Error::OwnerMismatch)
    ));
    assert!(
        policy()
            .validate_inherited_file_descriptor(&valid(ObjectKind::File))
            .is_err()
    );
    for trustees in [
        vec![USER, SYSTEM, EVERYONE],
        vec![USER, USER, ADMINISTRATORS],
        vec![USER, SYSTEM],
        vec![USER, SYSTEM, ADMINISTRATORS, EVERYONE],
    ] {
        assert!(
            policy()
                .validate_inherited_file_descriptor(&inherited(&trustees, USER))
                .is_err()
        );
    }
}

#[test]
fn inherited_file_policy_refuses_mixed_explicit_inherit_only_unknown_or_pending_permissions() {
    let original = inherited(&[USER, SYSTEM, ADMINISTRATORS], USER);
    let ace = 20 + USER.len() + 8;
    for flags in 0..=255 {
        if flags == 0x10 {
            continue;
        }
        let mut bytes = original.clone();
        bytes[ace + 1] = flags;
        assert!(
            policy().validate_inherited_file_descriptor(&bytes).is_err(),
            "ACE flags {flags}"
        );
    }
    for ace_type in 1..=255 {
        let mut bytes = original.clone();
        bytes[ace] = ace_type;
        assert!(policy().validate_inherited_file_descriptor(&bytes).is_err());
    }
    for control in [0x9004_u16, 0x9404, 0x8504, 0x840c, 0xc404, 0x8400] {
        let mut bytes = original.clone();
        bytes[2..4].copy_from_slice(&control.to_le_bytes());
        assert!(
            policy().validate_inherited_file_descriptor(&bytes).is_err(),
            "control {control:04x}"
        );
    }
    for index in 20..original.len() {
        for bit in 0..8 {
            let mut changed = original.clone();
            changed[index] ^= 1 << bit;
            assert!(
                policy()
                    .validate_inherited_file_descriptor(&changed)
                    .is_err(),
                "changed byte {index}, bit {bit}"
            );
        }
    }
    for end in 0..original.len() {
        assert!(
            policy()
                .validate_inherited_file_descriptor(&original[..end])
                .is_err()
        );
    }
}

#[test]
fn ancestor_policy_distinguishes_name_custody_from_in_place_mutation() {
    for owner in [USER, SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER] {
        let bytes = ancestor(owner, 3, GUARDED_ANCESTOR_RIGHTS);
        policy().validate_ancestor_descriptor(&bytes).unwrap();
        assert!(
            policy()
                .validate_descriptor(&bytes, ObjectKind::Directory)
                .is_err()
        );
        assert!(policy().validate_inherited_file_descriptor(&bytes).is_err());
        let mut unprotected = bytes;
        unprotected[3] &= !0x10;
        policy().validate_ancestor_descriptor(&unprotected).unwrap();
    }
    for bit in 0..32 {
        let mask = 1 << bit;
        assert_eq!(
            policy()
                .validate_ancestor_descriptor(&ancestor(USER, 0, mask))
                .is_ok(),
            mask & !GUARDED_ANCESTOR_RIGHTS == 0,
            "right {mask:08x}"
        );
    }
    assert!(matches!(
        policy().validate_ancestor_descriptor(&ancestor(EVERYONE, 0, 1)),
        Err(Error::OwnerMismatch)
    ));
    for flag in 0..=255 {
        let result = policy().validate_ancestor_descriptor(&ancestor(USER, flag, FILE_ALL_ACCESS));
        assert_eq!(
            result.is_ok(),
            flag & !0x1f == 0 && flag & 8 != 0,
            "flags {flag:02x}"
        );
    }
}

#[test]
fn traversed_ancestor_exception_adds_only_directory_creation_and_stays_internal() {
    let policy = policy();
    for bit in 0..32 {
        let mask = 1 << bit;
        let bytes = ancestor(USER, 0, mask);
        assert_eq!(
            validate_traversed_ancestor(&bytes, &policy.owner).is_ok(),
            mask & !(GUARDED_ANCESTOR_RIGHTS | 4) == 0,
            "right {mask:08x}"
        );
    }
    let bytes = ancestor(TRUSTED_INSTALLER, 0, GUARDED_ANCESTOR_RIGHTS | 4);
    validate_traversed_ancestor(&bytes, &policy.owner).unwrap();
    assert!(policy.validate_ancestor_descriptor(&bytes).is_err());
    assert!(
        policy
            .validate_descriptor(&bytes, ObjectKind::Directory)
            .is_err()
    );
    assert!(policy.validate_inherited_file_descriptor(&bytes).is_err());
    assert!(validate_traversed_ancestor(&ancestor(EVERYONE, 0, 1), &policy.owner).is_err());
    for flag in 0..=255 {
        assert_eq!(
            validate_traversed_ancestor(&ancestor(USER, flag, FILE_ALL_ACCESS), &policy.owner)
                .is_ok(),
            flag & !0x1f == 0 && flag & 8 != 0
        );
    }
}

#[test]
fn ancestor_policy_trusts_only_the_exact_system_service_and_refuses_unrecognized_aces() {
    let mut bytes = descriptor_with_owner(ObjectKind::Directory, &[TRUSTED_INSTALLER], USER);
    policy().validate_ancestor_descriptor(&bytes).unwrap();
    // A neighboring service SID with the same authority is not trusted.
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        policy().validate_ancestor_descriptor(&bytes),
        Err(Error::UnexpectedDacl)
    ));
    let original = ancestor(USER, 0, 1);
    for ace_type in 1..=255 {
        let mut changed = original.clone();
        changed[20 + USER.len() + 8] = ace_type;
        assert!(policy().validate_ancestor_descriptor(&changed).is_err());
    }
    for end in 0..original.len() {
        assert!(
            policy()
                .validate_ancestor_descriptor(&original[..end])
                .is_err()
        );
    }
    let mut broad = ancestor(USER, 0, FILE_ALL_ACCESS);
    // Replacing the parent owner does not make a broad trustee safe.
    broad[2] |= 1;
    assert!(policy().validate_ancestor_descriptor(&broad).is_err());
}

proptest! {
    #[test]
    fn arbitrary_descriptor_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = policy().validate_descriptor(&bytes, ObjectKind::File);
        let _ = policy().validate_descriptor(&bytes, ObjectKind::Directory);
        let _ = policy().validate_inherited_file_descriptor(&bytes);
        let _ = policy().validate_ancestor_descriptor(&bytes);
        let _ = validate_traversed_ancestor(&bytes, &policy().owner);
    }

    #[test]
    fn arbitrary_offsets_are_bounded(owner in any::<u32>(), group in any::<u32>(), sacl in any::<u32>(), dacl in any::<u32>()) {
        let mut bytes = valid(ObjectKind::File);
        for (field, value) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
            bytes[field..field+4].copy_from_slice(&value.to_le_bytes());
        }
        let _ = policy().validate_descriptor(&bytes, ObjectKind::File);
        let mut inherited = inherited(&[USER, SYSTEM, ADMINISTRATORS], USER);
        for (field, value) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
            inherited[field..field+4].copy_from_slice(&value.to_le_bytes());
        }
        let _ = policy().validate_inherited_file_descriptor(&inherited);
        let mut ancestor = ancestor(USER, 0, 1);
        for (field, value) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
            ancestor[field..field+4].copy_from_slice(&value.to_le_bytes());
        }
        let _ = policy().validate_ancestor_descriptor(&ancestor);
        let _ = validate_traversed_ancestor(&ancestor, &policy().owner);
    }
}
