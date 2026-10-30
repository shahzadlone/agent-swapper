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
    descriptor.extend(((20 + USER.len()) as u32).to_le_bytes());
    descriptor.extend(USER);
    descriptor.extend(acl);
    descriptor
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

proptest! {
    #[test]
    fn arbitrary_descriptor_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = policy().validate_descriptor(&bytes, ObjectKind::File);
        let _ = policy().validate_descriptor(&bytes, ObjectKind::Directory);
    }

    #[test]
    fn arbitrary_offsets_are_bounded(owner in any::<u32>(), group in any::<u32>(), sacl in any::<u32>(), dacl in any::<u32>()) {
        let mut bytes = valid(ObjectKind::File);
        for (field, value) in [(4, owner), (8, group), (12, sacl), (16, dacl)] {
            bytes[field..field+4].copy_from_slice(&value.to_le_bytes());
        }
        let _ = policy().validate_descriptor(&bytes, ObjectKind::File);
    }
}
