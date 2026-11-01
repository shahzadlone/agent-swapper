//! Read-only validation shared by the client library and fixture binary.
use std::io;

pub(crate) fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

pub(crate) fn identity_map(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| s.split_whitespace().eq(["0", "0", "4294967295"]))
}

pub(crate) fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
