//! An authenticated direct target's wait status. This is a statement about
//! one reaped child only; it says nothing about remaining writers, custody or
//! any other scope. The encoding matches the journal's pinned serialization.
use serde::{Deserialize, Serialize};
use std::io;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// A direct target's wait status, never a statement about remaining writers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetExit {
    Code { code: u8 },
    Signal { signal: u8, core_dumped: bool },
}

impl TargetExit {
    /// Refuse a termination signal outside the real-time range; an unknown
    /// signal number could otherwise fabricate a status the kernel never sent.
    pub fn validate(self) -> io::Result<Self> {
        if let Self::Signal { signal, .. } = self {
            require(
                (1..=64).contains(&signal),
                "invalid target termination signal",
            )?;
        }
        Ok(self)
    }
    /// Decode one Linux wait status. A stopped or continued target is not an
    /// exit; the waiter reports those separately.
    pub fn from_raw(raw: i32) -> io::Result<Self> {
        // Linux: WIFSTOPPED is (raw & 0xff) == 0x7f and WIFCONTINUED is
        // 0xffff; neither is a termination.
        require(
            (raw & 0xff) != 0x7f && raw != 0xffff,
            "a stopped or continued target is not an exit",
        )?;
        let low = raw & 0x7f;
        if low == 0 {
            let code = ((raw >> 8) & 0xff) as u8;
            return Ok(Self::Code { code });
        }
        let signal = low as u8;
        Ok(Self::Signal {
            signal,
            core_dumped: raw & 0x80 != 0,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn wait_statuses_decode_into_authenticated_exit_shapes() -> io::Result<()> {
        assert_eq!(TargetExit::from_raw(0)?, TargetExit::Code { code: 0 });
        assert_eq!(TargetExit::from_raw(0x0700)?, TargetExit::Code { code: 7 });
        assert_eq!(
            TargetExit::from_raw(0xff00)?,
            TargetExit::Code { code: 255 }
        );
        assert_eq!(
            TargetExit::from_raw(15)?,
            TargetExit::Signal {
                signal: 15,
                core_dumped: false
            }
        );
        assert_eq!(
            TargetExit::from_raw(0x80 | 11)?,
            TargetExit::Signal {
                signal: 11,
                core_dumped: true
            }
        );
        // Stopped, continued and unknown shapes refuse; 0x7f00 is a real
        // exit with code 127.
        assert_eq!(
            TargetExit::from_raw(0x7f00)?,
            TargetExit::Code { code: 127 }
        );
        assert!(TargetExit::from_raw(0x7f).is_err());
        assert!(TargetExit::from_raw(0xffff).is_err());
        assert!(
            TargetExit::Signal {
                signal: 0,
                core_dumped: false
            }
            .validate()
            .is_err()
        );
        assert!(
            TargetExit::Signal {
                signal: 65,
                core_dumped: false
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            TargetExit::Signal {
                signal: 64,
                core_dumped: true
            }
            .validate()?,
            TargetExit::Signal {
                signal: 64,
                core_dumped: true
            }
        );
        Ok(())
    }

    #[test]
    fn the_pinned_serialization_shape_is_stable() -> io::Result<()> {
        assert_eq!(
            serde_json::to_value(TargetExit::Code { code: 3 })?,
            serde_json::json!({"kind": "code", "code": 3})
        );
        assert_eq!(
            serde_json::to_value(TargetExit::Signal {
                signal: 9,
                core_dumped: false
            })?,
            serde_json::json!({"kind": "signal", "signal": 9, "core_dumped": false})
        );
        // Unknown fields refuse on decode.
        assert!(
            serde_json::from_value::<TargetExit>(serde_json::json!({
                "kind": "code", "code": 3, "extra": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TargetExit>(serde_json::json!({
                "kind": "unknown"
            }))
            .is_err()
        );
        Ok(())
    }
}
