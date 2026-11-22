//! The root-installed guardian entry. After exec the helper re-derives its
//! own image facts, binds them to the installed manifest, and only then
//! considers its service role. This entry performs no launch: the production
//! launch protocol remains a separately qualified gate.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::entry;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::*;

    const GENERATION: &str = "00112233445566778899aabbccddeeff";

    fn unit(instance: &str) -> String {
        format!("agentswapper-1000-{GENERATION}@{instance}.service")
    }

    #[test]
    fn unit_names_carry_exactly_the_installed_identity() {
        assert_eq!(
            parse_unit(&unit("17-1000")).ok(),
            Some((1000, GENERATION.to_owned()))
        );
        for bad in [
            "other.service",
            "agentswapper-1000.service",
            "agentswapper-0-00112233445566778899aabbccddeeff@x.service",
            "agentswapper-1000-00112233445566778899aabbccddeeff.service",
            "agentswapper-1000-00112233445566778899aabbccddeeff@.service",
            "agentswapper-1000-00112233445566778899aabbccddeeff@-x.service",
            "agentswapper-1000-00112233445566778899aabbccddeeff@x-.service",
            "agentswapper-1000-00112233445566778899aabbccddeeff@X.service",
            "agentswapper-1000-00112233445566778899aabbccddeefff@x.service",
            "agentswapper-1000-../escape@x.service",
            &format!("agentswapper-1000-{GENERATION}@{}.service", "x".repeat(65)),
        ] {
            assert!(parse_unit(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_entry_refuses_without_its_argument() {
        let args: Vec<String> = vec!["guardian".into()];
        assert!(entry(&args).is_err());
        let args: Vec<String> = vec!["guardian".into(), "unrelated".into(), "x".into()];
        assert!(entry(&args).is_err());
    }

    #[test]
    fn the_entry_refuses_outside_an_installed_host() {
        // No installed manifest exists on a development machine; the entry
        // must refuse with its fixed diagnostic either way.
        let args: Vec<String> = vec!["guardian".into(), unit("17-1000")];
        // Without an installed manifest the entry refuses, whatever the
        // reader's fixed diagnostic is.
        assert!(entry(&args).is_err());
    }
}
