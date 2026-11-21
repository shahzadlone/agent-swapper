//! The root-installed guardian entry. After exec the helper re-derives its
//! own image facts, binds them to the installed manifest, and only then
//! considers its service role. This entry performs no launch, no connection
//! and no service control yet; the production service protocol remains a
//! separately qualified gate and the entry refuses before it.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {
    use agentswapper_linux_runtime::{
        installed_manifest::InstalledManifest, self_image::SelfImage,
    };
    use std::io;

    fn require(ok: bool, message: &str) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    /// The one manager-assigned argument: the systemd unit name that started
    /// this service instance. Its stem carries the installation user; the
    /// group is the service's own primary group, fixed by the unit.
    pub(crate) fn parse_unit(unit: &str) -> io::Result<(u32, String)> {
        let invalid = || io::Error::other("guardian invocation is not its installed unit");
        let stem = unit
            .strip_suffix(".service")
            .and_then(|stem| stem.split_once('@'))
            .ok_or_else(invalid)?;
        let (stem, instance) = stem;
        let mut parts = stem.split('-');
        let identity = (parts.next(), parts.next(), parts.next(), parts.next());
        match identity {
            (Some("agentswapper"), Some(user), Some(generation), None) => {
                let user: u32 = user.parse().map_err(|_| invalid())?;
                let valid_user = user != 0 && user <= i32::MAX as u32;
                let valid_generation = generation.len() == 32
                    && generation
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && generation.bytes().any(|byte| byte != b'0');
                let valid_instance = !instance.is_empty()
                    && instance.len() <= 64
                    && instance.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
                    && !instance.starts_with('-')
                    && !instance.ends_with('-');
                require(
                    valid_user && valid_generation && valid_instance,
                    "guardian unit identity is outside the installed layout",
                )?;
                Ok((user, generation.to_owned()))
            }
            _ => Err(invalid()),
        }
    }

    /// Verify this running image against its installed manifest and identity,
    /// then refuse: the production service protocol is a separate gate.
    pub fn entry(args: &[String]) -> io::Result<()> {
        require(args.len() == 2, "guardian expects its unit name argument")?;
        let (user, generation) = parse_unit(&args[1])?;
        let group = rustix::process::getgid().as_raw();
        let manifest = InstalledManifest::open(user, group, &generation)?;
        let (path, expected) = manifest.guardian();
        require(
            path.file_name().and_then(|name| name.to_str()) == Some("guardian"),
            "the installed guardian path is unexpected",
        )?;
        let image = SelfImage::observe()?;
        require(
            image.sha256 == expected,
            "the running guardian image does not match its installed digest",
        )?;
        require(
            image.uid == 0 && image.mode == 0o755 && image.nlink == 1,
            "the running guardian is not the single root-owned installed image",
        )?;
        require(
            !image.noexec_or_nosuid && !image.file_capabilities,
            "the running guardian image lost its protected mount and capability policy",
        )?;
        require(
            rustix::process::getuid().as_raw() == user
                && rustix::process::getgid().as_raw() == group,
            "the guardian service runs outside its installed identity",
        )?;
        Err(io::Error::other(
            "the production guardian service protocol is not enabled",
        ))
    }
}

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
