use agentswapper_linux_runtime::{installed_manifest::InstalledManifest, self_image::SelfImage};
use std::{io, os::fd::AsFd};

pub(crate) mod activation;
pub(crate) mod launch;
pub(crate) mod shim;

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
                && instance
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
/// then serve the activation session on the manager-supplied connection.
/// Launch data is refused inside the session; the production launch protocol
/// remains a separately qualified gate.
pub fn entry(args: &[String]) -> io::Result<()> {
    if args.len() == 3 && args[1] == "exec-shim" {
        let control = std::io::stdin().as_fd().try_clone_to_owned()?;
        return shim::run(&control, &args[2]);
    }
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
        rustix::process::getuid().as_raw() == user && rustix::process::getgid().as_raw() == group,
        "the guardian service runs outside its installed identity",
    )?;
    let (shim_path, _) = manifest.exec_shim();
    activation::run(user, group, &args[1], &shim_path)
}
