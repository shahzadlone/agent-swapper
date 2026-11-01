//! Read-only installed-asset probe; the hosted harness creates its own assets.
#![forbid(unsafe_code)]
use agentswapper_linux_runtime::{
    installed_artifacts::InstalledArtifacts, installed_config::ProtectedConfig,
    installed_image::ProtectedImage, installed_manifest::InstalledManifest,
};
use std::{
    io::{self, Read, Write},
    path::Path,
};
const FIXTURE_SHA256: &str = "5b47177a0de17ca8c0bd2c1fda5d757ae4ed450cab5dada43018e9d7b9095dd9";

fn hold() -> io::Result<()> {
    println!("installed-asset: retained");
    io::stdout().flush()?;
    // The qualification harness bounds this wait and drops root before exec.
    let mut command = [0; 1];
    io::stdin().read_exact(&mut command)?;
    if command != *b"R" {
        return Err(io::Error::other("invalid asset recheck request"));
    }
    Ok(())
}

fn run() -> io::Result<()> {
    if rustix::process::getuid().is_root()
        || rustix::process::getuid() != rustix::process::geteuid()
        || rustix::process::getgid() != rustix::process::getegid()
    {
        return Err(io::Error::other("ordinary matching identities required"));
    }
    let args: Vec<_> = std::env::args_os().collect();
    match args.as_slice() {
        [_, mode] if mode == "--manifest-version" => {
            println!(
                "{}",
                agentswapper_linux_runtime::installed_manifest::VERSION
            );
            return Ok(());
        }
        [_, path] => {
            let _image = ProtectedImage::open(Path::new(path))?;
        }
        [_, mode, path] if mode == "--config" => {
            ProtectedConfig::open(Path::new(path))?.read()?;
        }
        [_, mode, path] if mode == "--config-digest" => {
            let config = ProtectedConfig::open(Path::new(path))?;
            config.require_sha256(FIXTURE_SHA256)?;
            config.require_current(Path::new(path))?;
        }
        [_, mode, path] if mode == "--image-digest" || mode == "--image-recheck" => {
            let image = ProtectedImage::open(Path::new(path))?;
            image.require_sha256(FIXTURE_SHA256)?;
            if mode == "--image-recheck" {
                hold()?;
            }
            image.require_current(Path::new(path))?;
        }
        [_, mode, path] if mode == "--manifest" => {
            let manifest = InstalledManifest::open_for_qualification(
                Path::new(path),
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
                "00112233445566778899aabbccddeeff",
            )?;
            manifest.require_current()?;
        }
        [_, mode, path] if mode == "--bundle" || mode == "--bundle-recheck" => {
            let path = Path::new(path);
            let manifest = InstalledManifest::open_for_qualification(
                path,
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
                "00112233445566778899aabbccddeeff",
            )?;
            let artifacts = InstalledArtifacts::open_for_qualification(
                manifest,
                path.parent()
                    .ok_or_else(|| io::Error::other("missing fixture directory"))?,
            )?;
            if mode == "--bundle-recheck" {
                hold()?;
            }
            artifacts.require_current()?;
        }
        [_, mode, path] if mode == "--config-recheck" => {
            let config = ProtectedConfig::open(Path::new(path))?;
            config.read()?;
            hold()?;
            config.require_current(Path::new(path))?;
        }
        _ => return Err(io::Error::other("expected an installed fixture asset path")),
    }
    println!("installed-asset: accepted");
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("installed-asset: {error}");
            std::process::ExitCode::from(125)
        }
    }
}
