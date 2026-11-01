//! Read-only installed-asset probe; the hosted harness creates its own assets.
#![forbid(unsafe_code)]
use agentswapper_linux_runtime::{
    installed_config::ProtectedConfig, installed_image::ProtectedImage,
};
use std::{io, path::Path};

fn run() -> io::Result<()> {
    if rustix::process::getuid().is_root()
        || rustix::process::getuid() != rustix::process::geteuid()
        || rustix::process::getgid() != rustix::process::getegid()
    {
        return Err(io::Error::other("ordinary matching identities required"));
    }
    let args: Vec<_> = std::env::args_os().collect();
    match args.as_slice() {
        [_, path] => {
            let _image = ProtectedImage::open(Path::new(path))?;
        }
        [_, mode, path] if mode == "--config" => {
            ProtectedConfig::open(Path::new(path))?.read()?;
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
