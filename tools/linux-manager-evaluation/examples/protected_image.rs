//! Read-only image-policy probe; the hosted harness creates its own test assets.
#![forbid(unsafe_code)]
use agentswapper_linux_runtime::installed_image::ProtectedImage;
use std::{io, path::Path};

fn run() -> io::Result<()> {
    if rustix::process::getuid().is_root()
        || rustix::process::getuid() != rustix::process::geteuid()
        || rustix::process::getgid() != rustix::process::getegid()
    {
        return Err(io::Error::other("ordinary matching identities required"));
    }
    let args: Vec<_> = std::env::args_os().collect();
    let [_, path] = args.as_slice() else {
        return Err(io::Error::other("expected one fixture image path"));
    };
    let _image = ProtectedImage::open(Path::new(path))?;
    println!("protected-image: accepted");
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("protected-image: {error}");
            std::process::ExitCode::from(125)
        }
    }
}
