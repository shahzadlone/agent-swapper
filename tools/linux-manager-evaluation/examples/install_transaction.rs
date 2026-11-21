//! Disposable install/upgrade/removal transaction exercise for the producer
//! side of the installation contract. It stages real generations under a
//! caller-provided root, cross-validates them with the installed readers at
//! the derived fixed paths, and proves overwrite refusal, upgrade selection,
//! generation retention and rollback. Never touches /etc, /usr or /run and
//! performs no service control. Run as root: the readers require root-owned
//! protected ancestry.
use agentswapper_linux_runtime::{
    install_plan::{Assets, Layout},
    installed_artifacts::InstalledArtifacts,
    installed_manifest::InstalledManifest,
};
use std::{io, path::Path, process};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn assets(role: u8) -> Assets {
    Assets {
        guardian: vec![b'g', role, b'!'],
        session_helper: vec![b's', role, b'!'],
        exec_shim: vec![b'e', role, b'!'],
    }
}

fn verify_reader(layout: &Layout) -> io::Result<()> {
    let manifest = InstalledManifest::open_for_qualification(
        &layout.manifest(),
        layout.identity().0,
        layout.identity().1,
        layout.generation(),
    )?;
    require(
        manifest.generation() == layout.generation(),
        "reader selected a different generation",
    )?;
    let artifacts = InstalledArtifacts::open_paths_for_qualification(
        manifest,
        [
            &layout.image("guardian"),
            &layout.image("session-helper"),
            &layout.image("exec-shim"),
        ],
        [&layout.service_template(), &layout.socket_unit()],
    )?;
    artifacts.require_current()?;
    Ok(())
}

fn run(root: &Path, first: &str, second: &str, third: &str) -> io::Result<()> {
    let (user, group) = (1000, 1001);
    require(
        rustix::process::getuid().as_raw() == 0,
        "transaction exercise requires a root-owned protected ancestry",
    )?;
    let first_layout = Layout::for_qualification(root, user, group, first)?;
    first_layout.stage(&assets(1))?.activate()?;
    verify_reader(&first_layout)?;

    // Overwrite refusal: restaging an existing generation never touches it.
    require(
        first_layout.stage(&assets(9)).is_err(),
        "restaging an existing generation was accepted",
    )?;
    verify_reader(&first_layout)?;

    // Upgrade: a distinct generation stages and the selector moves atomically
    // while the old generation stays completely intact.
    let second_layout = Layout::for_qualification(root, user, group, second)?;
    second_layout.stage(&assets(2))?.activate()?;
    verify_reader(&second_layout)?;
    verify_reader(&first_layout)?;
    let selected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(second_layout.selector())?)?;
    require(
        selected["generation"] == second,
        "selector did not move to the new generation",
    )?;

    // Rollback: a staged but unactivated generation leaves nothing behind.
    // Earlier generations' directories stay; only this transaction's files
    // and its own new directories are removed.
    let discarded = Layout::for_qualification(root, user, group, third)?;
    let staged = discarded.stage(&assets(3))?;
    staged.rollback()?;
    require(
        std::fs::symlink_metadata(discarded.image("guardian")).is_err(),
        "rolled-back staging left its guardian image behind",
    )?;
    require(
        std::fs::symlink_metadata(discarded.image("guardian").parent()).is_err(),
        "rolled-back staging left its generation directory behind",
    )?;
    require(
        std::fs::symlink_metadata(discarded.manifest()).is_err(),
        "rolled-back staging left its manifest behind",
    )?;

    // Removal: deleting a generation's files leaves a dangling selector that
    // every reader refuses, without disturbing the retained generation.
    for path in [
        second_layout.manifest(),
        second_layout.image("guardian"),
        second_layout.image("session-helper"),
        second_layout.image("exec-shim"),
        second_layout.service_template(),
        second_layout.socket_unit(),
    ] {
        std::fs::remove_file(&path)?;
    }
    require(
        InstalledManifest::open_for_qualification(&second_layout.manifest(), user, group, second)
            .is_err(),
        "a removed generation's manifest still opened",
    )?;
    verify_reader(&first_layout)?;

    // Re-installation after removal uses fresh inodes at the same paths.
    let replacement = Layout::for_qualification(root, user, group, second)?;
    replacement.stage(&assets(4))?.activate()?;
    verify_reader(&replacement)?;
    Ok(())
}

fn main() -> process::ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [root, first, second, third] if root.starts_with('/') => {
            run(Path::new(root), first, second, third)
        }
        _ => Err(io::Error::other(
            "install transaction requires ROOT GEN GEN GEN",
        )),
    };
    match result {
        Ok(()) => {
            println!(
                "install transaction: staged, selected, retained, refused, rolled back, removed and replaced"
            );
            process::ExitCode::SUCCESS
        }
        Err(error) => {
            let diagnostic: String = error
                .to_string()
                .escape_debug()
                .take(2000)
                .collect::<String>();
            eprintln!("install transaction refused: {diagnostic}");
            // Surface the bounded refusal where every reader can see it.
            println!(
                "::error title=install transaction::{}",
                diagnostic
                    .replace('%', "%25")
                    .replace('\r', "%0D")
                    .replace('\n', "%0A")
            );
            process::ExitCode::from(125)
        }
    }
}
