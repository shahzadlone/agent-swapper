use std::{
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    time::Duration,
};

use agentswapper_core::{
    Alias, Error, Harness, Result, Store,
    handover::{self, ExposeSecret, HandoverPack, SecretString, WorkspaceAnchor},
    terminal_text,
};
use clap::Subcommand;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub(crate) enum HandoverCommands {
    /// Encrypt an existing HANDOVER.md. Does not stop or switch an agent.
    Pack {
        #[arg(long)]
        from: Alias,
        #[arg(long)]
        input: PathBuf,
        /// New encrypted output file; existing files are never replaced.
        #[arg(long)]
        output: PathBuf,
        /// Directory to record as the workspace. Defaults to the current directory.
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(flatten)]
        secret: PassphraseInput,
    },
    /// Unlock and inspect metadata. Imported note content is not printed.
    Inspect {
        file: PathBuf,
        #[command(flatten)]
        secret: PassphraseInput,
    },
    /// Unlock and print a manual pickup note. Never launches the target agent.
    Pickup {
        file: PathBuf,
        /// Intended receiver; a label, not an automatic network disclosure.
        #[arg(long, value_parser = super::parse_harness)]
        target: Harness,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(flatten)]
        secret: PassphraseInput,
    },
}

#[derive(clap::Args)]
pub(crate) struct PassphraseInput {
    /// Read one passphrase line from a pipe. Default: hidden terminal prompt.
    #[arg(long)]
    passphrase_stdin: bool,
}

impl PassphraseInput {
    fn read(&self, confirm: bool, interrupted: &impl Fn() -> bool) -> Result<SecretString> {
        if self.passphrase_stdin {
            if io::stdin().is_terminal() {
                return Err(Error::PassphraseInput);
            }
            let mut value = Zeroizing::new(String::new());
            io::stdin().take(4099).read_to_string(&mut value)?;
            if value.len() > 4098 {
                return Err(Error::InvalidPassphrase);
            }
            if value.ends_with('\n') {
                value.pop();
                if value.ends_with('\r') {
                    value.pop();
                }
            }
            if value.chars().any(char::is_control) || value.len() > 4096 || value.is_empty() {
                return Err(Error::InvalidPassphrase);
            }
            let secret = SecretString::from(value.to_string());
            if confirm {
                handover::validate_new_passphrase(&secret)?;
            }
            return Ok(secret);
        }
        if !io::stdin().is_terminal() {
            return Err(Error::PassphraseInput);
        }
        let _restore = RestoreEcho;
        crossterm::terminal::enable_raw_mode()?;
        let first = hidden_passphrase("Handover passphrase: ", interrupted)?;
        if confirm {
            handover::validate_new_passphrase(&first)?;
            let second = hidden_passphrase("Confirm passphrase: ", interrupted)?;
            if first.expose_secret() != second.expose_secret() {
                return Err(Error::PassphraseMismatch);
            }
        }
        Ok(first)
    }
}

struct RestoreEcho;
impl Drop for RestoreEcho {
    fn drop(&mut self) {
        // Discard unread secret input before re-enabling terminal echo.
        #[cfg(unix)]
        let _ = rustix::termios::tcflush(io::stdin(), rustix::termios::QueueSelector::IFlush);
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = io::stderr().write_all(b"\r\n");
    }
}

fn hidden_passphrase(prompt: &str, interrupted: &impl Fn() -> bool) -> Result<SecretString> {
    check_interrupted(interrupted)?;
    io::stderr().write_all(prompt.as_bytes())?;
    io::stderr().flush()?;
    let mut value = Zeroizing::new(String::new());
    loop {
        check_interrupted(interrupted)?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let key = match event::read()? {
            Event::Key(key) => key,
            Event::Paste(paste) => {
                let paste = Zeroizing::new(paste);
                password_paste(&mut value, &paste)?;
                continue;
            }
            _ => continue,
        };
        match password_key(&mut value, key)? {
            PasswordAction::Submit => {
                io::stderr().write_all(b"\r\n")?;
                return Ok(SecretString::from(value.to_string()));
            }
            PasswordAction::Cancel => return Err(Error::Cancelled),
            PasswordAction::Continue => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PasswordAction {
    Continue,
    Submit,
    Cancel,
}

fn password_paste(value: &mut String, paste: &str) -> Result<()> {
    if value.len() + paste.len() > 4096 || paste.chars().any(char::is_control) {
        return Err(Error::InvalidPassphrase);
    }
    value.push_str(paste);
    Ok(())
}

fn password_key(value: &mut String, key: KeyEvent) -> Result<PasswordAction> {
    if key.kind == KeyEventKind::Release {
        return Ok(PasswordAction::Continue);
    }
    // Windows AltGr is CONTROL|ALT. It enters text rather than a Ctrl shortcut.
    let shortcut =
        key.modifiers.contains(KeyModifiers::CONTROL) && !key.modifiers.contains(KeyModifiers::ALT);
    if shortcut && matches!(key.code, KeyCode::Char('c' | 'd')) {
        return Ok(PasswordAction::Cancel);
    }
    let action = match key.code {
        KeyCode::Enter => PasswordAction::Submit,
        KeyCode::Esc => PasswordAction::Cancel,
        KeyCode::Backspace
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            value.pop();
            PasswordAction::Continue
        }
        KeyCode::Char(c) if !c.is_control() && !shortcut => {
            value.push(c);
            PasswordAction::Continue
        }
        KeyCode::Modifier(_) => PasswordAction::Continue,
        _ => return Err(Error::UnsupportedPasswordKey),
    };
    if value.len() > 4096 {
        return Err(Error::InvalidPassphrase);
    }
    Ok(action)
}

pub(crate) fn dispatch(
    command: HandoverCommands,
    json_mode: bool,
    state_dir: Option<PathBuf>,
) -> Result<i32> {
    #[cfg(unix)]
    let signals = {
        let secret = match &command {
            HandoverCommands::Pack { secret, .. }
            | HandoverCommands::Inspect { secret, .. }
            | HandoverCommands::Pickup { secret, .. } => secret,
        };
        if !secret.passphrase_stdin && io::stdin().is_terminal() {
            Some(crate::terminal_signals::TerminalSignals::install()?)
        } else {
            None
        }
    };
    let interrupted = || {
        #[cfg(unix)]
        {
            signals.as_ref().is_some_and(|signals| signals.requested())
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    // Keep handlers alive through cryptography and publication. Removing them
    // immediately after a prompt would leave later signals without an action.
    let result = dispatch_inner(command, json_mode, state_dir, interrupted);
    #[cfg(unix)]
    if let Some(signals) = signals {
        signals.finish()?;
    }
    result
}

fn check_interrupted(interrupted: &impl Fn() -> bool) -> Result<()> {
    if interrupted() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

fn dispatch_inner(
    command: HandoverCommands,
    json_mode: bool,
    state_dir: Option<PathBuf>,
    interrupted: impl Fn() -> bool,
) -> Result<i32> {
    match command {
        HandoverCommands::Pack {
            from,
            input,
            output,
            workspace,
            secret,
        } => {
            let root = match state_dir {
                Some(root) => root,
                None => Store::default_root()?,
            };
            let store = Store::open(&root)?;
            let profile = store.find(&from)?;
            // Check file shape and destination before asking for a password.
            if std::fs::symlink_metadata(&output).is_ok() {
                return Err(Error::OutputExists);
            }
            let source_path = handover::validate_note_location(&input, store.root())?;
            let note = handover::read_note(&source_path)?;
            let workspace = WorkspaceAnchor::measure(&selected_workspace(workspace)?)?;
            let pack = HandoverPack::new(&profile, workspace, note)?;
            let passphrase = secret.read(true, &interrupted)?;
            check_interrupted(&interrupted)?;
            let ciphertext = pack.seal(passphrase)?;
            check_interrupted(&interrupted)?;
            let handover::PublishedPack {
                path: output,
                directory_synced,
            } = handover::write_ciphertext(&output, &ciphertext)?;
            super::emit(
                json_mode,
                &json!({"output":output,"sourcePath":source_path,"directorySynced":directory_synced,"pack":pack.summary()}),
                &format!(
                    "Encrypted handover {}\nSaved: {}\nDirectory sync: {}\nTrust: imported/unverified. No agent was stopped or switched.\nNext: aswp handover inspect PACK.age",
                    pack.summary().capsule_id,
                    terminal_text(&output.display().to_string()),
                    if directory_synced {
                        "confirmed"
                    } else {
                        "not confirmed"
                    }
                ),
            )?;
        }
        HandoverCommands::Inspect { file, secret } => {
            let ciphertext = handover::read_ciphertext(&file)?;
            let passphrase = secret.read(false, &interrupted)?;
            check_interrupted(&interrupted)?;
            let pack = HandoverPack::open(&ciphertext, passphrase)?;
            check_interrupted(&interrupted)?;
            let metadata = pack.summary();
            super::emit(
                json_mode,
                &metadata,
                &format!(
                    "Handover {}\nSource: {} (operator label)\nDocument: {} bytes\nTrust: imported/unverified\nWorkspace: {}\nGit HEAD: {}\nWorking-tree files: not checked. Note content is hidden.",
                    metadata.capsule_id,
                    metadata.source_harness,
                    metadata.document_bytes,
                    terminal_text(&metadata.workspace.directory.display().to_string()),
                    metadata.workspace.head.as_deref().unwrap_or("unknown")
                ),
            )?;
        }
        HandoverCommands::Pickup {
            file,
            target,
            workspace,
            secret,
        } => {
            let ciphertext = handover::read_ciphertext(&file)?;
            let passphrase = secret.read(false, &interrupted)?;
            check_interrupted(&interrupted)?;
            let pack = HandoverPack::open(&ciphertext, passphrase)?;
            let report = pack.reconcile(target, &selected_workspace(workspace)?)?;
            let note = Zeroizing::new(pack.render_pickup(&report));
            check_interrupted(&interrupted)?;
            if json_mode {
                super::emit(true, &json!({"report":report,"handover":note.as_str()}), "")?;
            } else {
                let mut stdout = io::stdout().lock();
                stdout.write_all(note.as_bytes())?;
                stdout.flush()?;
            }
        }
    }
    Ok(0)
}

fn selected_workspace(workspace: Option<PathBuf>) -> Result<PathBuf> {
    workspace
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn handover_password_preserves_altgr_unicode_and_repeated_characters() {
        let mut value = String::new();
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        for character in ['@', '\u{20ac}', '\u{142}', 'c'] {
            password_key(&mut value, KeyEvent::new(KeyCode::Char(character), altgr)).unwrap();
        }
        let mut repeated = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        repeated.kind = KeyEventKind::Repeat;
        password_key(&mut value, repeated).unwrap();
        assert_eq!(value, "@\u{20ac}\u{142}cx");
        repeated.kind = KeyEventKind::Release;
        password_key(&mut value, repeated).unwrap();
        assert_eq!(value, "@\u{20ac}\u{142}cx");
        assert_eq!(
            password_key(
                &mut value,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
            )
            .unwrap(),
            PasswordAction::Cancel
        );
    }

    #[test]
    fn handover_password_rejects_unsupported_editing_keys_instead_of_dropping_them() {
        let mut value = "retained".to_owned();
        assert!(matches!(
            password_key(&mut value, KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)),
            Err(Error::UnsupportedPasswordKey)
        ));
        assert_eq!(value, "retained");
        password_key(
            &mut value,
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(value, "retaine");
    }

    #[test]
    fn handover_password_preserves_pasted_text_and_refuses_pasted_controls() {
        let mut value = "prefix-".to_owned();
        password_paste(&mut value, "exact \u{20ac} text").unwrap();
        assert_eq!(value, "prefix-exact \u{20ac} text");
        assert!(password_paste(&mut value, "unexpected\nline").is_err());
        assert_eq!(value, "prefix-exact \u{20ac} text");
    }
}
