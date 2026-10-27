use std::{ffi::OsString, path::PathBuf};

use agentswapper_core::{
    Result, Store,
    config::{ConfigEntry, ConfigKey, ConfigStore},
    terminal_text,
};
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Show effective values, defaults and whether each preference is saved.
    List,
    /// Inspect one preference (history.limit or ui.mask).
    Get {
        #[arg(allow_hyphen_values = true)]
        key: OsString,
    },
    /// Save a non-secret preference. No execution or authentication settings.
    Set {
        #[arg(allow_hyphen_values = true)]
        key: OsString,
        #[arg(allow_hyphen_values = true)]
        value: OsString,
    },
    /// Remove an override and return to its built-in default.
    Unset {
        #[arg(allow_hyphen_values = true)]
        key: OsString,
    },
    /// Print the preferences file path without creating it.
    Path,
}

pub(crate) fn dispatch(
    command: Option<ConfigCommands>,
    root: Option<PathBuf>,
    json_mode: bool,
) -> Result<i32> {
    let root = match root {
        Some(root) => root,
        None => Store::default_root()?,
    };
    let store = ConfigStore::new(&root)?;
    match command.unwrap_or(ConfigCommands::List) {
        ConfigCommands::Path => {
            let path = store.path();
            super::emit(
                json_mode,
                &json!({"path":path}),
                &terminal_text(&path.display().to_string()),
            )?;
        }
        ConfigCommands::List => {
            let entries = store.load()?.entries();
            let text = entries
                .iter()
                .map(entry_line)
                .collect::<Vec<_>>()
                .join("\n");
            super::emit(json_mode, &entries, &text)?;
        }
        ConfigCommands::Get { key } => {
            let key = ConfigKey::parse(
                key.to_str()
                    .ok_or(agentswapper_core::Error::UnknownConfigKey)?,
            )?;
            let entry = store.load()?.entry(key);
            super::emit(json_mode, &entry, &entry_line(&entry))?;
        }
        ConfigCommands::Set { key, value } => {
            let key = ConfigKey::parse(
                key.to_str()
                    .ok_or(agentswapper_core::Error::UnknownConfigKey)?,
            )?;
            let entry = store
                .set(
                    key,
                    value
                        .to_str()
                        .ok_or(agentswapper_core::Error::InvalidConfigValue)?,
                )?
                .entry(key);
            super::emit(json_mode, &entry, &format!("Saved {}", entry_line(&entry)))?;
        }
        ConfigCommands::Unset { key } => {
            let key = ConfigKey::parse(
                key.to_str()
                    .ok_or(agentswapper_core::Error::UnknownConfigKey)?,
            )?;
            let entry = store.unset(key)?.entry(key);
            super::emit(json_mode, &entry, &format!("Reset {}", entry_line(&entry)))?;
        }
    }
    Ok(0)
}
fn entry_line(entry: &ConfigEntry) -> String {
    format!(
        "{} = {} ({}, default: {})",
        entry.key, entry.value, entry.source, entry.default
    )
}
