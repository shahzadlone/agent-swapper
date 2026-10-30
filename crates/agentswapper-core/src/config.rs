//! Non-secret display preferences. This file never authorizes execution.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result, private_fs};

const VERSION: u32 = 1;
const MAX_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigKey {
    HistoryLimit,
    UiMask,
}
impl ConfigKey {
    pub const ALL: [Self; 2] = [Self::HistoryLimit, Self::UiMask];
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "history.limit" => Ok(Self::HistoryLimit),
            "ui.mask" => Ok(Self::UiMask),
            _ => Err(Error::UnknownConfigKey),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HistoryLimit => "history.limit",
            Self::UiMask => "ui.mask",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Overrides {
    #[serde(
        default,
        rename = "history.limit",
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    history_limit: Option<u16>,
    #[serde(
        default,
        rename = "ui.mask",
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    ui_mask: Option<bool>,
}

// Absence means default; a present null is an invalid typed setting.
fn present_value<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    settings: Overrides,
}
impl Default for Document {
    fn default() -> Self {
        Self {
            version: VERSION,
            settings: Overrides::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Preferences {
    overrides: Overrides,
}

#[derive(Debug, Serialize)]
pub struct ConfigEntry {
    pub key: &'static str,
    pub value: Value,
    pub default: Value,
    pub source: &'static str,
}

impl Preferences {
    pub fn history_limit(&self) -> u16 {
        self.overrides.history_limit.unwrap_or(20)
    }
    pub fn ui_mask(&self) -> bool {
        self.overrides.ui_mask.unwrap_or(false)
    }
    pub fn entry(&self, key: ConfigKey) -> ConfigEntry {
        let (value, default, saved) = match key {
            ConfigKey::HistoryLimit => (
                Value::from(self.history_limit()),
                Value::from(20),
                self.overrides.history_limit.is_some(),
            ),
            ConfigKey::UiMask => (
                Value::from(self.ui_mask()),
                Value::from(false),
                self.overrides.ui_mask.is_some(),
            ),
        };
        ConfigEntry {
            key: key.as_str(),
            value,
            default,
            source: if saved { "config" } else { "default" },
        }
    }
    pub fn entries(&self) -> Vec<ConfigEntry> {
        ConfigKey::ALL
            .into_iter()
            .map(|key| self.entry(key))
            .collect()
    }
}

/// Resolve the selected state root without creating it or opening the registry.
pub struct ConfigStore {
    root: PathBuf,
}
impl ConfigStore {
    pub fn new(root: &Path) -> Result<Self> {
        let store = Self {
            root: private_fs::normalize_root(root)?,
        };
        store.root_exists()?;
        Ok(store)
    }
    pub fn path(&self) -> PathBuf {
        self.root.join("config.json")
    }
    fn root_exists(&self) -> Result<bool> {
        match fs::symlink_metadata(&self.root) {
            Ok(_) => {
                private_fs::directory(&self.root, false)?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn read_document(&self) -> Result<Document> {
        if !self.root_exists()? {
            return Ok(Document::default());
        }
        #[cfg(windows)]
        let _private_root = private_fs::StateRoot::open(&self.root, false)?;
        let file = match open_checked(&self.path(), false) {
            Ok(file) => file,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Document::default());
            }
            Err(e) => return Err(e),
        };
        if file.metadata()?.len() > MAX_BYTES {
            return Err(Error::ConfigTooLarge);
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::ConfigTooLarge);
        }
        #[derive(Deserialize)]
        struct VersionHeader {
            version: u32,
        }
        let header: VersionHeader =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidConfig)?;
        if header.version > VERSION {
            return Err(Error::NewerConfig);
        }
        let document: Document =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidConfig)?;
        if document.version != VERSION
            || document
                .settings
                .history_limit
                .is_some_and(|limit| !(1..=200).contains(&limit))
        {
            return Err(Error::InvalidConfig);
        }
        Ok(document)
    }
    pub fn load(&self) -> Result<Preferences> {
        Ok(Preferences {
            overrides: self.read_document()?.settings,
        })
    }
    pub fn set(&self, key: ConfigKey, value: &str) -> Result<Preferences> {
        let edit = match key {
            ConfigKey::HistoryLimit => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(Error::InvalidConfigValue);
                }
                let limit = value
                    .parse::<u16>()
                    .ok()
                    .filter(|n| (1..=200).contains(n))
                    .ok_or(Error::InvalidConfigValue)?;
                Edit::History(Some(limit))
            }
            ConfigKey::UiMask => Edit::Mask(Some(match value {
                "true" => true,
                "false" => false,
                _ => return Err(Error::InvalidConfigValue),
            })),
        };
        self.update(edit)
    }
    pub fn unset(&self, key: ConfigKey) -> Result<Preferences> {
        // No file or lock is needed to reset an entirely absent state directory.
        if !self.root_exists()? {
            return Ok(Preferences::default());
        }
        self.update(match key {
            ConfigKey::HistoryLimit => Edit::History(None),
            ConfigKey::UiMask => Edit::Mask(None),
        })
    }
    fn update(&self, edit: Edit) -> Result<Preferences> {
        #[cfg(windows)]
        let _private_root = private_fs::StateRoot::open(&self.root, true)?;
        private_fs::directory(&self.root, true)?;
        let lock = open_checked(&self.root.join("config.lock"), true)?;
        let started = Instant::now();
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock)
                    if started.elapsed() < Duration::from_secs(3) =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(std::fs::TryLockError::WouldBlock) => return Err(Error::ConfigBusy),
                Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
            }
        }
        let mut document = self.read_document()?;
        let changed = match edit {
            Edit::History(value) => {
                let changed = document.settings.history_limit != value;
                document.settings.history_limit = value;
                changed
            }
            Edit::Mask(value) => {
                let changed = document.settings.ui_mask != value;
                document.settings.ui_mask = value;
                changed
            }
        };
        if changed {
            let mut file = tempfile::Builder::new()
                .prefix(".config-")
                .tempfile_in(&self.root)?;
            validate_handle(file.as_file(), true)?;
            serde_json::to_writer_pretty(&mut file, &document)?;
            file.write_all(b"\n")?;
            file.as_file().sync_all()?;
            publish(file, &self.path(), &self.root, sync_directory)?;
        }
        Ok(Preferences {
            overrides: document.settings,
        })
    }
}

fn publish(
    mut file: tempfile::NamedTempFile,
    path: &Path,
    root: &Path,
    sync: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let started = Instant::now();
    loop {
        // Check the open handle too (including Windows link count). A same-user
        // malicious replacement after this check is outside the trust boundary.
        match open_checked(path, false) {
            Ok(_) => {}
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(Error::Io(e)) if retry_replace(&e, started) => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(e) => return Err(e),
        }
        match file.persist(path) {
            Ok(_) => break,
            Err(e) if retry_replace(&e.error, started) => {
                file = e.file;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(Error::Io(e.error)),
        }
    }
    sync(root).map_err(|_| Error::ConfigDurability)
}

fn retry_replace(error: &std::io::Error, started: Instant) -> bool {
    #[cfg(windows)]
    {
        // Access denied, sharing violation and lock violation can be transient
        // while a scanner or editor holds the old file without delete sharing.
        matches!(error.raw_os_error(), Some(5 | 32 | 33))
            && started.elapsed() < Duration::from_secs(3)
    }
    #[cfg(not(windows))]
    {
        let _ = (error, started);
        false
    }
}

fn sync_directory(root: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(root)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Ok(())
    }
}

enum Edit {
    History(Option<u16>),
    Mask(Option<bool>),
}

fn open_checked(path: &Path, create: bool) -> Result<File> {
    #[cfg(windows)]
    if create {
        return private_fs::file(path);
    }
    private_fs::reject_links(path)?;
    // Path checks also allow a detached snapshot: an atomic replacement can
    // unlink the old inode even while metadata(path) is completing.
    match fs::symlink_metadata(path) {
        Ok(meta) if create => private_fs::validate_file_metadata(&meta)?,
        Ok(meta) => private_fs::validate_snapshot_metadata(&meta)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    validate_handle(&file, create)?;
    Ok(file)
}

fn validate_handle(file: &File, create: bool) -> Result<()> {
    if create {
        private_fs::validate_file_metadata(&file.metadata()?)?;
    } else {
        private_fs::validate_snapshot_metadata(&file.metadata()?)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let links = winapi_util::file::information(file)?.number_of_links();
        if file.metadata()?.file_attributes() & 0x400 != 0 || links > 1 || (create && links == 0) {
            return Err(Error::UnsafePath);
        }
        private_fs::validate_snapshot(file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
