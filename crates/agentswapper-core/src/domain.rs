use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, Result};

/// A validated label. Profile paths always use an opaque ID instead.
///
/// ```
/// use agentswapper_core::Alias;
/// let alias: Alias = "work-laptop".parse()?;
/// assert_eq!(alias.to_string(), "work-laptop");
/// assert!("../credentials".parse::<Alias>().is_err());
/// # Ok::<(), agentswapper_core::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Alias(String);

impl FromStr for Alias {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let valid = (1..=32).contains(&value.len())
            && value.as_bytes()[0].is_ascii_lowercase()
            && value
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !valid {
            return Err(Error::InvalidAlias);
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for Alias {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<Alias> for String {
    fn from(value: Alias) -> Self {
        value.0
    }
}

impl fmt::Display for Alias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(Uuid);

impl ProfileId {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ProfileId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| Error::CorruptRegistry)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Harness {
    Claude,
    Codex,
    Kimi,
}

impl Harness {
    pub const ALL: [Self; 3] = [Self::Claude, Self::Codex, Self::Kimi];

    pub fn home_variable(self) -> &'static str {
        match self {
            Self::Claude => "CLAUDE_CONFIG_DIR",
            Self::Codex => "CODEX_HOME",
            Self::Kimi => "KIMI_CODE_HOME",
        }
    }

    pub fn conflicts(self) -> &'static [&'static str] {
        match self {
            Self::Claude => &[
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_PROFILE",
                "ANTHROPIC_CUSTOM_HEADERS",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "CLAUDE_CODE_USE_BEDROCK",
                "CLAUDE_CODE_USE_VERTEX",
                "CLAUDE_CODE_USE_FOUNDRY",
                "CLAUDE_CONFIG_DIR",
            ],
            Self::Codex => &[
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "OPENAI_ORG_ID",
                "OPENAI_ORGANIZATION",
                "OPENAI_PROJECT_ID",
                "CODEX_API_KEY",
                "CODEX_HOME",
            ],
            Self::Kimi => &[
                "KIMI_API_KEY",
                "KIMI_BASE_URL",
                "KIMI_CODE_HOME",
                "MOONSHOT_API_KEY",
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
            ],
        }
    }

    pub fn login_args(self) -> &'static [&'static str] {
        match self {
            Self::Claude => &["auth", "login"],
            Self::Codex | Self::Kimi => &["login"],
        }
    }
}

impl fmt::Display for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Kimi => "kimi",
        })
    }
}

impl FromStr for Harness {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "kimi" => Ok(Self::Kimi),
            _ => Err(Error::CorruptRegistry),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: ProfileId,
    pub alias: Alias,
    pub harness: Harness,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn accepted_aliases_are_safe_and_round_trip(value in ".{0,100}") {
            if let Ok(alias) = value.parse::<Alias>() {
                prop_assert!(!value.is_empty() && value.len() <= 32);
                prop_assert!(value.as_bytes()[0].is_ascii_lowercase());
                prop_assert!(value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
                let json = serde_json::to_string(&alias)?;
                prop_assert_eq!(serde_json::from_str::<Alias>(&json)?, alias);
            }
        }

        #[test]
        fn valid_aliases_are_accepted(value in "[a-z][a-z0-9-]{0,31}") {
            prop_assert!(value.parse::<Alias>().is_ok());
        }
    }

    #[test]
    fn deserialization_cannot_bypass_validation() {
        assert!(serde_json::from_str::<Alias>(r#""../secret""#).is_err());
        for value in ["", "1", "WORK", "../work", "a\x1b[31m", "a_b", "a/b"] {
            assert!(value.parse::<Alias>().is_err());
        }
    }
}
