use std::{fmt, net::SocketAddr, str::FromStr};

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
    Gents,
}

impl Harness {
    pub const NATIVE: [Self; 3] = [Self::Claude, Self::Codex, Self::Kimi];
    pub const ALL: [Self; 4] = [Self::Claude, Self::Codex, Self::Kimi, Self::Gents];

    pub fn engine(self) -> ExecutionEngine {
        if self == Self::Gents {
            ExecutionEngine::Gents
        } else {
            ExecutionEngine::Native
        }
    }

    pub fn home_variable(self) -> &'static str {
        match self {
            Self::Claude => "CLAUDE_CONFIG_DIR",
            Self::Codex => "CODEX_HOME",
            Self::Kimi => "KIMI_CODE_HOME",
            Self::Gents => "GENTS_HOME",
        }
    }

    /// Gents receives an environment allowlist instead of inherited credentials.
    pub fn conflicts(self) -> &'static [&'static str] {
        match self {
            Self::Gents => &[],
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
                "CODEX_ACCESS_TOKEN",
                "CODEX_SQLITE_HOME",
                "OPENAI_FEDERATION_RULE_ID",
                "OPENAI_IDENTITY_TOKEN_FILE",
                "OPENAI_WORKLOAD_IDENTITY_CONTEXT",
                "CODEX_HOME",
            ],
            Self::Kimi => &[
                "KIMI_API_KEY",
                "KIMI_BASE_URL",
                "KIMI_CODE_HOME",
                "KIMI_CODE_BASE_URL",
                "KIMI_CODE_OAUTH_HOST",
                "KIMI_OAUTH_HOST",
                "KIMI_CODE_CUSTOM_HEADERS",
                "KIMI_CODE_PASSWORD",
                "KIMI_SHARE_DIR",
                "KIMI_MODEL_NAME",
                "KIMI_MODEL_API_KEY",
                "KIMI_MODEL_PROVIDER_TYPE",
                "KIMI_MODEL_BASE_URL",
                "KIMI_MODEL_MAX_CONTEXT_SIZE",
                "KIMI_MODEL_CAPABILITIES",
                "KIMI_MODEL_DISPLAY_NAME",
                "KIMI_MODEL_MAX_OUTPUT_SIZE",
                "KIMI_MODEL_REASONING_KEY",
                "KIMI_MODEL_THINKING_EFFORT",
                "KIMI_MODEL_ADAPTIVE_THINKING",
                "GOOGLE_APPLICATION_CREDENTIALS",
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
            Self::Gents => &[],
        }
    }
}

impl fmt::Display for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Kimi => "kimi",
            Self::Gents => "gents",
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
            "gents" => Ok(Self::Gents),
            _ => Err(Error::CorruptRegistry),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProfileFields")]
pub struct Profile {
    pub id: ProfileId,
    pub alias: Alias,
    pub harness: Harness,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gents: Option<GentsBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFields {
    id: ProfileId,
    alias: Alias,
    harness: Harness,
    enabled: bool,
    #[serde(default)]
    gents: Option<GentsBinding>,
}
impl TryFrom<ProfileFields> for Profile {
    type Error = Error;
    fn try_from(value: ProfileFields) -> Result<Self> {
        let profile = Self {
            id: value.id,
            alias: value.alias,
            harness: value.harness,
            enabled: value.enabled,
            gents: value.gents,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// Gents IDs are exact, case-sensitive identifiers, not profile aliases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GentsAgentId(String);
impl FromStr for GentsAgentId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::InvalidGentsAgent);
        }
        Ok(Self(value.to_owned()))
    }
}
impl TryFrom<String> for GentsAgentId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}
impl From<GentsAgentId> for String {
    fn from(value: GentsAgentId) -> Self {
        value.0
    }
}
impl fmt::Display for GentsAgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        if (self.harness == Harness::Gents) != self.gents.is_some() {
            return Err(Error::InvalidEngineBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionEngine {
    Native,
    Gents,
}

impl fmt::Display for ExecutionEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Gents => "gents",
        })
    }
}

impl FromStr for ExecutionEngine {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "native" => Ok(Self::Native),
            "gents" => Ok(Self::Gents),
            _ => Err(Error::InvalidEngineBinding),
        }
    }
}

/// An explicit local runtime route. This is not proof of the server's identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GentsBindingFields")]
pub struct GentsBinding {
    address: SocketAddr,
    agent: GentsAgentId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GentsBindingFields {
    address: SocketAddr,
    agent: GentsAgentId,
}

impl TryFrom<GentsBindingFields> for GentsBinding {
    type Error = Error;
    fn try_from(value: GentsBindingFields) -> Result<Self> {
        Self::new(value.address, value.agent)
    }
}

impl GentsBinding {
    pub fn new(address: SocketAddr, agent: GentsAgentId) -> Result<Self> {
        if !address.ip().is_loopback()
            || address.port() == 0
            || matches!(address, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0)
        {
            return Err(Error::InvalidEngineBinding);
        }
        Ok(Self { address, agent })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn agent(&self) -> &GentsAgentId {
        &self.agent
    }
    pub fn graphql_url(&self) -> String {
        format!("http://{}/api/v0/graphql", self.address)
    }
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

#[cfg(test)]
mod engine_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn bindings_reject_remote_zero_port_and_deserialization_bypasses() {
        for address in [
            "192.0.2.1:9191",
            "0.0.0.0:9191",
            "127.0.0.1:0",
            "[::]:9191",
            "[::ffff:127.0.0.1]:9191",
            "[::1%1]:9191",
        ] {
            let json = serde_json::json!({"address":address,"agent":"web_persona"});
            assert!(
                serde_json::from_value::<GentsBinding>(json).is_err(),
                "{address}"
            );
        }
        for address in ["127.0.0.1:9191", "[::1]:9192"] {
            let binding =
                GentsBinding::new(address.parse().unwrap(), "web_persona".parse().unwrap())
                    .unwrap();
            assert_eq!(
                binding.graphql_url(),
                format!("http://{address}/api/v0/graphql")
            );
            assert_eq!(
                serde_json::from_value::<GentsBinding>(serde_json::to_value(&binding).unwrap())
                    .unwrap(),
                binding
            );
        }
        for id in ["", "has space", "line\nbreak", "\x1b[31m", "\u{202e}agent"] {
            assert!(id.parse::<GentsAgentId>().is_err());
        }
        assert!("A".repeat(129).parse::<GentsAgentId>().is_err());
        assert_eq!(
            "Agent:worker_1"
                .parse::<GentsAgentId>()
                .unwrap()
                .to_string(),
            "Agent:worker_1"
        );
    }

    #[test]
    fn native_events_stay_compatible_and_engine_binding_is_mandatory() {
        let native = serde_json::json!({"id":ProfileId::new(),"alias":"work","harness":"claude","enabled":true});
        let p: Profile = serde_json::from_value(native.clone()).unwrap();
        assert_eq!(serde_json::to_value(p).unwrap(), native);
        let mut gents = native.clone();
        gents["harness"] = "gents".into();
        assert!(serde_json::from_value::<Profile>(gents.clone()).is_err());
        gents["gents"] = serde_json::json!({"address":"127.0.0.1:9191","agent":"web_persona"});
        assert!(serde_json::from_value::<Profile>(gents.clone()).is_ok());
        gents["harness"] = "codex".into();
        assert!(serde_json::from_value::<Profile>(gents).is_err());
    }
}
