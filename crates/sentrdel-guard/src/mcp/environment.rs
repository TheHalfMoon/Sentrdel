//! T093 deny-by-default child environment for bounded stdio MCP servers.
//!
//! Ambient process environment is never inherited wholesale. Sentrdel copies
//! only a tiny platform process-requirement set plus environment capabilities
//! explicitly authorized by trusted user/system configuration. Values are kept
//! out of Debug output and process application always begins with `env_clear`.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    process::Command,
};

pub const MAX_MCP_ENVIRONMENT_CAPABILITIES: usize = 64;
pub const MAX_MCP_ENVIRONMENT_NAME_BYTES: usize = 128;
pub const MAX_MCP_ENVIRONMENT_VALUE_BYTES: usize = 32 * 1024;
pub const MAX_MCP_ENVIRONMENT_TOTAL_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct McpEnvironmentCapability(String);

impl McpEnvironmentCapability {
    pub fn new(name: impl Into<String>) -> Result<Self, McpEnvironmentError> {
        let name = name.into();
        validate_environment_name(&name)?;
        Ok(Self(name))
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct McpChildEnvironment {
    entries: BTreeMap<String, OsString>,
    authorized_capabilities: BTreeSet<McpEnvironmentCapability>,
}

impl McpChildEnvironment {
    pub fn from_runtime(
        authorized_capabilities: BTreeSet<McpEnvironmentCapability>,
    ) -> Result<Self, McpEnvironmentError> {
        Self::from_lookup(authorized_capabilities, std::env::var_os)
    }

    fn from_lookup<F>(
        authorized_capabilities: BTreeSet<McpEnvironmentCapability>,
        mut lookup: F,
    ) -> Result<Self, McpEnvironmentError>
    where
        F: FnMut(&str) -> Option<OsString>,
    {
        if authorized_capabilities.len() > MAX_MCP_ENVIRONMENT_CAPABILITIES {
            return Err(McpEnvironmentError::TooManyCapabilities {
                count: authorized_capabilities.len(),
                max: MAX_MCP_ENVIRONMENT_CAPABILITIES,
            });
        }

        let mut selected_names = platform_process_requirement_names()
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        selected_names.extend(
            authorized_capabilities
                .iter()
                .map(|capability| capability.name().to_owned()),
        );

        let mut entries = BTreeMap::new();
        let mut total_bytes = 0_usize;
        for name in selected_names {
            validate_environment_name(&name)?;
            let Some(value) = lookup(&name) else {
                continue;
            };
            let value_bytes = os_string_bytes(&value);
            if value_bytes > MAX_MCP_ENVIRONMENT_VALUE_BYTES {
                return Err(McpEnvironmentError::ValueTooLarge {
                    name,
                    size: value_bytes,
                    max: MAX_MCP_ENVIRONMENT_VALUE_BYTES,
                });
            }
            total_bytes = total_bytes
                .checked_add(name.len())
                .and_then(|size| size.checked_add(value_bytes))
                .ok_or(McpEnvironmentError::EnvironmentTooLarge {
                    size: usize::MAX,
                    max: MAX_MCP_ENVIRONMENT_TOTAL_BYTES,
                })?;
            if total_bytes > MAX_MCP_ENVIRONMENT_TOTAL_BYTES {
                return Err(McpEnvironmentError::EnvironmentTooLarge {
                    size: total_bytes,
                    max: MAX_MCP_ENVIRONMENT_TOTAL_BYTES,
                });
            }
            entries.insert(name, value);
        }

        Ok(Self {
            entries,
            authorized_capabilities,
        })
    }

    pub fn apply_to_command(&self, command: &mut Command) {
        command.env_clear();
        command.envs(&self.entries);
    }

    pub fn environment_names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    #[must_use]
    pub fn authorized_capabilities(&self) -> &BTreeSet<McpEnvironmentCapability> {
        &self.authorized_capabilities
    }
}

impl fmt::Debug for McpChildEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpChildEnvironment")
            .field(
                "environment_names",
                &self.entries.keys().collect::<Vec<_>>(),
            )
            .field("authorized_capabilities", &self.authorized_capabilities)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpEnvironmentError {
    InvalidName(String),
    NameTooLarge {
        name: String,
        size: usize,
        max: usize,
    },
    TooManyCapabilities {
        count: usize,
        max: usize,
    },
    ValueTooLarge {
        name: String,
        size: usize,
        max: usize,
    },
    EnvironmentTooLarge {
        size: usize,
        max: usize,
    },
}

impl fmt::Display for McpEnvironmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(
                formatter,
                "MCP environment capability name must be normalized ASCII uppercase: {name:?}"
            ),
            Self::NameTooLarge { name, size, max } => write!(
                formatter,
                "MCP environment capability name {name:?} is {size} bytes and exceeds cap {max}"
            ),
            Self::TooManyCapabilities { count, max } => write!(
                formatter,
                "MCP environment capability count {count} exceeds cap {max}"
            ),
            Self::ValueTooLarge { name, size, max } => write!(
                formatter,
                "MCP environment value for {name:?} is {size} bytes and exceeds cap {max}"
            ),
            Self::EnvironmentTooLarge { size, max } => write!(
                formatter,
                "MCP explicit child environment size {size} exceeds cap {max}"
            ),
        }
    }
}

impl Error for McpEnvironmentError {}

fn validate_environment_name(name: &str) -> Result<(), McpEnvironmentError> {
    if name.len() > MAX_MCP_ENVIRONMENT_NAME_BYTES {
        return Err(McpEnvironmentError::NameTooLarge {
            name: name.to_owned(),
            size: name.len(),
            max: MAX_MCP_ENVIRONMENT_NAME_BYTES,
        });
    }
    let valid = !name.is_empty()
        && name.trim() == name
        && name.bytes().enumerate().all(|(index, byte)| match byte {
            b'A'..=b'Z' | b'_' => true,
            b'0'..=b'9' => index > 0,
            _ => false,
        });
    if !valid {
        return Err(McpEnvironmentError::InvalidName(name.to_owned()));
    }
    Ok(())
}

#[cfg(windows)]
const PROCESS_REQUIREMENT_NAMES: &[&str] = &["COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"];

#[cfg(not(windows))]
const PROCESS_REQUIREMENT_NAMES: &[&str] = &["PATH"];

#[must_use]
pub const fn platform_process_requirement_names() -> &'static [&'static str] {
    PROCESS_REQUIREMENT_NAMES
}

fn os_string_bytes(value: &OsStr) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return value.as_bytes().len();
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        return value.encode_wide().count().saturating_mul(2);
    }

    #[allow(unreachable_code)]
    value.to_string_lossy().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL_CANARIES: &[&str] = &[
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "SSH_AUTH_SOCK",
        "GPG_AGENT_INFO",
        "DATABASE_URL",
        "SUPABASE_SERVICE_ROLE_KEY",
        "CLOUDFLARE_API_TOKEN",
    ];

    fn synthetic_lookup(name: &str) -> Option<OsString> {
        if platform_process_requirement_names().contains(&name) {
            return Some(OsString::from(format!("requirement:{name}")));
        }
        if CREDENTIAL_CANARIES.contains(&name) {
            return Some(OsString::from(format!("canary:{name}")));
        }
        if name == "MCP_EXPLICIT_CAPABILITY" {
            return Some(OsString::from("explicit-value"));
        }
        None
    }

    #[test]
    fn default_boundary_excludes_credential_canaries() {
        let environment = McpChildEnvironment::from_lookup(BTreeSet::new(), synthetic_lookup)
            .expect("default environment");
        let names = environment.environment_names().collect::<BTreeSet<_>>();

        for canary in CREDENTIAL_CANARIES {
            assert!(!names.contains(canary));
        }
        for requirement in platform_process_requirement_names() {
            assert!(names.contains(requirement));
        }
    }

    #[test]
    fn only_explicit_user_capability_can_cross_the_boundary() {
        let capability =
            McpEnvironmentCapability::new("MCP_EXPLICIT_CAPABILITY").expect("capability");
        let environment = McpChildEnvironment::from_lookup(
            BTreeSet::from([capability.clone()]),
            synthetic_lookup,
        )
        .expect("authorized environment");
        let names = environment.environment_names().collect::<BTreeSet<_>>();

        assert!(names.contains("MCP_EXPLICIT_CAPABILITY"));
        assert_eq!(
            environment.authorized_capabilities(),
            &BTreeSet::from([capability])
        );
        for canary in CREDENTIAL_CANARIES {
            assert!(!names.contains(canary));
        }
    }

    #[test]
    fn explicit_credential_capability_requires_exact_authorization() {
        let capability = McpEnvironmentCapability::new("OPENAI_API_KEY").expect("capability");
        let environment =
            McpChildEnvironment::from_lookup(BTreeSet::from([capability]), synthetic_lookup)
                .expect("authorized credential environment");

        assert!(
            environment
                .environment_names()
                .any(|name| name == "OPENAI_API_KEY")
        );
    }

    #[test]
    fn names_and_resource_bounds_fail_closed() {
        for invalid in ["", "lowercase", "PADDED ", "A=B", "1FIRST", "A-B"] {
            assert!(McpEnvironmentCapability::new(invalid).is_err());
        }

        let too_many = (0..=MAX_MCP_ENVIRONMENT_CAPABILITIES)
            .map(|index| McpEnvironmentCapability::new(format!("CAP_{index}")))
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("normalized capabilities");
        assert!(matches!(
            McpChildEnvironment::from_lookup(too_many, |_| None),
            Err(McpEnvironmentError::TooManyCapabilities { .. })
        ));

        let large = McpEnvironmentCapability::new("MCP_LARGE").expect("capability");
        assert!(matches!(
            McpChildEnvironment::from_lookup(BTreeSet::from([large]), |name| {
                (name == "MCP_LARGE")
                    .then(|| OsString::from("x".repeat(MAX_MCP_ENVIRONMENT_VALUE_BYTES + 1)))
            }),
            Err(McpEnvironmentError::ValueTooLarge { .. })
        ));
    }

    #[test]
    fn debug_never_exposes_environment_values() {
        let capability =
            McpEnvironmentCapability::new("MCP_EXPLICIT_CAPABILITY").expect("capability");
        let environment =
            McpChildEnvironment::from_lookup(BTreeSet::from([capability]), synthetic_lookup)
                .expect("environment");
        let debug = format!("{environment:?}");

        assert!(debug.contains("MCP_EXPLICIT_CAPABILITY"));
        assert!(!debug.contains("explicit-value"));
        assert!(!debug.contains("requirement:PATH"));
    }

    #[test]
    fn command_application_clears_prior_explicit_environment() {
        let capability =
            McpEnvironmentCapability::new("MCP_EXPLICIT_CAPABILITY").expect("capability");
        let environment =
            McpChildEnvironment::from_lookup(BTreeSet::from([capability]), synthetic_lookup)
                .expect("environment");
        let mut command = Command::new("not-executed");
        command.env("OPENAI_API_KEY", "must-not-survive");
        environment.apply_to_command(&mut command);

        let explicit = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .collect::<BTreeMap<_, _>>();
        assert!(!explicit.contains_key(OsStr::new("OPENAI_API_KEY")));
        assert_eq!(
            explicit.get(OsStr::new("MCP_EXPLICIT_CAPABILITY")).copied(),
            Some(OsStr::new("explicit-value"))
        );
    }
}
