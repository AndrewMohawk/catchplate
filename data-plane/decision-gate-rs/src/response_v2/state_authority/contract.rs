use serde::{Deserialize, Serialize};
use std::fmt;

pub const STATE_AUTHORITY_API_VERSION: &str =
    "catchplate.responseV2.stateAuthority/v1";
pub const STATE_AUTHORITY_SCHEMA_VERSION: &str = "1";
pub const STATE_AUTHORITY_RPC_KIND: &str =
    "CatchplateResponseV2StateAuthorityRpc";
pub const STATE_AUTHORITY_RESULT_KIND: &str =
    "CatchplateResponseV2StateAuthorityResult";
pub const STATE_AUTHORITY_GENERATION_RPC_KIND: &str =
    "CatchplateResponseV2StateAuthorityGenerationRpc";
pub const STATE_AUTHORITY_GENERATION_RESULT_KIND: &str =
    "CatchplateResponseV2StateAuthorityGenerationResult";
pub const PROVIDER_GENERATION_API_VERSION: &str =
    "catchplate.responseV2.providerGeneration/v1";
pub const PROVIDER_GENERATION_KIND: &str =
    "CatchplateResponseV2ProviderGeneration";
pub const NESTED_AUTHORITY_API_VERSION: &str =
    "catchplate.responseV2.nestedAuthorityArtifact/v1";
pub const NESTED_AUTHORITY_KIND: &str =
    "CatchplateResponseV2NestedAuthorityArtifact";
pub const FINAL_ENVELOPE_API_VERSION: &str =
    "catchplate.responseV2.canonicalFinalEnvelope/v1";
pub const FINAL_ENVELOPE_KIND: &str =
    "CatchplateResponseV2CanonicalFinalEnvelope";
pub const IMMUTABLE_RAW_OBJECT_API_VERSION: &str =
    "catchplate.responseV2.immutableRawObject/v1";
pub const IMMUTABLE_RAW_OBJECT_KIND: &str =
    "CatchplateResponseV2ImmutableRawObject";
pub const SIGNED_CHECKPOINT_API_VERSION: &str =
    "catchplate.responseV2.signedCheckpoint/v1";
pub const SIGNED_CHECKPOINT_KIND: &str =
    "CatchplateResponseV2SignedCheckpoint";
pub const RESUME_RECORD_API_VERSION: &str =
    "catchplate.responseV2.resumeRecord/v1";
pub const RELEASE_REPLAY_API_VERSION: &str =
    "catchplate.responseV2.releaseReplay/v1";
pub const TRUSTED_HOST_ATTESTATION_MODE: &str = "TrustedHostNoTee";
pub const LOCAL_FAULT_DOMAIN_ID: &str = "host-1";
pub const LOCAL_QUORUM_PROFILE: &str = "LOCAL_1_OF_1";
pub const SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const JCS_PROFILE: &str =
    "RFC8785-JCS/catchplate-safe-integers-unique-keys/v1";
pub const DIGEST_PREFIX: &str = "sha256:";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    InvalidContract {
        field: &'static str,
        reason: String,
    },
    Conflict {
        code: &'static str,
        authoritative_state: Option<String>,
    },
    Authentication {
        code: &'static str,
        reason: String,
    },
    Backend {
        code: &'static str,
        reason: String,
    },
    Serialization {
        reason: String,
    },
    NotReady {
        blockers: Vec<String>,
    },
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::Conflict {
                code,
                authoritative_state,
            } => write!(
                formatter,
                "conflict {code}: {}",
                authoritative_state.as_deref().unwrap_or("unknown")
            ),
            Self::Authentication { code, reason } => {
                write!(formatter, "authentication {code}: {reason}")
            }
            Self::Backend { code, reason } => {
                write!(formatter, "backend {code}: {reason}")
            }
            Self::Serialization { reason } => {
                write!(formatter, "serialization: {reason}")
            }
            Self::NotReady { blockers } => {
                write!(formatter, "not ready: {}", blockers.join(", "))
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

pub type AuthorityResult<T> = Result<T, AuthorityError>;

#[derive(
    Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(transparent)]
pub struct Identifier(pub String);

impl Identifier {
    pub fn validate(
        &self,
        field: &'static str,
        maximum_length: usize,
    ) -> AuthorityResult<()> {
        if self.0.is_empty() || self.0.len() > maximum_length {
            return Err(AuthorityError::InvalidContract {
                field,
                reason: format!(
                    "length must be between 1 and {maximum_length} bytes"
                ),
            });
        }
        let mut chars = self.0.chars();
        let first = chars.next().ok_or_else(|| {
            AuthorityError::InvalidContract {
                field,
                reason: "identifier is empty".to_owned(),
            }
        })?;
        if !first.is_ascii_alphanumeric() {
            return Err(AuthorityError::InvalidContract {
                field,
                reason: "identifier must start with an ASCII alphanumeric"
                    .to_owned(),
            });
        }
        if !chars.all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '.' | '_' | ':' | '/' | '@' | '-'
                )
        }) {
            return Err(AuthorityError::InvalidContract {
                field,
                reason: "identifier contains a forbidden character"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(
    Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(transparent)]
pub struct Digest(pub String);

impl Digest {
    pub fn validate(&self, field: &'static str) -> AuthorityResult<()> {
        if self.0.len() != 71 || !self.0.starts_with(DIGEST_PREFIX) {
            return Err(AuthorityError::InvalidContract {
                field,
                reason: "expected sha256 followed by 64 lowercase hex digits"
                    .to_owned(),
            });
        }
        if !self.0[DIGEST_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthorityError::InvalidContract {
                field,
                reason: "digest is not lowercase hexadecimal".to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootDeadline {
    pub clock: String,
    pub boot_id: Identifier,
    pub deadline_boot_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootInstant {
    pub clock: String,
    pub boot_id: Identifier,
    pub boot_millis: u64,
}

pub trait BootClock: Send + Sync {
    fn current_boot_instant(&self) -> AuthorityResult<BootInstant>;
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CgroupOwner {
    pub process_id: Identifier,
    pub pid: u32,
    pub process_start_time_ticks: u64,
    pub cgroup_id: Identifier,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CgroupObservation {
    pub owner_death_observed: bool,
    pub cgroup_empty_observed: bool,
    pub cgroup_death_observed: bool,
}

pub trait CgroupObserver: Send + Sync {
    fn observe(
        &self,
        owner: &CgroupOwner,
        deadline: &BootDeadline,
    ) -> AuthorityResult<CgroupObservation>;
}

impl BootDeadline {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.clock != "CLOCK_BOOTTIME" {
            return Err(AuthorityError::InvalidContract {
                field: "deadline.clock",
                reason: "only CLOCK_BOOTTIME is permitted".to_owned(),
            });
        }
        self.boot_id.validate("deadline.bootId", 128)?;
        if self.deadline_boot_millis > MAX_SAFE_INTEGER {
            return Err(AuthorityError::InvalidContract {
                field: "deadline.deadlineBootMillis",
                reason: "value exceeds the interoperable integer range"
                    .to_owned(),
            });
        }
        Ok(())
    }

    pub fn ensure_current(
        &self,
        instant: &BootInstant,
    ) -> AuthorityResult<()> {
        self.validate()?;
        if instant.clock != "CLOCK_BOOTTIME"
            || instant.boot_id != self.boot_id
        {
            return Err(AuthorityError::Conflict {
                code: "request_deadline_boot_mismatch",
                authoritative_state: Some(instant.boot_id.0.clone()),
            });
        }
        if instant.boot_millis >= self.deadline_boot_millis {
            return Err(AuthorityError::Conflict {
                code: "request_deadline_expired",
                authoritative_state: Some(instant.boot_millis.to_string()),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAuthorityConfiguration {
    pub api_version: String,
    pub schema_version: String,
    pub generation_id: Identifier,
    pub pinned_generation_sha256: Digest,
    pub local_role_id: Identifier,
    pub statement_timeout_millis: u64,
    pub lock_timeout_millis: u64,
    pub idle_transaction_timeout_millis: u64,
    pub cleanup_timeout_millis: u64,
    pub maximum_result_bytes: u64,
}

impl StateAuthorityConfiguration {
    pub fn validate(&self) -> AuthorityResult<()> {
        if self.api_version != STATE_AUTHORITY_API_VERSION {
            return Err(AuthorityError::InvalidContract {
                field: "configuration.apiVersion",
                reason: "unsupported API version".to_owned(),
            });
        }
        if self.schema_version != STATE_AUTHORITY_SCHEMA_VERSION {
            return Err(AuthorityError::InvalidContract {
                field: "configuration.schemaVersion",
                reason: "unsupported schema version".to_owned(),
            });
        }
        self.generation_id
            .validate("configuration.generationId", 128)?;
        self.pinned_generation_sha256
            .validate("configuration.pinnedGenerationSha256")?;
        self.local_role_id
            .validate("configuration.localRoleId", 128)?;
        for (field, value) in [
            (
                "configuration.statementTimeoutMillis",
                self.statement_timeout_millis,
            ),
            (
                "configuration.lockTimeoutMillis",
                self.lock_timeout_millis,
            ),
            (
                "configuration.idleTransactionTimeoutMillis",
                self.idle_transaction_timeout_millis,
            ),
            (
                "configuration.cleanupTimeoutMillis",
                self.cleanup_timeout_millis,
            ),
            (
                "configuration.maximumResultBytes",
                self.maximum_result_bytes,
            ),
        ] {
            if value == 0 || value > MAX_SAFE_INTEGER {
                return Err(AuthorityError::InvalidContract {
                    field,
                    reason:
                        "value must be a positive interoperable integer"
                            .to_owned(),
                });
            }
        }
        Ok(())
    }
}
