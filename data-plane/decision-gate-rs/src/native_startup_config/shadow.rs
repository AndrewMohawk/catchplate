//! Closed shadow inputs preserving the actual signed startup authorization.

use super::{bounded_absolute_path, originals::ArtifactV1, PinnedVerifierConfigV1};
use super::super::{policy_shadow::Sha256Digest,
    policy_shadow_generation::PolicyShadowGenerationConfig};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ShadowConfigV1 {
    trust_manifest: ArtifactV1,
    runtime_verifier: PinnedVerifierConfigV1,
    webauthn_verifier: PinnedVerifierConfigV1,
    publication_handoff: PinnedVerifierConfigV1,
    custody_config: ArtifactV1,
    startup_active_authorization: ArtifactV1,
}

fn digest(value: String) -> Result<Sha256Digest, String> {
    Sha256Digest::parse(value).map_err(|_| "native shadow artifact pin is not canonical SHA-256".to_owned())
}

impl ShadowConfigV1 {
    pub(super) fn into_config(self) -> Result<PolicyShadowGenerationConfig, String> {
        for path in [&self.trust_manifest.path, &self.custody_config.path,
            &self.startup_active_authorization.path] { bounded_absolute_path(path)?; }
        Ok(PolicyShadowGenerationConfig {
            trust_manifest_path: self.trust_manifest.path,
            trust_manifest_sha256: digest(self.trust_manifest.sha256)?,
            runtime_verifier: self.runtime_verifier.into_command()?,
            webauthn_verifier: self.webauthn_verifier.into_command()?,
            publication_handoff: self.publication_handoff.into_command()?,
            custody_config_path: self.custody_config.path,
            custody_config_sha256: Some(digest(self.custody_config.sha256)?),
            startup_generation_path: None, startup_generation_sha256: None,
            startup_active_authorization_path: Some(self.startup_active_authorization.path),
            startup_active_authorization_sha256: Some(digest(self.startup_active_authorization.sha256)?),
        })
    }
}
