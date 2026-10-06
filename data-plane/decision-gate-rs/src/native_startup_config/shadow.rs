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
            native_workers: None,
            native_activation:None,
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

/// Additive closed nested profile, explicitly selected inside outer v15.
/// Outer v1-v14 keep their exact ShadowConfigV1 decoder.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ShadowConfigV2 {
    #[serde(deserialize_with="version_two")]
    api_version: String,
    trust_manifest: ArtifactV1,
    runtime_verifier: PinnedVerifierConfigV1,
    webauthn_verifier: PinnedVerifierConfigV1,
    publication_handoff: PinnedVerifierConfigV1,
    custody_config: ArtifactV1,
    startup_active_authorization: ArtifactV1,
    workers: serverware_decision_gate::native_shadow_workers::Configuration,
}

fn exact_version<'de,D:serde::Deserializer<'de>>(de:D,expected:&str)->Result<String,D::Error> {
    let value=String::deserialize(de)?;
    if value==expected {Ok(value)} else {Err(serde::de::Error::custom("native shadow profile version differs"))}
}
fn version_two<'de,D:serde::Deserializer<'de>>(de:D)->Result<String,D::Error> {
    exact_version(de,"serverware.nativeShadowConfiguration/v2")
}
fn version_three<'de,D:serde::Deserializer<'de>>(de:D)->Result<String,D::Error> {
    exact_version(de,"serverware.nativeShadowConfiguration/v3")
}
fn version_four<'de,D:serde::Deserializer<'de>>(de:D)->Result<String,D::Error> {
    exact_version(de,"serverware.nativeShadowConfiguration/v4")
}
fn version_five<'de,D:serde::Deserializer<'de>>(de:D)->Result<String,D::Error> {
    exact_version(de,"serverware.nativeShadowConfiguration/v5")
}

impl ShadowConfigV2 {
    pub(super) fn into_config(self) -> Result<PolicyShadowGenerationConfig, String> {
        if self.api_version != "serverware.nativeShadowConfiguration/v2" {
            return Err("native shadow worker configuration version differs".into());
        }
        self.workers.validate_legacy()?;
        let mut original = ShadowConfigV1 {
            trust_manifest: self.trust_manifest, runtime_verifier: self.runtime_verifier,
            webauthn_verifier: self.webauthn_verifier, publication_handoff: self.publication_handoff,
            custody_config: self.custody_config, startup_active_authorization: self.startup_active_authorization,
        }.into_config()?;
        original.native_workers = Some(self.workers);
        Ok(original)
    }
}

/// Disjoint closed alternatives for v15 only. An unknown marker or extra
/// field cannot fall through to the legacy contract.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum ShadowConfigV15 {
    Legacy(ShadowConfigV1),
    Native(ShadowConfigV2),
    NativeActivation(ShadowConfigV3),
    NativePublication(ShadowConfigV4),
    NativeRuntimeVerification(ShadowConfigV5),
}

impl From<ShadowConfigV1> for ShadowConfigV15 {
    fn from(value: ShadowConfigV1) -> Self { Self::Legacy(value) }
}

impl ShadowConfigV15 {
    pub(super) fn into_config(self) -> Result<PolicyShadowGenerationConfig, String> {
        match self {
            Self::Legacy(value) => value.into_config(),
            Self::Native(value) => value.into_config(),
            Self::NativeActivation(value)=>value.into_config(),
            Self::NativePublication(value)=>value.into_config(),
            Self::NativeRuntimeVerification(value)=>value.into_config(),
        }
    }
}

/// Only this explicit nested successor may select publication descriptors.
/// An omitted activation profile remains omitted; explicit null is not one.
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ShadowConfigV4 {
    #[serde(deserialize_with="version_four")]
    api_version:String,trust_manifest:ArtifactV1,runtime_verifier:PinnedVerifierConfigV1,
    webauthn_verifier:PinnedVerifierConfigV1,publication_handoff:PinnedVerifierConfigV1,
    custody_config:ArtifactV1,startup_active_authorization:ArtifactV1,
    workers:serverware_decision_gate::native_shadow_workers::Configuration,
    #[serde(default,deserialize_with="present_activation")]
    native_activation:Option<super::super::policy_shadow_generation::activation::Configuration>,
}
fn present_activation<'de,D:serde::Deserializer<'de>>(deserializer:D)
    ->Result<Option<super::super::policy_shadow_generation::activation::Configuration>,D::Error> {
    Deserialize::deserialize(deserializer).map(Some)
}
impl ShadowConfigV4 {
    fn into_config(self)->Result<PolicyShadowGenerationConfig,String> {
        if self.api_version!="serverware.nativeShadowConfiguration/v4" || !self.workers.publication_resources()
            || self.workers.runtime_resources() {
            return Err("native publication nested profile differs".into());
        }
        self.workers.validate()?;
        let mut value=ShadowConfigV1{trust_manifest:self.trust_manifest,runtime_verifier:self.runtime_verifier,
            webauthn_verifier:self.webauthn_verifier,publication_handoff:self.publication_handoff,
            custody_config:self.custody_config,startup_active_authorization:self.startup_active_authorization}.into_config()?;
        value.native_workers=Some(self.workers);value.native_activation=self.native_activation;Ok(value)
    }
}

/// Runtime verification receives separately admitted originals only through
/// this explicit successor. It may also select the existing publication and
/// activation owners; none is inferred from inherited descriptor presence.
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ShadowConfigV5 {
    #[serde(deserialize_with="version_five")]
    api_version:String,trust_manifest:ArtifactV1,runtime_verifier:PinnedVerifierConfigV1,
    webauthn_verifier:PinnedVerifierConfigV1,publication_handoff:PinnedVerifierConfigV1,
    custody_config:ArtifactV1,startup_active_authorization:ArtifactV1,
    workers:serverware_decision_gate::native_shadow_workers::Configuration,
    #[serde(default,deserialize_with="present_activation")]
    native_activation:Option<super::super::policy_shadow_generation::activation::Configuration>,
}
impl ShadowConfigV5 {
    fn into_config(self)->Result<PolicyShadowGenerationConfig,String> {
        if self.api_version!="serverware.nativeShadowConfiguration/v5" || !self.workers.runtime_resources() {
            return Err("native runtime-verifier nested profile differs".into());
        }
        self.workers.validate()?;
        let mut value=ShadowConfigV1{trust_manifest:self.trust_manifest,runtime_verifier:self.runtime_verifier,
            webauthn_verifier:self.webauthn_verifier,publication_handoff:self.publication_handoff,
            custody_config:self.custody_config,startup_active_authorization:self.startup_active_authorization}.into_config()?;
        value.native_workers=Some(self.workers);value.native_activation=self.native_activation;Ok(value)
    }
}

/// Explicit successor nested profile. Old bytes keep the closed V1/V2 arms;
/// no inherited descriptor or optional untrusted field selects activation.
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ShadowConfigV3{
    #[serde(deserialize_with="version_three")]
    api_version:String,trust_manifest:ArtifactV1,runtime_verifier:PinnedVerifierConfigV1,
    webauthn_verifier:PinnedVerifierConfigV1,publication_handoff:PinnedVerifierConfigV1,
    custody_config:ArtifactV1,startup_active_authorization:ArtifactV1,
    workers:serverware_decision_gate::native_shadow_workers::Configuration,
    native_activation:super::super::policy_shadow_generation::activation::Configuration,
}
impl ShadowConfigV3{
    fn into_config(self)->Result<PolicyShadowGenerationConfig,String>{
        if self.api_version!="serverware.nativeShadowConfiguration/v3"{return Err("native activation nested profile differs".into());}
        let mut value=ShadowConfigV2{api_version:"serverware.nativeShadowConfiguration/v2".into(),trust_manifest:self.trust_manifest,
            runtime_verifier:self.runtime_verifier,webauthn_verifier:self.webauthn_verifier,publication_handoff:self.publication_handoff,
            custody_config:self.custody_config,startup_active_authorization:self.startup_active_authorization,workers:self.workers}.into_config()?;
        value.native_activation=Some(self.native_activation);Ok(value)
    }
}
