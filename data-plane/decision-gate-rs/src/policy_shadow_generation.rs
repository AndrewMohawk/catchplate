//! Closed candidate-shadow generation installation ingress.
//!
//! The HTTP body contains only fixed signed artifacts and policy bundles. All
//! trust, verifier, and custody paths are startup configuration. Production
//! accepts only an attested policy root, an immutable digest-pinned role-key
//! manifest, and a digest-pinned runtime-attestation verifier.

use super::policy_shadow::{
    activation_authority_signers, canonical_json_bytes,
    production_now_boottime_nanos, verify_activation_checkpoint_chain,
    verify_activation_readiness, verify_assignment, verify_load_receipt,
    verify_envelope, verify_policy_authority_analysis,
    ActivationPublicationReceiptWire, AtomicTrustCheckpoint,
    CanonicalAscii, EnvelopeKeyTrust, EnvelopePayload,
    ExpectedSigner, FleetMember, Identifier, PolicyShadowAssignmentPayload,
    PolicyActivationReadinessPayload, PolicyAuthorityAnalysisPayload,
    PolicyShadowCheckpointPayload, PolicyShadowLoadReceiptPayload,
    PolicyShadowCustodyRpcSupervisor,
    RuntimeAttestationVerification, RuntimeIdentity, Sha256Digest, ShadowError,
    ShadowGenerationIdentity, SignedEnvelope, TrustedTime,
    VerifiedActivationPublicationReceipt, VerifiedAssignment,
    VerifiedLoadReceipt,
    WebAuthnAssertionEvidence, WebAuthnVerification,
    VerifiedWebAuthnAssertion, ASSIGNMENT_DOMAIN,
    ACTIVATION_APPROVAL_DOMAIN, ACTIVE_DECISION_DOMAIN, CANONICAL_PROFILE,
    CHECKPOINT_DOMAIN, HEARTBEAT_DOMAIN, INGRESS_EVIDENCE_DOMAIN,
    LOAD_RECEIPT_DOMAIN, OBSERVATION_DOMAIN,
    POLICY_AUTHORITY_ANALYSIS_DOMAIN, READINESS_DOMAIN, SIGNATURE_ALGORITHM,
    WINDOW_CLOSURE_DOMAIN,
};
#[cfg(target_os = "linux")]
use super::policy_shadow::{install_policy_shadow_custody_generation_from_retained_file,
    install_native_custody_generation_from_retained_owner};
use super::{
    bind_next_active_runtime_identity, bind_shadow_active_runtime_identity,
    current_snapshot, is_sha256_digest, load_shadow_snapshot_pair,
    policy_trust_is_fresh,
    run_pinned_bounded_json_command_with_output_limit,
    same_exact_snapshot_identity, sha256_prefixed, strict_json_from_slice,
    verifying_key_from_spki_pem_text, verify_pinned_verifier_executable,
    zeroize_json_value, GateState, PinnedVerifierCommand, Snapshot,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{
    FileExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[path = "policy_shadow_generation_native.rs"]
mod native;
#[path="policy_shadow_generation_activation.rs"]
pub(crate) mod activation;
pub(crate) use native::PreparedNativeShadowControl;

pub(crate) const INSTALL_PATH: &str = "/v1/policy-shadow/generations";
pub(crate) const INSTALL_CONTENT_TYPE: &str = "application/json";
pub(crate) const MAX_INSTALL_BODY_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const ACTIVATION_PATH: &str =
    "/v1/policy-shadow/generations/activate";
pub(crate) const ACTIVATION_CONTENT_TYPE: &str = "application/json";
pub(crate) const MAX_ACTIVATION_BODY_BYTES: u64 = 16 * 1024 * 1024;

const TRUST_MANIFEST_API_VERSION: &str =
    "serverware.policyShadowGenerationTrust/v1";
const INSTALL_REQUEST_API_VERSION: &str =
    "serverware.policyShadowGenerationInstall/v2";
const ACTIVATION_REQUEST_API_VERSION: &str =
    "serverware.policyShadowGenerationActivationRequest/v1";
const ACTIVATION_RESPONSE_API_VERSION: &str =
    "serverware.policyShadowGenerationActivationResponse/v1";
const INSTALL_RECEIPT_API_VERSION: &str =
    "serverware.policyShadowGenerationPublication/v2";
const INSTALL_RECEIPT_KIND: &str =
    "PolicyShadowGenerationPublication";
const PUBLICATION_PREPARATION_API_VERSION: &str =
    "serverware.policyShadowGenerationPublicationPreparation/v1";
const PUBLICATION_PREPARATION_KIND: &str =
    "PolicyShadowGenerationPublicationPreparation";
const PUBLICATION_HANDOFF_API_VERSION: &str =
    "serverware.policyShadowGenerationPublicationHandoff/v1";
const PUBLICATION_SIGNATURE_DOMAIN: &str =
    "serverware.policyShadowGenerationPublication/v2";
const PUBLICATION_PREPARATION_SIGNATURE_DOMAIN: &str =
    "serverware.policyShadowGenerationPublicationPreparation/v1";
const STARTUP_ATTESTATION_HANDOFF_API_VERSION: &str =
    "serverware.policyShadowRuntimeAttestationHandoff/v2";
const STARTUP_ATTESTATION_RECEIPT_API_VERSION: &str =
    "serverware.policyRuntimeAttestation/v2";
const STARTUP_ATTESTATION_RECEIPT_KIND: &str =
    "PolicyRuntimeAttestation";
const SHADOW_ROLE_AUTHORIZATION_API_VERSION: &str =
    "serverware.policyShadowRoleAuthorization/v1";
const SHADOW_ROLE_AUTHORIZATION_KIND: &str =
    "PolicyShadowRoleAuthorization";
const RUNTIME_EVIDENCE_API_VERSION: &str =
    "serverware.policyShadowRuntimeAttestationEvidence/v1";
const RUNTIME_VERIFIER_REQUEST_API_VERSION: &str =
    "serverware.policyShadowRuntimeAttestationVerificationRequest/v1";
const RUNTIME_VERIFIER_RESPONSE_API_VERSION: &str =
    "serverware.policyShadowRuntimeAttestationVerification/v2";
const RUNTIME_VERIFIER_RESPONSE_KIND: &str =
    "PolicyShadowRuntimeAttestationVerification";
const RUNTIME_VERIFIER_SIGNATURE_DOMAIN: &str =
    "serverware.policyShadowRuntimeAttestationVerification/v2";
const WEBAUTHN_VERIFIER_REQUEST_API_VERSION: &str =
    "serverware.policyActivationWebAuthnVerificationRequest/v1";
const WEBAUTHN_VERIFIER_RESPONSE_API_VERSION: &str =
    "serverware.policyActivationWebAuthnVerification/v1";
const WEBAUTHN_VERIFIER_RESPONSE_KIND: &str =
    "PolicyActivationWebAuthnVerification";
const WEBAUTHN_VERIFIER_SIGNATURE_DOMAIN: &str =
    "serverware.policyActivationWebAuthnVerification/v1";
const MAX_TRUST_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RUNTIME_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CUSTODY_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STARTUP_ACTIVE_AUTHORIZATION_BYTES: u64 = 64 * 1024;
const MAX_TRUST_KEYS: usize = 2048;
const MAX_SIGNATURE_DOMAINS_PER_KEY: usize = 64;
const MAX_TRUST_LIFETIME_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;
const MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS: i64 =
    15 * 60 * 1_000_000_000;
const MAX_REPLAY_IDENTIFIER_BYTES: usize = 128;

const TRUST_MANIFEST_PATH_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_TRUST_MANIFEST";
const TRUST_MANIFEST_SHA256_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_TRUST_MANIFEST_SHA256";
const RUNTIME_VERIFIER_COMMAND_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_RUNTIME_ATTESTATION_VERIFY_COMMAND";
const RUNTIME_VERIFIER_SHA256_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_RUNTIME_ATTESTATION_VERIFIER_SHA256";
const WEBAUTHN_VERIFIER_COMMAND_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_WEBAUTHN_VERIFY_COMMAND";
const WEBAUTHN_VERIFIER_SHA256_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_WEBAUTHN_VERIFIER_SHA256";
const PUBLICATION_HANDOFF_COMMAND_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_PUBLICATION_HANDOFF_COMMAND";
const PUBLICATION_HANDOFF_SHA256_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_PUBLICATION_HANDOFF_SHA256";
const CUSTODY_CONFIG_PATH_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_CUSTODY_CONFIG";
const STARTUP_GENERATION_PATH_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_STARTUP_GENERATION";
const STARTUP_GENERATION_SHA256_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_STARTUP_GENERATION_SHA256";
const STARTUP_ACTIVE_AUTHORIZATION_PATH_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_STARTUP_ACTIVE_AUTHORIZATION";
const STARTUP_ACTIVE_AUTHORIZATION_SHA256_ENV: &str =
    "SERVERWARE_POLICY_SHADOW_STARTUP_ACTIVE_AUTHORIZATION_SHA256";
const STARTUP_ACTIVE_AUTHORIZATION_API_VERSION: &str =
    "serverware.policyShadowStartupActiveAuthorization/v1";

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerTrustManifest {
    policy_compiler_binary_sha256: Sha256Digest,
    policy_compiler_configuration_sha256: Sha256Digest,
    policy_schema_sha256: Sha256Digest,
    adapter_schema_sha256: Sha256Digest,
    policy_semantic_model_sha256: Sha256Digest,
    policy_plan_schema_sha256: Sha256Digest,
    request_facts_schema_sha256: Sha256Digest,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustKeyManifest {
    role: String,
    signature_domains: Vec<String>,
    key_id: Sha256Digest,
    key_spki_sha256: Sha256Digest,
    public_key_pem: String,
    not_before_unix_nanos: i64,
    not_after_unix_nanos: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationTrustManifest {
    api_version: String,
    trust_class: String,
    self_signed: bool,
    manifest_revision: u64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    assignment_signing_key_id: Sha256Digest,
    assignment_signing_key_spki_sha256: Sha256Digest,
    startup_attestation_signing_key_id: Sha256Digest,
    startup_attestation_signing_key_spki_sha256: Sha256Digest,
    runtime_attestation_policy_sha256: Sha256Digest,
    runtime_attestation_verifier_signing_key_id: Sha256Digest,
    runtime_attestation_verifier_signing_key_spki_sha256: Sha256Digest,
    webauthn_verification_policy_sha256: Sha256Digest,
    webauthn_verifier_signing_key_id: Sha256Digest,
    webauthn_verifier_signing_key_spki_sha256: Sha256Digest,
    publication_signing_key_id: Sha256Digest,
    publication_signing_key_spki_sha256: Sha256Digest,
    publication_replay_store_sha256: Sha256Digest,
    compiler: CompilerTrustManifest,
    keys: Vec<TrustKeyManifest>,
}

#[derive(Clone)]
struct PinnedTrustKey {
    verifying_key: VerifyingKey,
    not_before_unix_nanos: i64,
    not_after_unix_nanos: i64,
}

#[derive(Clone)]
struct PinnedEnvelopeKeyTrust {
    checkpoint: AtomicTrustCheckpoint,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    assignment_signing_key_id: Sha256Digest,
    assignment_signing_key_spki_sha256: Sha256Digest,
    startup_attestation_signing_key_id: Sha256Digest,
    startup_attestation_signing_key_spki_sha256: Sha256Digest,
    runtime_attestation_policy_sha256: Sha256Digest,
    runtime_attestation_verifier_signing_key_id: Sha256Digest,
    runtime_attestation_verifier_signing_key_spki_sha256: Sha256Digest,
    webauthn_verification_policy_sha256: Sha256Digest,
    webauthn_verifier_signing_key_id: Sha256Digest,
    webauthn_verifier_signing_key_spki_sha256: Sha256Digest,
    publication_signing_key_id: Sha256Digest,
    publication_signing_key_spki_sha256: Sha256Digest,
    publication_replay_store_sha256: Sha256Digest,
    compiler: CompilerTrustManifest,
    keys: BTreeMap<
        (String, String, Sha256Digest, Sha256Digest),
        PinnedTrustKey,
    >,
}

fn required_trust_role(signature_domain: &str) -> Option<&'static str> {
    match signature_domain {
        ASSIGNMENT_DOMAIN => Some("assignment-authority"),
        LOAD_RECEIPT_DOMAIN => Some("fleet-shadow-runtime"),
        INGRESS_EVIDENCE_DOMAIN => Some("fleet-ingress-runtime"),
        ACTIVE_DECISION_DOMAIN => Some("fleet-active-decision-runtime"),
        OBSERVATION_DOMAIN => Some("fleet-shadow-runtime"),
        HEARTBEAT_DOMAIN => Some("fleet-shadow-runtime"),
        CHECKPOINT_DOMAIN => Some("fleet-shadow-runtime"),
        WINDOW_CLOSURE_DOMAIN => Some("fleet-ingress-runtime"),
        STARTUP_ATTESTATION_RECEIPT_API_VERSION => {
            Some("runtime-attestation-authority")
        }
        SHADOW_ROLE_AUTHORIZATION_API_VERSION => {
            Some("shadow-role-authorization-authority")
        }
        POLICY_AUTHORITY_ANALYSIS_DOMAIN => Some("compiler-analysis"),
        READINESS_DOMAIN => Some("activation-readiness"),
        ACTIVATION_APPROVAL_DOMAIN => Some("activation-approval"),
        RUNTIME_VERIFIER_SIGNATURE_DOMAIN => {
            Some("runtime-attestation-verifier")
        }
        WEBAUTHN_VERIFIER_SIGNATURE_DOMAIN => {
            Some("activation-webauthn-verifier")
        }
        PUBLICATION_SIGNATURE_DOMAIN
        | PUBLICATION_PREPARATION_SIGNATURE_DOMAIN => {
            Some("fleet-shadow-runtime")
        }
        "serverware.policyShadowIngressAdmission/v1" => {
            Some("custody-ingress-admission")
        }
        "serverware.policyShadowUnavailableIngress/v1" => {
            Some("custody-unavailable-ingress")
        }
        "serverware.policyShadowDispatchBarrier/v1" => {
            Some("custody-dispatch-barrier")
        }
        "serverware.policyShadowActiveEffectBarrier/v1" => {
            Some("custody-active-effect-barrier")
        }
        "serverware.policyShadowActiveEffectCommit/v1" => {
            Some("custody-active-effect-commit")
        }
        "serverware.policyShadowTerminalAppend/v1" => {
            Some("custody-terminal-append")
        }
        "serverware.policyShadowLedgerAppend/v1" => {
            Some("custody-ledger-append")
        }
        "serverware.policyShadowSpoolCompaction/v1" => {
            Some("custody-spool-compaction")
        }
        "serverware.policyShadowPublicationReconciliation/v1" => {
            Some("custody-publication-reconciliation")
        }
        "serverware.policyActivationPublication/v1" => {
            Some("custody-activation-publication")
        }
        "serverware.policyShadowCustodyResultEnvelope/v1" => {
            Some("custody-result-envelope")
        }
        "serverware.policyShadowCustodyStoreResponse/v1" => {
            Some("custody-store-response")
        }
        "serverware.policyShadowCustodySignerResponse/v1" => {
            Some("custody-signer-response")
        }
        "serverware.policyShadowCustodyRetrievalResponse/v1" => {
            Some("custody-retrieval-response")
        }
        "serverware.policyShadowCustodyTrustedTimeResponse/v1" => {
            Some("custody-trusted-time-response")
        }
        "serverware.policyShadowCustodyProviderResponse/v1" => {
            Some("custody-provider-response")
        }
        "serverware.policyShadowCustodyAttestationVerifier/v1" => {
            Some("custody-attestation-verifier")
        }
        "serverware.policyShadowCustodySupervisorCapability/v1" => {
            Some("custody-supervisor-capability")
        }
        _ => None,
    }
}

impl PinnedEnvelopeKeyTrust {
    fn from_manifest(
        bytes: &[u8],
        manifest_sha256: &Sha256Digest,
        is_production: bool,
    ) -> Result<Self, String> {
        let manifest: GenerationTrustManifest =
            strict_json_from_slice(bytes).map_err(|_| {
                "policy-shadow trust manifest is not strict JSON".to_string()
            })?;
        if manifest.api_version != TRUST_MANIFEST_API_VERSION
            || manifest.manifest_revision == 0
            || manifest.revocation_generation == 0
            || manifest.issued_at_unix_nanos < 0
            || manifest.expires_at_unix_nanos
                <= manifest.issued_at_unix_nanos
            || manifest
                .expires_at_unix_nanos
                .checked_sub(manifest.issued_at_unix_nanos)
                .is_none_or(|lifetime| {
                    lifetime > MAX_TRUST_LIFETIME_NANOS
                })
            || manifest.keys.is_empty()
            || manifest.keys.len() > MAX_TRUST_KEYS
        {
            return Err(
                "policy-shadow trust manifest bounds are invalid".to_string(),
            );
        }
        if is_production
            && (manifest.trust_class != "production-pinned"
                || manifest.self_signed)
        {
            return Err(
                "production rejects development or self-signed policy-shadow trust"
                    .to_string(),
            );
        }
        if !is_production
            && !matches!(
                manifest.trust_class.as_str(),
                "production-pinned" | "development-pinned"
            )
        {
            return Err(
                "policy-shadow trust class is unsupported".to_string(),
            );
        }

        let checkpoint = AtomicTrustCheckpoint::new(
            manifest_sha256.clone(),
            manifest.issued_at_unix_nanos,
            manifest.revocation_generation,
            manifest.revocation_root_sha256,
        )
        .map_err(shadow_error)?;
        let mut keys = BTreeMap::new();
        let mut previous_order: Option<(String, String, String)> = None;
        let mut key_id_roles = BTreeMap::new();
        let mut spki_roles = BTreeMap::new();
        let mut assignment_authority_present = false;
        let mut startup_attestation_authority_present = false;
        let mut shadow_role_authorization_authority_present = false;
        let mut runtime_attestation_verifier_present = false;
        let mut policy_authority_analysis_present = false;
        let mut activation_readiness_present = false;
        let mut activation_approval_present = false;
        let mut webauthn_verifier_present = false;
        let mut activation_role_key_ids = BTreeSet::new();
        let mut activation_role_spkis = BTreeSet::new();
        let mut activation_role_domains = BTreeSet::new();
        let mut publication_signer_present = false;
        let mut publication_preparation_signer_present = false;
        let mut load_receipt_signer_present = false;
        let mut ingress_evidence_signer_present = false;
        let mut active_decision_signer_present = false;
        let mut observation_signer_present = false;
        let mut heartbeat_signer_present = false;
        let mut checkpoint_signer_present = false;
        let mut window_closure_signer_present = false;
        for record in manifest.keys {
            if !bounded_ascii_token(&record.role, 128)
                || record.signature_domains.is_empty()
                || record.signature_domains.len()
                    > MAX_SIGNATURE_DOMAINS_PER_KEY
                || record.not_before_unix_nanos < 0
                || record.not_after_unix_nanos
                    <= record.not_before_unix_nanos
                || record.not_before_unix_nanos
                    > manifest.issued_at_unix_nanos
                || record.not_after_unix_nanos
                    < manifest.expires_at_unix_nanos
            {
                return Err(
                    "policy-shadow trust key bounds are invalid".to_string(),
                );
            }
            let order = (
                record.role.clone(),
                record.key_id.as_str().to_string(),
                record.key_spki_sha256.as_str().to_string(),
            );
            if previous_order
                .as_ref()
                .is_some_and(|previous| previous >= &order)
            {
                return Err(
                    "policy-shadow trust keys must be unique and sorted"
                        .to_string(),
                );
            }
            previous_order = Some(order);
            let (verifying_key, computed_spki_sha256) =
                verifying_key_from_spki_pem_text(
                    &record.public_key_pem,
                    "policy-shadow role",
                )?;
            if record.key_id.as_str() != computed_spki_sha256
                || record.key_spki_sha256.as_str()
                    != computed_spki_sha256
            {
                return Err(
                    "policy-shadow role key is not bound to its exact SPKI"
                        .to_string(),
                );
            }
            if key_id_roles
                .insert(record.key_id.clone(), record.role.clone())
                .is_some()
                || spki_roles
                    .insert(
                        record.key_spki_sha256.clone(),
                        record.role.clone(),
                    )
                    .is_some()
            {
                return Err(
                    "policy-shadow trust roles must use independent keys"
                        .to_string(),
                );
            }
            let mut previous_domain: Option<&str> = None;
            for domain in &record.signature_domains {
                if !bounded_ascii_domain(domain)
                    || required_trust_role(domain)
                        != Some(record.role.as_str())
                    || previous_domain.is_some_and(|previous| {
                        previous >= domain.as_str()
                    })
                {
                    return Err(
                        "policy-shadow signature domains must be unique and sorted"
                            .to_string(),
                    );
                }
                previous_domain = Some(domain);
                if record.role == "assignment-authority"
                    && domain == ASSIGNMENT_DOMAIN
                    && record.key_id
                        == manifest.assignment_signing_key_id
                    && record.key_spki_sha256
                        == manifest.assignment_signing_key_spki_sha256
                {
                    assignment_authority_present = true;
                }
                if record.role == "runtime-attestation-authority"
                    && domain == STARTUP_ATTESTATION_RECEIPT_API_VERSION
                    && record.key_id
                        == manifest.startup_attestation_signing_key_id
                    && record.key_spki_sha256
                        == manifest
                            .startup_attestation_signing_key_spki_sha256
                {
                    startup_attestation_authority_present = true;
                }
                if record.role
                    == "shadow-role-authorization-authority"
                    && domain
                        == SHADOW_ROLE_AUTHORIZATION_API_VERSION
                {
                    shadow_role_authorization_authority_present = true;
                }
                if record.role == "runtime-attestation-verifier"
                    && domain == RUNTIME_VERIFIER_SIGNATURE_DOMAIN
                    && record.key_id
                        == manifest
                            .runtime_attestation_verifier_signing_key_id
                    && record.key_spki_sha256
                        == manifest
                            .runtime_attestation_verifier_signing_key_spki_sha256
                {
                    runtime_attestation_verifier_present = true;
                }
                if matches!(
                    (record.role.as_str(), domain.as_str()),
                    ("compiler-analysis", POLICY_AUTHORITY_ANALYSIS_DOMAIN)
                        | ("activation-readiness", READINESS_DOMAIN)
                        | ("activation-approval", ACTIVATION_APPROVAL_DOMAIN)
                ) {
                    if !activation_role_key_ids
                        .insert(record.key_id.clone())
                        || !activation_role_spkis
                            .insert(record.key_spki_sha256.clone())
                        || !activation_role_domains.insert(domain.clone())
                    {
                        return Err(
                            "activation authority roles must use independent keys"
                                .to_string(),
                        );
                    }
                    match domain.as_str() {
                        POLICY_AUTHORITY_ANALYSIS_DOMAIN => {
                            policy_authority_analysis_present = true
                        }
                        READINESS_DOMAIN => {
                            activation_readiness_present = true
                        }
                        ACTIVATION_APPROVAL_DOMAIN => {
                            activation_approval_present = true
                        }
                        _ => unreachable!(),
                    }
                }
                if record.role == "activation-webauthn-verifier"
                    && domain == WEBAUTHN_VERIFIER_SIGNATURE_DOMAIN
                    && record.key_id
                        == manifest.webauthn_verifier_signing_key_id
                    && record.key_spki_sha256
                        == manifest
                            .webauthn_verifier_signing_key_spki_sha256
                {
                    webauthn_verifier_present = true;
                }
                if record.role == "fleet-shadow-runtime"
                    && record.key_id
                        == manifest.publication_signing_key_id
                    && record.key_spki_sha256
                        == manifest.publication_signing_key_spki_sha256
                {
                    if domain == PUBLICATION_SIGNATURE_DOMAIN {
                        publication_signer_present = true;
                    }
                    if domain
                        == PUBLICATION_PREPARATION_SIGNATURE_DOMAIN
                    {
                        publication_preparation_signer_present = true;
                    }
                }
                if record.role == "fleet-shadow-runtime"
                    && domain == LOAD_RECEIPT_DOMAIN
                {
                    load_receipt_signer_present = true;
                }
                if record.role == "fleet-ingress-runtime"
                    && domain == INGRESS_EVIDENCE_DOMAIN
                {
                    ingress_evidence_signer_present = true;
                }
                if record.role == "fleet-active-decision-runtime"
                    && domain == ACTIVE_DECISION_DOMAIN
                {
                    active_decision_signer_present = true;
                }
                if record.role == "fleet-shadow-runtime"
                    && domain == OBSERVATION_DOMAIN
                {
                    observation_signer_present = true;
                }
                if record.role == "fleet-shadow-runtime"
                    && domain == HEARTBEAT_DOMAIN
                {
                    heartbeat_signer_present = true;
                }
                if record.role == "fleet-shadow-runtime"
                    && domain == CHECKPOINT_DOMAIN
                {
                    checkpoint_signer_present = true;
                }
                if record.role == "fleet-ingress-runtime"
                    && domain == WINDOW_CLOSURE_DOMAIN
                {
                    window_closure_signer_present = true;
                }
                if keys
                    .insert(
                        (
                            record.role.clone(),
                            domain.clone(),
                            record.key_id.clone(),
                            record.key_spki_sha256.clone(),
                        ),
                        PinnedTrustKey {
                            verifying_key: verifying_key.clone(),
                            not_before_unix_nanos:
                                record.not_before_unix_nanos,
                            not_after_unix_nanos:
                                record.not_after_unix_nanos,
                        },
                    )
                    .is_some()
                {
                    return Err(
                        "policy-shadow trust key authorization is duplicated"
                            .to_string(),
                    );
                }
            }
        }
        if !assignment_authority_present
            || !startup_attestation_authority_present
            || !shadow_role_authorization_authority_present
            || !runtime_attestation_verifier_present
            || !policy_authority_analysis_present
            || !activation_readiness_present
            || !activation_approval_present
            || !webauthn_verifier_present
            || activation_role_key_ids.len() != 3
            || activation_role_spkis.len() != 3
            || activation_role_domains.len() != 3
            || !publication_signer_present
            || !publication_preparation_signer_present
            || !load_receipt_signer_present
            || !ingress_evidence_signer_present
            || !active_decision_signer_present
            || !observation_signer_present
            || !heartbeat_signer_present
            || !checkpoint_signer_present
            || !window_closure_signer_present
        {
            return Err(
                "policy-shadow assignment, attestation, or publication authority is not exactly pinned"
                    .to_string(),
            );
        }
        Ok(Self {
            checkpoint,
            issued_at_unix_nanos: manifest.issued_at_unix_nanos,
            expires_at_unix_nanos: manifest.expires_at_unix_nanos,
            assignment_signing_key_id:
                manifest.assignment_signing_key_id,
            assignment_signing_key_spki_sha256:
                manifest.assignment_signing_key_spki_sha256,
            startup_attestation_signing_key_id:
                manifest.startup_attestation_signing_key_id,
            startup_attestation_signing_key_spki_sha256:
                manifest.startup_attestation_signing_key_spki_sha256,
            runtime_attestation_policy_sha256:
                manifest.runtime_attestation_policy_sha256,
            runtime_attestation_verifier_signing_key_id:
                manifest
                    .runtime_attestation_verifier_signing_key_id,
            runtime_attestation_verifier_signing_key_spki_sha256:
                manifest
                    .runtime_attestation_verifier_signing_key_spki_sha256,
            webauthn_verification_policy_sha256:
                manifest.webauthn_verification_policy_sha256,
            webauthn_verifier_signing_key_id:
                manifest.webauthn_verifier_signing_key_id,
            webauthn_verifier_signing_key_spki_sha256:
                manifest.webauthn_verifier_signing_key_spki_sha256,
            publication_signing_key_id:
                manifest.publication_signing_key_id,
            publication_signing_key_spki_sha256:
                manifest.publication_signing_key_spki_sha256,
            publication_replay_store_sha256:
                manifest.publication_replay_store_sha256,
            compiler: manifest.compiler,
            keys,
        })
    }

    fn authorize_at(&self, trusted_now_unix_nanos: i64) -> Result<(), String> {
        if trusted_now_unix_nanos < self.issued_at_unix_nanos
            || trusted_now_unix_nanos >= self.expires_at_unix_nanos
            || self.keys.values().any(|key| {
                trusted_now_unix_nanos < key.not_before_unix_nanos
                    || trusted_now_unix_nanos
                        >= key.not_after_unix_nanos
            })
        {
            return Err(
                "policy-shadow immutable trust is not current".to_string(),
            );
        }
        Ok(())
    }
}

impl EnvelopeKeyTrust for PinnedEnvelopeKeyTrust {
    fn current_checkpoint(
        &self,
    ) -> Result<AtomicTrustCheckpoint, ShadowError> {
        Ok(self.checkpoint.clone())
    }

    fn resolve_ed25519_key(
        &self,
        checkpoint: &AtomicTrustCheckpoint,
        signature_domain: &str,
        key_id: &Sha256Digest,
        key_spki_sha256: &Sha256Digest,
    ) -> Result<VerifyingKey, ShadowError> {
        if checkpoint != &self.checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        let required_role = required_trust_role(signature_domain)
            .ok_or(ShadowError::TrustResolutionFailed)?;
        self.keys
            .get(&(
                required_role.to_string(),
                signature_domain.to_string(),
                key_id.clone(),
                key_spki_sha256.clone(),
            ))
            .map(|key| key.verifying_key.clone())
            .ok_or(ShadowError::TrustResolutionFailed)
    }
}

#[derive(Clone)]
struct FixedTrustedTime {
    now_unix_nanos: i64,
}

impl TrustedTime for FixedTrustedTime {
    fn now_unix_nanos(&self) -> Result<i64, ShadowError> {
        Ok(self.now_unix_nanos)
    }
}

struct AnchoredTrustedTime {
    signed_now_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    maximum_age_nanos: i64,
    boot_id_sha256: Sha256Digest,
    anchor_boottime_nanos: u64,
    last_boottime_nanos: AtomicU64,
}

impl AnchoredTrustedTime {
    fn from_signed_runtime_verification(
        result: &RuntimeAttestationVerificationResult,
    ) -> Result<Self, ShadowError> {
        result.validate_intrinsic()?;
        let anchor_boottime_nanos = production_now_boottime_nanos()?;
        Ok(Self {
            signed_now_unix_nanos: result.trusted_now_unix_nanos,
            issued_at_unix_nanos: result.issued_at_unix_nanos,
            expires_at_unix_nanos: result.expires_at_unix_nanos,
            maximum_age_nanos: result.maximum_age_nanos,
            boot_id_sha256: current_linux_boot_id_sha256()?,
            anchor_boottime_nanos,
            last_boottime_nanos: AtomicU64::new(anchor_boottime_nanos),
        })
    }
}

impl TrustedTime for AnchoredTrustedTime {
    fn now_unix_nanos(&self) -> Result<i64, ShadowError> {
        if current_linux_boot_id_sha256()? != self.boot_id_sha256 {
            return Err(ShadowError::TrustedTimeUnavailable);
        }
        let current_boottime_nanos = production_now_boottime_nanos()?;
        let mut previous = self.last_boottime_nanos.load(Ordering::Acquire);
        loop {
            if current_boottime_nanos < previous
                || current_boottime_nanos < self.anchor_boottime_nanos
            {
                return Err(ShadowError::TrustedTimeUnavailable);
            }
            match self.last_boottime_nanos.compare_exchange_weak(
                previous,
                current_boottime_nanos,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        let elapsed = current_boottime_nanos
            .checked_sub(self.anchor_boottime_nanos)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ShadowError::CounterOverflow)?;
        let now = self
            .signed_now_unix_nanos
            .checked_add(elapsed)
            .ok_or(ShadowError::CounterOverflow)?;
        if now < self.issued_at_unix_nanos {
            return Err(ShadowError::EvidenceNotYetValid);
        }
        if now >= self.expires_at_unix_nanos {
            return Err(ShadowError::EvidenceExpired);
        }
        if now
            .checked_sub(self.issued_at_unix_nanos)
            .is_none_or(|age| age > self.maximum_age_nanos)
        {
            return Err(ShadowError::EvidenceTooOld);
        }
        Ok(now)
    }
}

fn current_linux_boot_id_sha256() -> Result<Sha256Digest, ShadowError> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| ShadowError::TrustedTimeUnavailable)?;
    let value = value.trim();
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte != b'-'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(ShadowError::TrustedTimeUnavailable);
    }
    Ok(Sha256Digest::compute(value.to_ascii_lowercase().as_bytes()))
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeAttestationEvidence {
    api_version: String,
    evidence_id: Sha256Digest,
    evidence_revision: u64,
    evidence_type: String,
    evidence_sha256: Sha256Digest,
    evidence: Value,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartupRuntimeAttestationRecord {
    fleet_id: Sha256Digest,
    membership_revision: u64,
    member_ordinal: u64,
    member_id: Sha256Digest,
    instance_id: String,
    boot_id_sha256: Sha256Digest,
    spiffe_id: String,
    tee_platform: String,
    tee_evidence_sha256: Sha256Digest,
    tee_measurement_sha256: Sha256Digest,
    role_keys_digest: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartupRuntimeAttestationReceiptPayload {
    issued_at_epoch_ns: i64,
    expires_at_epoch_ns: i64,
    record: StartupRuntimeAttestationRecord,
}

impl EnvelopePayload for StartupRuntimeAttestationReceiptPayload {
    const API_VERSION: &'static str =
        STARTUP_ATTESTATION_RECEIPT_API_VERSION;
    const KIND: &'static str = STARTUP_ATTESTATION_RECEIPT_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        STARTUP_ATTESTATION_RECEIPT_API_VERSION;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_epoch_ns
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_epoch_ns
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.issued_at_epoch_ns <= 0
            || self.expires_at_epoch_ns <= self.issued_at_epoch_ns
            || self.record.membership_revision == 0
            || self.record.member_ordinal == 0
            || !bounded_ascii_token(&self.record.instance_id, 256)
            || !bounded_ascii_token(&self.record.spiffe_id, 2048)
            || !matches!(
                self.record.tee_platform.as_str(),
                "aws-nitro-enclave"
                    | "amd-sev-snp"
                    | "intel-tdx"
                    | "trusted-host-no-tee"
            )
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ShadowRoleAuthorizationRecord {
    authorization_id: Sha256Digest,
    authorization_revision: u64,
    role: String,
    candidate_id: Sha256Digest,
    canary_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    membership_root_sha256: Sha256Digest,
    member_ordinal: u64,
    member_id: Sha256Digest,
    instance_id: String,
    boot_id_sha256: Sha256Digest,
    runtime_attestation_receipt_id: Sha256Digest,
    runtime_attestation_receipt_revision: u64,
    runtime_attestation_receipt_sha256: Sha256Digest,
    runtime_attestation_payload_sha256: Sha256Digest,
    attestation_evidence_id: Sha256Digest,
    attestation_evidence_revision: u64,
    attestation_evidence_sha256: Sha256Digest,
    runtime_identity_sha256: Sha256Digest,
    runtime_executable_sha256: Sha256Digest,
    runtime_release_sha256: Sha256Digest,
    runtime_config_sha256: Sha256Digest,
    runtime_policy_sha256: Sha256Digest,
    attestation_policy_sha256: Sha256Digest,
    attestation_trust_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    shadow_signing_key_id: Sha256Digest,
    shadow_signing_key_spki_sha256: Sha256Digest,
    tee_measurement_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ShadowRoleAuthorizationPayload {
    issued_at_epoch_ns: i64,
    expires_at_epoch_ns: i64,
    record: ShadowRoleAuthorizationRecord,
}

impl EnvelopePayload for ShadowRoleAuthorizationPayload {
    const API_VERSION: &'static str =
        SHADOW_ROLE_AUTHORIZATION_API_VERSION;
    const KIND: &'static str = SHADOW_ROLE_AUTHORIZATION_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        SHADOW_ROLE_AUTHORIZATION_API_VERSION;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_epoch_ns
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_epoch_ns
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.issued_at_epoch_ns <= 0
            || self.expires_at_epoch_ns <= self.issued_at_epoch_ns
            || self.record.authorization_revision == 0
            || self.record.assignment_revision == 0
            || self.record.runtime_attestation_receipt_revision == 0
            || self.record.attestation_evidence_revision == 0
            || self.record.fleet_membership_revision == 0
            || self.record.member_ordinal == 0
            || self.record.revocation_generation == 0
            || self.record.role != "shadow"
            || !bounded_ascii_token(&self.record.instance_id, 256)
            || self.record.shadow_signing_key_id
                != self.record.shadow_signing_key_spki_sha256
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeAttestationHandoff {
    api_version: String,
    receipt_id: Sha256Digest,
    receipt_revision: u64,
    receipt: SignedEnvelope<StartupRuntimeAttestationReceiptPayload>,
    receipt_sha256: Sha256Digest,
    receipt_payload_sha256: Sha256Digest,
    role_authorization_id: Sha256Digest,
    role_authorization_revision: u64,
    role_authorization:
        SignedEnvelope<ShadowRoleAuthorizationPayload>,
    role_authorization_sha256: Sha256Digest,
    role_authorization_payload_sha256: Sha256Digest,
    evidence: RuntimeAttestationEvidence,
    chain_sha256: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeAttestationVerifierResponse {
    api_version: String,
    evidence: RuntimeAttestationEvidence,
    verification:
        SignedEnvelope<RuntimeAttestationVerificationResult>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationInstallRequest {
    api_version: String,
    request_id: String,
    replay_id: String,
    management_handoff_id: String,
    assignment: SignedEnvelope<PolicyShadowAssignmentPayload>,
    load_receipt: SignedEnvelope<PolicyShadowLoadReceiptPayload>,
    active_policy_bundle: Value,
    candidate_policy_bundle: Value,
    runtime_attestation: RuntimeAttestationHandoff,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartupActivePolicyAuthorization {
    api_version: String,
    authorization_kind: String,
    active_snapshot_identity_sha256: Sha256Digest,
    active_policy_sha256: Sha256Digest,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    activation_transaction_sha256: Option<Sha256Digest>,
    activation_publication_receipt_sha256: Option<Sha256Digest>,
    activation_publication_revision: Option<u64>,
}

impl StartupActivePolicyAuthorization {
    fn validate_intrinsic(&self) -> Result<(), String> {
        if self.api_version != STARTUP_ACTIVE_AUTHORIZATION_API_VERSION
            || self.active_policy_sequence == 0
            || self.active_rollback_epoch == 0
        {
            return Err(
                "startup active-policy authorization metadata is invalid"
                    .to_string(),
            );
        }
        match self.authorization_kind.as_str() {
            "genesis" => {
                if self.activation_transaction_sha256.is_some()
                    || self
                        .activation_publication_receipt_sha256
                        .is_some()
                    || self.activation_publication_revision.is_some()
                {
                    return Err(
                        "genesis startup authorization must not claim an activation publication"
                            .to_string(),
                    );
                }
            }
            "activated" => {
                let Some(transaction_sha256) =
                    self.activation_transaction_sha256.as_ref()
                else {
                    return Err(
                        "activated startup authorization omits its activation transaction"
                            .to_string(),
                    );
                };
                let Some(receipt_sha256) = self
                    .activation_publication_receipt_sha256
                    .as_ref()
                else {
                    return Err(
                        "activated startup authorization omits its activation receipt"
                            .to_string(),
                    );
                };
                if transaction_sha256 == receipt_sha256
                    || self
                        .activation_publication_revision
                        .is_none_or(|revision| revision == 0)
                {
                    return Err(
                        "activated startup authorization publication binding is invalid"
                            .to_string(),
                    );
                }
            }
            _ => {
                return Err(
                    "startup active-policy authorization kind is unsupported"
                        .to_string(),
                )
            }
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeAttestationVerificationResult {
    schema_version: String,
    status: String,
    attestation_policy_sha256: Sha256Digest,
    verifier_executable_sha256: Sha256Digest,
    attestation_mode: String,
    hardware_attested: bool,
    assignment_payload_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    runtime_identity_sha256: Sha256Digest,
    runtime_attestation_receipt_sha256: Sha256Digest,
    runtime_attestation_payload_sha256: Sha256Digest,
    role_authorization_sha256: Sha256Digest,
    role_authorization_payload_sha256: Sha256Digest,
    attestation_evidence_id: Sha256Digest,
    attestation_evidence_revision: u64,
    tee_evidence_sha256: Sha256Digest,
    tee_measurement_sha256: Sha256Digest,
    runtime_executable_sha256: Sha256Digest,
    runtime_release_sha256: Sha256Digest,
    runtime_config_sha256: Sha256Digest,
    runtime_policy_sha256: Sha256Digest,
    shadow_signing_key_id: Sha256Digest,
    shadow_signing_key_spki_sha256: Sha256Digest,
    trust_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    evidence_chain_sha256: Sha256Digest,
    trusted_now_unix_nanos: i64,
    maximum_age_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl RuntimeAttestationVerificationResult {
    fn validate(
        &self,
        checkpoint: &AtomicTrustCheckpoint,
        assignment_payload_sha256: &Sha256Digest,
        load_receipt_payload_sha256: &Sha256Digest,
        runtime_identity_sha256: &Sha256Digest,
        runtime: &RuntimeIdentity,
        handoff: &RuntimeAttestationHandoff,
        evidence: &RuntimeAttestationEvidence,
        expected_policy_sha256: &Sha256Digest,
        expected_verifier_sha256: &Sha256Digest,
    ) -> Result<(), String> {
        let role = &handoff
            .role_authorization
            .untrusted_payload()
            .record;
        let hardware_expected =
            evidence.evidence_type != "trusted-host-no-tee";
        let runtime_hardware_expected =
            runtime.tee_platform_label() != "trusted-host-no-tee";
        let evidence_chain_sha256 = startup_attestation_handoff_chain_sha256(
            handoff,
            assignment_payload_sha256,
            load_receipt_payload_sha256,
            runtime_identity_sha256,
            expected_policy_sha256,
        )?;
        if self.schema_version != RUNTIME_VERIFIER_RESPONSE_API_VERSION
            || self.status != "verified"
            || self.attestation_policy_sha256 != *expected_policy_sha256
            || self.verifier_executable_sha256
                != *expected_verifier_sha256
            || self.attestation_mode != evidence.evidence_type
            || self.hardware_attested != hardware_expected
            || hardware_expected != runtime_hardware_expected
            || self.attestation_mode
                != runtime.tee_platform_label()
            || self.assignment_payload_sha256
                != *assignment_payload_sha256
            || self.load_receipt_payload_sha256
                != *load_receipt_payload_sha256
            || self.runtime_identity_sha256
                != *runtime_identity_sha256
            || self.runtime_attestation_receipt_sha256
                != handoff.receipt_sha256
            || self.runtime_attestation_payload_sha256
                != handoff.receipt_payload_sha256
            || self.role_authorization_sha256
                != handoff.role_authorization_sha256
            || self.role_authorization_payload_sha256
                != handoff.role_authorization_payload_sha256
            || self.attestation_evidence_id
                != evidence.evidence_id
            || self.attestation_evidence_revision
                != evidence.evidence_revision
            || self.tee_evidence_sha256 != evidence.evidence_sha256
            || self.tee_evidence_sha256
                != *runtime.tee_evidence_sha256()
            || self.tee_measurement_sha256
                != *runtime.tee_measurement_sha256()
            || self.tee_measurement_sha256
                != role.tee_measurement_sha256
            || self.runtime_executable_sha256
                != role.runtime_executable_sha256
            || self.runtime_release_sha256
                != role.runtime_release_sha256
            || self.runtime_config_sha256
                != role.runtime_config_sha256
            || self.runtime_policy_sha256
                != role.runtime_policy_sha256
            || self.shadow_signing_key_id
                != *runtime.shadow_signing_key_id()
            || self.shadow_signing_key_spki_sha256
                != *runtime.shadow_signing_key_spki_sha256()
            || self.shadow_signing_key_id
                != role.shadow_signing_key_id
            || self.shadow_signing_key_spki_sha256
                != role.shadow_signing_key_spki_sha256
            || self.shadow_signing_key_id
                != self.shadow_signing_key_spki_sha256
            || self.trust_checkpoint_sha256
                != role.attestation_trust_checkpoint_sha256
            || self.trust_checkpoint_sha256
                != checkpoint.checkpoint_id
            || self.revocation_generation
                != role.revocation_generation
            || self.revocation_generation
                != checkpoint.revocation_generation
            || self.revocation_root_sha256
                != role.revocation_root_sha256
            || self.revocation_root_sha256
                != checkpoint.revocation_root_sha256
            || self.evidence_chain_sha256 != evidence_chain_sha256
            || self.trusted_now_unix_nanos
                < checkpoint.as_of_unix_nanos
        {
            return Err(
                "runtime attestation verifier result binding is invalid"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl EnvelopePayload for RuntimeAttestationVerificationResult {
    const API_VERSION: &'static str =
        RUNTIME_VERIFIER_RESPONSE_API_VERSION;
    const KIND: &'static str = RUNTIME_VERIFIER_RESPONSE_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        RUNTIME_VERIFIER_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.schema_version != Self::API_VERSION
            || self.status != "verified"
            || self.revocation_generation == 0
            || self.attestation_evidence_revision == 0
            || self.shadow_signing_key_id
                != self.shadow_signing_key_spki_sha256
            || self.trusted_now_unix_nanos <= 0
            || self.maximum_age_nanos <= 0
            || self.maximum_age_nanos
                > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
            || self.issued_at_unix_nanos <= 0
            || self.trusted_now_unix_nanos
                < self.issued_at_unix_nanos
            || self.trusted_now_unix_nanos
                >= self.expires_at_unix_nanos
            || self.expires_at_unix_nanos
                <= self.issued_at_unix_nanos
            || self
                .expires_at_unix_nanos
                .checked_sub(self.issued_at_unix_nanos)
                .is_none_or(|lifetime| {
                    lifetime > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
                })
            || self
                .trusted_now_unix_nanos
                .checked_sub(self.issued_at_unix_nanos)
                .is_none_or(|age| age > self.maximum_age_nanos)
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct VerifiedRuntimeAttestation {
    result: RuntimeAttestationVerificationResult,
    runtime_identity_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    signed_verification_sha256: Sha256Digest,
}

impl RuntimeAttestationVerification for VerifiedRuntimeAttestation {
    fn verify_runtime_identity(
        &self,
        trust_checkpoint: &AtomicTrustCheckpoint,
        runtime: &RuntimeIdentity,
        _assigned_member: &FleetMember,
        assignment_payload_sha256: &Sha256Digest,
        trusted_now_unix_nanos: i64,
    ) -> Result<(), ShadowError> {
        let runtime_identity_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(runtime)?,
        );
        if trust_checkpoint.checkpoint_id
                != self.result.trust_checkpoint_sha256
            || trust_checkpoint.revocation_generation
                != self.result.revocation_generation
            || trust_checkpoint.revocation_root_sha256
                != self.result.revocation_root_sha256
            || runtime_identity_sha256
                != self.runtime_identity_sha256
            || assignment_payload_sha256
                != &self.assignment_payload_sha256
            || trusted_now_unix_nanos
                < self.result.issued_at_unix_nanos
            || trusted_now_unix_nanos
                >= self.result.expires_at_unix_nanos
            || trusted_now_unix_nanos
                .checked_sub(self.result.issued_at_unix_nanos)
                .is_none_or(|age| {
                    age > self.result.maximum_age_nanos
                })
            || self.result.tee_evidence_sha256
                != *runtime.tee_evidence_sha256()
            || self.signed_verification_sha256.as_str().is_empty()
        {
            return Err(ShadowError::RuntimeAttestationRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebAuthnVerificationResult {
    schema_version: String,
    status: String,
    verifier_executable_sha256: Sha256Digest,
    verification_policy_sha256: Sha256Digest,
    assertion_evidence_sha256: Sha256Digest,
    principal_id: Identifier,
    credential_id: Sha256Digest,
    readiness_core_challenge_sha256: Sha256Digest,
    assertion_object_sha256: Sha256Digest,
    authenticator_data_sha256: Sha256Digest,
    client_data_json_sha256: Sha256Digest,
    assertion_signature_sha256: Sha256Digest,
    cose_public_key_sha256: Sha256Digest,
    rp_id: Identifier,
    origin: CanonicalAscii,
    credential_state_revision: u64,
    previous_signature_counter: Option<u64>,
    signature_counter: u64,
    replay_state_sha256: Sha256Digest,
    approved_at_unix_nanos: i64,
    hardware_backed: bool,
    user_present: bool,
    user_verified: bool,
    verified_at_unix_nanos: i64,
    maximum_age_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for WebAuthnVerificationResult {
    const API_VERSION: &'static str =
        WEBAUTHN_VERIFIER_RESPONSE_API_VERSION;
    const KIND: &'static str = WEBAUTHN_VERIFIER_RESPONSE_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        WEBAUTHN_VERIFIER_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.schema_version != Self::API_VERSION
            || self.status != "verified"
            || self.credential_state_revision == 0
            || self.issued_at_unix_nanos <= 0
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
            || self.verified_at_unix_nanos < self.issued_at_unix_nanos
            || self.verified_at_unix_nanos >= self.expires_at_unix_nanos
            || self.maximum_age_nanos <= 0
            || self.maximum_age_nanos
                > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
            || self
                .verified_at_unix_nanos
                .checked_sub(self.issued_at_unix_nanos)
                .is_none_or(|age| age > self.maximum_age_nanos)
            || self.previous_signature_counter.is_some_and(|previous| {
                self.signature_counter != 0
                    && previous >= self.signature_counter
            })
        {
            return Err(ShadowError::ApprovalBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebAuthnVerifierResponse {
    api_version: String,
    assertion_evidence_sha256: Sha256Digest,
    verification: SignedEnvelope<WebAuthnVerificationResult>,
}

struct ExternalWebAuthnVerifier<'a> {
    command: &'a PinnedVerifierCommand,
    native_workers: Option<&'a Arc<serverware_decision_gate::native_shadow_workers::Owner>>,
    key_trust: &'a PinnedEnvelopeKeyTrust,
    trusted_time: &'a dyn TrustedTime,
}

impl WebAuthnVerification for ExternalWebAuthnVerifier<'_> {
    fn verify_assertion(
        &self,
        evidence: &WebAuthnAssertionEvidence,
        expected_readiness_core_sha256: &Sha256Digest,
        trusted_now_unix_nanos: i64,
    ) -> Result<VerifiedWebAuthnAssertion, ShadowError> {
        let expected_verifier_sha256 = Sha256Digest::parse(
            self.command.expected_sha256.clone(),
        )?;
        let request = json!({
            "apiVersion":WEBAUTHN_VERIFIER_REQUEST_API_VERSION,
            "operation":"resolve-and-verify-assertion-by-digest",
            "assertionEvidenceSha256":evidence.assertion_evidence_sha256,
            "readinessCoreChallengeSha256":expected_readiness_core_sha256,
            "verificationPolicySha256":
                self.key_trust.webauthn_verification_policy_sha256,
            "verifierExecutableSha256":expected_verifier_sha256,
        });
        let value = native::run_command(
            self.native_workers,
            serverware_decision_gate::native_shadow_workers::Purpose::Webauthn,
            self.command,
            &request,
            "policy activation WebAuthn verifier",
            64 * 1024,
        )
        .map_err(|_| ShadowError::ApprovalBindingMismatch)?;
        let response: WebAuthnVerifierResponse =
            serde_json::from_value(value)
                .map_err(|_| ShadowError::ApprovalBindingMismatch)?;
        if response.api_version != WEBAUTHN_VERIFIER_RESPONSE_API_VERSION
            || response.assertion_evidence_sha256
                != evidence.assertion_evidence_sha256
        {
            return Err(ShadowError::ApprovalBindingMismatch);
        }
        let verified = verify_envelope(
            response.verification,
            ExpectedSigner {
                key_id: &self
                    .key_trust
                    .webauthn_verifier_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .webauthn_verifier_signing_key_spki_sha256,
            },
            self.key_trust,
            self.trusted_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )?;
        let result = verified.payload();
        let current_now = self.trusted_time.now_unix_nanos()?;
        if current_now < trusted_now_unix_nanos
            || current_now < result.verified_at_unix_nanos
            || current_now >= result.expires_at_unix_nanos
            || current_now
                .checked_sub(result.verified_at_unix_nanos)
                .is_none_or(|age| age > result.maximum_age_nanos)
            || result.verifier_executable_sha256
                != expected_verifier_sha256
            || result.verification_policy_sha256
                != self.key_trust.webauthn_verification_policy_sha256
            || result.assertion_evidence_sha256
                != evidence.assertion_evidence_sha256
            || result.principal_id != evidence.principal_id
            || result.credential_id != evidence.credential_id
            || result.readiness_core_challenge_sha256
                != *expected_readiness_core_sha256
            || result.readiness_core_challenge_sha256
                != evidence.readiness_core_challenge_sha256
            || result.assertion_object_sha256
                != evidence.assertion_object_sha256
            || result.authenticator_data_sha256
                != evidence.authenticator_data_sha256
            || result.client_data_json_sha256
                != evidence.client_data_json_sha256
            || result.assertion_signature_sha256
                != evidence.assertion_signature_sha256
            || result.cose_public_key_sha256
                != evidence.cose_public_key_sha256
            || result.rp_id != evidence.rp_id
            || result.origin != evidence.origin
            || result.credential_state_revision
                != evidence.credential_state_revision
            || result.previous_signature_counter
                != evidence.expected_previous_signature_counter
            || result.signature_counter != evidence.signature_counter
            || result.replay_state_sha256
                != evidence.replay_state_sha256
            || result.approved_at_unix_nanos
                != evidence.approved_at_unix_nanos
        {
            return Err(ShadowError::ApprovalBindingMismatch);
        }
        Ok(VerifiedWebAuthnAssertion::from_authenticator_verification(
            result.assertion_evidence_sha256.clone(),
            result.principal_id.clone(),
            result.credential_id.clone(),
            result.assertion_object_sha256.clone(),
            result.authenticator_data_sha256.clone(),
            result.client_data_json_sha256.clone(),
            result.assertion_signature_sha256.clone(),
            result.cose_public_key_sha256.clone(),
            result.rp_id.clone(),
            result.origin.clone(),
            result.credential_state_revision,
            result.previous_signature_counter,
            result.signature_counter,
            result.replay_state_sha256.clone(),
            result.hardware_backed,
            result.user_present,
            result.user_verified,
        ))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationRequestBinding {
    request_id: String,
    replay_id: String,
    management_handoff_id: String,
    management_handoff_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationSnapshotBinding {
    policy_sha256: Sha256Digest,
    policy_sequence: u64,
    rollback_epoch: u64,
    compiled_snapshot_sha256: Sha256Digest,
    compiled_behavior_sha256: Sha256Digest,
    runtime_snapshot_epoch: u64,
    policy_trust_generation: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationGenerationBinding {
    generation_id: Sha256Digest,
    generation_epoch: u64,
    minimum_generation_tombstone_epoch: u64,
    generation_tombstone_epoch: u64,
    assignment_envelope_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    load_receipt_envelope_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    runtime_boot_id_sha256: Sha256Digest,
    active: PublicationSnapshotBinding,
    active_policy_bundle_sha256: Sha256Digest,
    candidate: PublicationSnapshotBinding,
    candidate_policy_bundle_sha256: Sha256Digest,
    request_commitment_key_epoch: u64,
    request_facts_schema_sha256: Sha256Digest,
    ingress_range_start_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    observation_interval_sha256: Sha256Digest,
    response_validation_obligations_root_sha256: Sha256Digest,
    signed_publication_revision: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationCustodyBinding {
    custody_configuration_sha256: Sha256Digest,
    preparation_receipt_sha256: Sha256Digest,
    publication_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    authoritative_ledger_event_ordinal: u64,
    authoritative_ledger_head_sha256: Sha256Digest,
    authoritative_spool_root_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationRuntimeBinding {
    decision_gate_executable_sha256: Sha256Digest,
    decision_gate_runtime_measurement_sha256: Sha256Digest,
    release_provenance_sha256: Sha256Digest,
    runtime_configuration_sha256: Sha256Digest,
    runtime_policy_sha256: Sha256Digest,
    image_signatures_sha256: Sha256Digest,
    generation_trust_manifest_sha256: Sha256Digest,
    policy_compiler_binary_sha256: Sha256Digest,
    policy_compiler_configuration_sha256: Sha256Digest,
    policy_schema_sha256: Sha256Digest,
    adapter_schema_sha256: Sha256Digest,
    policy_semantic_model_sha256: Sha256Digest,
    policy_plan_schema_sha256: Sha256Digest,
    request_facts_schema_sha256: Sha256Digest,
    runtime_attestation_verifier_executable_sha256: Sha256Digest,
    publication_handoff_executable_sha256: Sha256Digest,
    active_policy_signing_key_id: Sha256Digest,
    runtime_instance_id: String,
    runtime_identity_sha256: Sha256Digest,
    runtime_boot_id_sha256: Sha256Digest,
    runtime_tee_measurement_sha256: Sha256Digest,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationTrustBinding {
    trust_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    runtime_attestation_policy_sha256: Sha256Digest,
    runtime_attestation_verifier_signing_key_id: Sha256Digest,
    runtime_attestation_verifier_signing_key_spki_sha256: Sha256Digest,
    publication_signing_key_id: Sha256Digest,
    publication_signing_key_spki_sha256: Sha256Digest,
    publication_replay_store_sha256: Sha256Digest,
    replay_store_revision: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationAttestationChain {
    startup_attestation: RuntimeAttestationHandoff,
    runtime_attestation_verification:
        SignedEnvelope<RuntimeAttestationVerificationResult>,
    runtime_attestation_verification_envelope_sha256: Sha256Digest,
    attestation_mode: String,
    hardware_attested: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationPublicationPreparationPayload {
    schema_version: String,
    signature_domain: String,
    signature_algorithm: String,
    canonicalization_profile: String,
    status: String,
    request: PublicationRequestBinding,
    generation: PublicationGenerationBinding,
    runtime: PublicationRuntimeBinding,
    trust: PublicationTrustBinding,
    attestation_chain: PublicationAttestationChain,
    durable_reservation_receipt_sha256: Sha256Digest,
    not_before_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for GenerationPublicationPreparationPayload {
    const API_VERSION: &'static str =
        PUBLICATION_PREPARATION_API_VERSION;
    const KIND: &'static str = PUBLICATION_PREPARATION_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        PUBLICATION_PREPARATION_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_publication_common(
            &self.schema_version,
            Self::API_VERSION,
            &self.signature_domain,
            Self::SIGNATURE_DOMAIN,
            &self.signature_algorithm,
            &self.canonicalization_profile,
            &self.status,
            "prepared",
            &self.request,
            &self.generation,
            &self.runtime,
            &self.trust,
            &self.attestation_chain,
            self.not_before_unix_nanos,
            self.issued_at_unix_nanos,
            self.expires_at_unix_nanos,
        )?;
        if self.durable_reservation_receipt_sha256
            != publication_reservation_receipt_sha256(
                &self.request,
                &self.generation,
                &self.trust,
            )?
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationPublicationPayload {
    schema_version: String,
    signature_domain: String,
    signature_algorithm: String,
    canonicalization_profile: String,
    status: String,
    request: PublicationRequestBinding,
    preparation_envelope_sha256: Sha256Digest,
    generation: PublicationGenerationBinding,
    custody: PublicationCustodyBinding,
    runtime: PublicationRuntimeBinding,
    trust: PublicationTrustBinding,
    attestation_chain: PublicationAttestationChain,
    external_record_sha256: Sha256Digest,
    durable_commit_receipt_sha256: Sha256Digest,
    not_before_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationPublicationExternalRecord {
    request_id: String,
    replay_id: String,
    management_handoff_id: String,
    request_payload_sha256: Sha256Digest,
    management_handoff_identity_sha256: Sha256Digest,
    candidate_id: Sha256Digest,
    canary_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    generation_epoch: u64,
    minimum_generation_tombstone_epoch: u64,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    membership_root_sha256: Sha256Digest,
    member_ordinal: u64,
    member_id: Sha256Digest,
    instance_id: String,
    boot_id_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    generation_id: Sha256Digest,
    publication_revision: u64,
    custody_preparation_receipt_sha256: Sha256Digest,
    custody_high_water_sha256: Sha256Digest,
    custody_sequence: u64,
    ingress_high_water_sha256: Sha256Digest,
    ingress_sequence: u64,
    active_policy_sha256: Sha256Digest,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    active_policy_bundle_sha256: Sha256Digest,
    candidate_policy_sha256: Sha256Digest,
    candidate_policy_sequence: u64,
    candidate_rollback_epoch: u64,
    candidate_policy_bundle_sha256: Sha256Digest,
    runtime_executable_sha256: Sha256Digest,
    runtime_release_sha256: Sha256Digest,
    runtime_config_sha256: Sha256Digest,
    runtime_policy_sha256: Sha256Digest,
    attestation_policy_sha256: Sha256Digest,
    attestation_trust_checkpoint_sha256: Sha256Digest,
    runtime_attestation_receipt_sha256: Sha256Digest,
    runtime_attestation_payload_sha256: Sha256Digest,
    runtime_attestation_verification_receipt_sha256: Sha256Digest,
    attestation_role_authorization_sha256: Sha256Digest,
    attestation_evidence_sha256: Sha256Digest,
    tee_measurement_sha256: Sha256Digest,
    attestation_chain_sha256: Sha256Digest,
    attestation_mode: String,
    hardware_attested: bool,
    generation_evidence: GenerationPublicationPayload,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationPublicationExternalPayload {
    issued_at_epoch_ns: i64,
    expires_at_epoch_ns: i64,
    record: GenerationPublicationExternalRecord,
}

impl EnvelopePayload for GenerationPublicationExternalPayload {
    const API_VERSION: &'static str = INSTALL_RECEIPT_API_VERSION;
    const KIND: &'static str = INSTALL_RECEIPT_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        PUBLICATION_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_epoch_ns
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_epoch_ns
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.issued_at_epoch_ns <= 0
            || self.expires_at_epoch_ns <= self.issued_at_epoch_ns
            || self.record.assignment_revision == 0
            || self.record.generation_epoch == 0
            || self.record.minimum_generation_tombstone_epoch == 0
            || self.record.fleet_membership_revision == 0
            || self.record.member_ordinal == 0
            || self.record.publication_revision == 0
            || self.record.active_policy_sequence == 0
            || self.record.active_rollback_epoch == 0
            || self.record.candidate_policy_sequence == 0
            || self.record.candidate_rollback_epoch == 0
            || !bounded_ascii_token(
                &self.record.request_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || !bounded_ascii_token(&self.record.instance_id, 256)
            || !matches!(
                self.record.attestation_mode.as_str(),
                "aws-nitro-enclave"
                    | "amd-sev-snp"
                    | "intel-tdx"
                    | "trusted-host-no-tee"
            )
            || self.record.hardware_attested
                == (self.record.attestation_mode
                    == "trusted-host-no-tee")
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }
}

impl EnvelopePayload for GenerationPublicationPayload {
    const API_VERSION: &'static str = INSTALL_RECEIPT_API_VERSION;
    const KIND: &'static str = INSTALL_RECEIPT_KIND;
    const SIGNATURE_DOMAIN: &'static str =
        PUBLICATION_SIGNATURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_publication_common(
            &self.schema_version,
            Self::API_VERSION,
            &self.signature_domain,
            Self::SIGNATURE_DOMAIN,
            &self.signature_algorithm,
            &self.canonicalization_profile,
            &self.status,
            "published",
            &self.request,
            &self.generation,
            &self.runtime,
            &self.trust,
            &self.attestation_chain,
            self.not_before_unix_nanos,
            self.issued_at_unix_nanos,
            self.expires_at_unix_nanos,
        )?;
        if self.custody.publication_revision == 0
            || self.custody.publication_revision
                != self.generation.signed_publication_revision
            || self.durable_commit_receipt_sha256
                != publication_commit_receipt_sha256(
                    &self.request,
                    &self.preparation_envelope_sha256,
                    &self.generation,
                    &self.custody,
                    &self.trust,
                )?
            || self.preparation_envelope_sha256.as_str().is_empty()
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct GenerationPublicationReceipt {
    envelope: SignedEnvelope<GenerationPublicationExternalPayload>,
    internal_envelope: SignedEnvelope<GenerationPublicationPayload>,
    internal_envelope_sha256: Sha256Digest,
    canonical_envelope: Vec<u8>,
}

impl GenerationPublicationReceipt {
    pub(crate) fn canonical_envelope(&self) -> &[u8] {
        &self.canonical_envelope
    }

    pub(crate) fn audit_identity(&self) -> Value {
        json!({
            "apiVersion":INSTALL_RECEIPT_API_VERSION,
            "status":"published",
            "requestId":self.envelope.untrusted_payload().record.request_id,
            "generationId":self.envelope.untrusted_payload().record.generation_id,
            "publicationRevision":self.envelope.untrusted_payload().record.publication_revision,
            "internalPublicationEnvelopeSha256":self.internal_envelope_sha256,
            "publicationEnvelopeSha256":Sha256Digest::compute(&self.canonical_envelope),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationHandoffResponse {
    api_version: String,
    operation: String,
    status: String,
    preparation:
        Option<SignedEnvelope<GenerationPublicationPreparationPayload>>,
    internal_publication:
        Option<SignedEnvelope<GenerationPublicationPayload>>,
    publication:
        Option<SignedEnvelope<GenerationPublicationExternalPayload>>,
}

pub(crate) struct GenerationInstallError {
    status: &'static str,
    code: &'static str,
    detail: String,
}

impl GenerationInstallError {
    fn invalid(detail: impl Into<String>) -> Self {
        Self {
            status: "422 Unprocessable Entity",
            code: "policy_shadow_generation_invalid",
            detail: detail.into(),
        }
    }

    fn conflict(detail: impl Into<String>) -> Self {
        Self {
            status: "409 Conflict",
            code: "policy_shadow_generation_conflict",
            detail: detail.into(),
        }
    }

    pub(crate) fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            status: "503 Service Unavailable",
            code: "policy_shadow_generation_unavailable",
            detail: detail.into(),
        }
    }

    pub(crate) fn status(&self) -> &'static str {
        self.status
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn detail_sha256(&self) -> String {
        sha256_prefixed(self.detail.as_bytes())
    }
}

struct ImmutablePathIdentity {
    path: PathBuf,
    retained_file: fs::File,
    content_sha256: Sha256Digest,
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl ImmutablePathIdentity {
    fn revalidate(&self) -> Result<(), String> {
        let retained_metadata =
            self.retained_file.metadata().map_err(|error| {
                format!(
                    "reinspect retained policy-shadow custody configuration: {error}"
                )
            })?;
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            format!("reinspect policy-shadow custody configuration: {error}")
        })?;
        let mut bytes = vec![
            0_u8;
            usize::try_from(self.size).map_err(|_| {
                "policy-shadow custody configuration size is not representable"
                    .to_string()
            })?
        ];
        self.retained_file
            .read_exact_at(&mut bytes, 0)
            .map_err(|error| {
                format!(
                    "reread retained policy-shadow custody configuration: {error}"
                )
            })?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.len() != self.size
            || metadata.mode() != self.mode
            || metadata.mtime() != self.modified_seconds
            || metadata.mtime_nsec() != self.modified_nanoseconds
            || metadata.ctime() != self.changed_seconds
            || metadata.ctime_nsec() != self.changed_nanoseconds
            || !same_metadata(&metadata, &retained_metadata)
            || Sha256Digest::compute(&bytes) != self.content_sha256
        {
            return Err(
                "policy-shadow custody configuration changed after startup"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn retained_file(&self) -> Result<fs::File, String> {
        self.retained_file.try_clone().map_err(|error| {
            format!(
                "clone retained policy-shadow custody configuration descriptor: {error}"
            )
        })
    }

    fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivationMemberEvidence {
    load_receipt: SignedEnvelope<PolicyShadowLoadReceiptPayload>,
    runtime_attestation: RuntimeAttestationHandoff,
    runtime_attestation_verification:
        SignedEnvelope<RuntimeAttestationVerificationResult>,
    checkpoints: Vec<SignedEnvelope<PolicyShadowCheckpointPayload>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationActivationRequest {
    api_version: String,
    request_id: String,
    replay_id: String,
    generation_id: Sha256Digest,
    generation_publication_envelope_sha256: Sha256Digest,
    policy_authority_analysis:
        SignedEnvelope<PolicyAuthorityAnalysisPayload>,
    members: Vec<ActivationMemberEvidence>,
    readiness: SignedEnvelope<PolicyActivationReadinessPayload>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationActivationResponseWire {
    api_version: String,
    status: String,
    request_id: String,
    replay_id: String,
    request_sha256: Sha256Digest,
    generation_id: Sha256Digest,
    generation_publication_envelope:
        SignedEnvelope<GenerationPublicationPayload>,
    generation_publication_envelope_digest: Sha256Digest,
    activation_publication_envelope: ActivationPublicationReceiptWire,
    activation_publication_envelope_digest: Sha256Digest,
    runtime_attestation_verifier_envelope:
        SignedEnvelope<RuntimeAttestationVerificationResult>,
    runtime_attestation_verifier_envelope_digest: Sha256Digest,
    trusted_now_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

#[derive(Clone)]
pub(crate) struct GenerationActivationResponse {
    wire: GenerationActivationResponseWire,
    canonical_response: Vec<u8>,
}

impl GenerationActivationResponse {
    pub(crate) fn canonical_response(&self) -> &[u8] {
        &self.canonical_response
    }

    pub(crate) fn audit_identity(&self) -> Value {
        json!({
            "apiVersion":ACTIVATION_RESPONSE_API_VERSION,
            "status":"published",
            "requestId":self.wire.request_id,
            "replayId":self.wire.replay_id,
            "generationId":self.wire.generation_id,
            "requestSha256":self.wire.request_sha256,
            "activationPublicationEnvelopeDigest":
                self.wire.activation_publication_envelope_digest,
            "generationPublicationEnvelopeDigest":
                self.wire.generation_publication_envelope_digest,
            "runtimeAttestationVerifierEnvelopeDigest":
                self.wire.runtime_attestation_verifier_envelope_digest,
        })
    }
}

struct RetainedActivationResult {
    request_sha256: Sha256Digest,
    receipt: VerifiedActivationPublicationReceipt,
    trusted_now_unix_nanos: i64,
    response: Option<GenerationActivationResponse>,
}

struct RetainedGenerationActivationContext {
    install_request_sha256: Sha256Digest,
    assignment: VerifiedAssignment,
    load_receipt: VerifiedLoadReceipt,
    startup_attestation: RuntimeAttestationHandoff,
    runtime_attestation_verification:
        SignedEnvelope<RuntimeAttestationVerificationResult>,
    runtime_attestation: VerifiedRuntimeAttestation,
    trusted_time: Arc<AnchoredTrustedTime>,
    custody: Arc<dyn PolicyShadowCustodyRpcSupervisor>,
    generation_identity: ShadowGenerationIdentity,
    runtime_identity: RuntimeIdentity,
    publication_receipt: GenerationPublicationReceipt,
    activation: Mutex<Option<RetainedActivationResult>>,
}

fn build_activation_response(
    retained: &RetainedGenerationActivationContext,
    request_id: &str,
    replay_id: &str,
    request_sha256: &Sha256Digest,
    activation_receipt: &VerifiedActivationPublicationReceipt,
    trusted_now_unix_nanos: i64,
) -> Result<GenerationActivationResponse, GenerationInstallError> {
    let activation_publication_envelope_digest = Sha256Digest::compute(
        &canonical_json_bytes(activation_receipt.wire()).map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?,
    );
    let wire = GenerationActivationResponseWire {
        api_version: ACTIVATION_RESPONSE_API_VERSION.to_string(),
        status: "published".to_string(),
        request_id: request_id.to_string(),
        replay_id: replay_id.to_string(),
        request_sha256: request_sha256.clone(),
        generation_id: retained.generation_identity.generation_id().clone(),
        generation_publication_envelope: retained
            .publication_receipt
            .internal_envelope
            .clone(),
        generation_publication_envelope_digest: retained
            .publication_receipt
            .internal_envelope_sha256
            .clone(),
        activation_publication_envelope: activation_receipt.wire().clone(),
        activation_publication_envelope_digest,
        runtime_attestation_verifier_envelope: retained
            .runtime_attestation_verification
            .clone(),
        runtime_attestation_verifier_envelope_digest: Sha256Digest::compute(
            &canonical_json_bytes(&retained.runtime_attestation_verification)
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?,
        ),
        trusted_now_unix_nanos,
        expires_at_unix_nanos: retained
            .publication_receipt
            .internal_envelope
            .untrusted_payload()
            .expires_at_unix_nanos,
    };
    let canonical_response = canonical_json_bytes(&wire)
        .map_err(|error| GenerationInstallError::invalid(error.to_string()))?;
    if canonical_response.is_empty()
        || canonical_response.len() as u64 > MAX_ACTIVATION_BODY_BYTES
    {
        return Err(GenerationInstallError::unavailable(
            "canonical activation response is outside its fixed bound",
        ));
    }
    Ok(GenerationActivationResponse {
        wire,
        canonical_response,
    })
}

struct FleetRuntimeAttestation {
    members: Vec<VerifiedRuntimeAttestation>,
}

impl RuntimeAttestationVerification for FleetRuntimeAttestation {
    fn verify_runtime_identity(
        &self,
        trust_checkpoint: &AtomicTrustCheckpoint,
        runtime: &RuntimeIdentity,
        assigned_member: &FleetMember,
        assignment_payload_sha256: &Sha256Digest,
        trusted_now_unix_nanos: i64,
    ) -> Result<(), ShadowError> {
        let runtime_identity_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(runtime)?,
        );
        let verifier = self
            .members
            .iter()
            .find(|member| {
                member.runtime_identity_sha256
                    == runtime_identity_sha256
                    && member.assignment_payload_sha256
                        == *assignment_payload_sha256
            })
            .ok_or(ShadowError::RuntimeAttestationRevoked)?;
        verifier.verify_runtime_identity(
            trust_checkpoint,
            runtime,
            assigned_member,
            assignment_payload_sha256,
            trusted_now_unix_nanos,
        )
    }
}

/// Explicit startup inputs, not a verified trust or activation token.
///
/// Paths and pins are admitted by `from_config` through the same retained-file
/// and executable checks used by the environment-backed development entry.
pub(crate) struct PolicyShadowGenerationConfig {
    pub(crate) native_workers: Option<serverware_decision_gate::native_shadow_workers::Configuration>,
    pub(crate) native_activation:Option<activation::Configuration>,
    pub(crate) trust_manifest_path: PathBuf,
    pub(crate) trust_manifest_sha256: Sha256Digest,
    pub(crate) runtime_verifier: PinnedVerifierCommand,
    pub(crate) webauthn_verifier: PinnedVerifierCommand,
    pub(crate) publication_handoff: PinnedVerifierCommand,
    pub(crate) custody_config_path: PathBuf,
    pub(crate) custody_config_sha256: Option<Sha256Digest>,
    pub(crate) startup_generation_path: Option<PathBuf>,
    pub(crate) startup_generation_sha256: Option<Sha256Digest>,
    pub(crate) startup_active_authorization_path: Option<PathBuf>,
    pub(crate) startup_active_authorization_sha256: Option<Sha256Digest>,
}

pub(crate) struct PolicyShadowGenerationControl {
    native_workers: Option<Arc<serverware_decision_gate::native_shadow_workers::Owner>>,
    #[cfg(target_os="linux")]
    native_custody_lifecycle:Option<Arc<super::policy_shadow::NativeCustodyLifecycleOwner>>,
    native_activation:Mutex<Option<activation::Owner>>,
    is_production: bool,
    trust_manifest_sha256: Sha256Digest,
    key_trust: Arc<PinnedEnvelopeKeyTrust>,
    runtime_verifier: PinnedVerifierCommand,
    webauthn_verifier: PinnedVerifierCommand,
    publication_handoff: PinnedVerifierCommand,
    custody_config: ImmutablePathIdentity,
    installation_lock: Mutex<()>,
    #[cfg(target_os = "linux")]
    installed_custody: Mutex<
        Option<
            Arc<
                super::policy_shadow::
                    ProductionPolicyShadowCustodyRpcSupervisor,
            >,
        >,
    >,
    startup_request: Option<Vec<u8>>,
    startup_active_authorization:
        Option<StartupActivePolicyAuthorization>,
    retained_generation:
        Mutex<Option<Arc<RetainedGenerationActivationContext>>>,
}

impl PolicyShadowGenerationControl {
    pub(crate) fn from_env(
        is_production: bool,
        policy_trust_is_attested: bool,
    ) -> Result<Option<Arc<Self>>, String> {
        let configured = [
            TRUST_MANIFEST_PATH_ENV,
            TRUST_MANIFEST_SHA256_ENV,
            RUNTIME_VERIFIER_COMMAND_ENV,
            RUNTIME_VERIFIER_SHA256_ENV,
            WEBAUTHN_VERIFIER_COMMAND_ENV,
            WEBAUTHN_VERIFIER_SHA256_ENV,
            PUBLICATION_HANDOFF_COMMAND_ENV,
            PUBLICATION_HANDOFF_SHA256_ENV,
            CUSTODY_CONFIG_PATH_ENV,
            STARTUP_GENERATION_PATH_ENV,
            STARTUP_GENERATION_SHA256_ENV,
            STARTUP_ACTIVE_AUTHORIZATION_PATH_ENV,
            STARTUP_ACTIVE_AUTHORIZATION_SHA256_ENV,
        ]
        .iter()
        .any(|name| env::var_os(name).is_some());
        if !configured {
            if is_production {
                return Err(
                    "production requires policy-shadow generation trust, attestation, and custody configuration"
                        .to_string(),
                );
            }
            return Ok(None);
        }
        if is_production && !policy_trust_is_attested {
            return Err(
                "production policy-shadow generation control requires an attested policy trust root"
                    .to_string(),
            );
        }

        let config = PolicyShadowGenerationConfig {
            native_workers: None,
            native_activation:None,
            trust_manifest_path: PathBuf::from(required_env(
                TRUST_MANIFEST_PATH_ENV,
            )?),
            trust_manifest_sha256: Sha256Digest::parse(required_env(
                TRUST_MANIFEST_SHA256_ENV,
            )?).map_err(shadow_error)?,
            runtime_verifier: configured_pinned_command_from_env(
                RUNTIME_VERIFIER_COMMAND_ENV,
                RUNTIME_VERIFIER_SHA256_ENV,
            )?,
            webauthn_verifier: configured_pinned_command_from_env(
                WEBAUTHN_VERIFIER_COMMAND_ENV,
                WEBAUTHN_VERIFIER_SHA256_ENV,
            )?,
            publication_handoff: configured_pinned_command_from_env(
                PUBLICATION_HANDOFF_COMMAND_ENV,
                PUBLICATION_HANDOFF_SHA256_ENV,
            )?,
            custody_config_path: PathBuf::from(required_env(
                CUSTODY_CONFIG_PATH_ENV,
            )?),
            custody_config_sha256: None,
            startup_generation_path: optional_env_path(
                STARTUP_GENERATION_PATH_ENV,
            ),
            startup_generation_sha256: optional_env_digest(
                STARTUP_GENERATION_SHA256_ENV,
            )?,
            startup_active_authorization_path: optional_env_path(
                STARTUP_ACTIVE_AUTHORIZATION_PATH_ENV,
            ),
            startup_active_authorization_sha256: optional_env_digest(
                STARTUP_ACTIVE_AUTHORIZATION_SHA256_ENV,
            )?,
        };
        Self::from_config(is_production, policy_trust_is_attested, config)
            .map(Some)
    }

    /// Admit explicit startup inputs without consulting the environment.
    /// The caller's policy-trust classification is not created by this API;
    /// signed generation and active-policy joins still occur at their existing
    /// startup/installation boundaries.
    pub(crate) fn from_config(
        is_production: bool,
        policy_trust_is_attested: bool,
        config: PolicyShadowGenerationConfig,
    ) -> Result<Arc<Self>, String> {
        if config.native_workers.is_some() || config.native_activation.is_some() {
            return Err("native shadow workers require the retained pre-drop preparation owner".into());
        }
        if is_production && !policy_trust_is_attested {
            return Err(
                "production policy-shadow generation control requires an attested policy trust root"
                    .to_string(),
            );
        }
        let PolicyShadowGenerationConfig {
            native_workers: _,
            native_activation:_,
            trust_manifest_path,
            trust_manifest_sha256,
            runtime_verifier,
            webauthn_verifier,
            publication_handoff,
            custody_config_path,
            custody_config_sha256,
            startup_generation_path,
            startup_generation_sha256,
            startup_active_authorization_path,
            startup_active_authorization_sha256,
        } = config;
        let trust_path = normalized_absolute_path(
            trust_manifest_path,
            TRUST_MANIFEST_PATH_ENV,
        )?;
        let trust_bytes = read_immutable_artifact(
            &trust_path,
            MAX_TRUST_MANIFEST_BYTES,
            &trust_manifest_sha256,
            is_production,
            "policy-shadow trust manifest",
        )?;
        let key_trust = Arc::new(PinnedEnvelopeKeyTrust::from_manifest(
            &trust_bytes,
            &trust_manifest_sha256,
            is_production,
        )?);

        validate_configured_pinned_command(
            &runtime_verifier,
            RUNTIME_VERIFIER_SHA256_ENV,
        )?;
        validate_configured_pinned_command(
            &webauthn_verifier,
            WEBAUTHN_VERIFIER_SHA256_ENV,
        )?;
        validate_configured_pinned_command(
            &publication_handoff,
            PUBLICATION_HANDOFF_SHA256_ENV,
        )?;

        let custody_path = normalized_absolute_path(
            custody_config_path,
            CUSTODY_CONFIG_PATH_ENV,
        )?;
        let custody_config =
            immutable_config_identity(&custody_path, is_production)?;
        if custody_config_sha256.as_ref().is_some_and(|expected|
            expected != &custody_config.content_sha256)
        {
            return Err("policy-shadow custody configuration differs from its explicit SHA-256 pin".to_owned());
        }

        let startup_path = startup_generation_path
            .map(|path| normalized_absolute_path(
                path, STARTUP_GENERATION_PATH_ENV,
            ))
            .transpose()?;
        let startup_request = match (
            startup_path, startup_generation_sha256,
        ) {
            (None, None) => None,
            (Some(path), Some(digest)) => Some(read_immutable_artifact(
                &path,
                MAX_INSTALL_BODY_BYTES,
                &digest,
                is_production,
                "policy-shadow startup generation",
            )?),
            _ => {
                return Err(format!(
                    "{STARTUP_GENERATION_PATH_ENV} and {STARTUP_GENERATION_SHA256_ENV} must be configured together"
                ))
            }
        };
        let startup_authorization_path = startup_active_authorization_path
            .map(|path| normalized_absolute_path(
                path, STARTUP_ACTIVE_AUTHORIZATION_PATH_ENV,
            ))
            .transpose()?;
        let startup_active_authorization = match (
            startup_authorization_path,
            startup_active_authorization_sha256,
        ) {
            (None, None) if !is_production => None,
            (None, None) => {
                return Err(format!(
                    "production policy-shadow generation control requires {STARTUP_ACTIVE_AUTHORIZATION_PATH_ENV} and {STARTUP_ACTIVE_AUTHORIZATION_SHA256_ENV}"
                ))
            }
            (Some(path), Some(digest)) => {
                let bytes = read_immutable_artifact(
                    &path,
                    MAX_STARTUP_ACTIVE_AUTHORIZATION_BYTES,
                    &digest,
                    is_production,
                    "policy-shadow startup active-policy authorization",
                )?;
                let authorization: StartupActivePolicyAuthorization =
                    strict_json_from_slice(&bytes).map_err(|_| {
                        "policy-shadow startup active-policy authorization is not strict JSON"
                            .to_string()
                    })?;
                authorization.validate_intrinsic()?;
                if canonical_json_bytes(&authorization)
                    .map_err(shadow_error)?
                    != bytes
                {
                    return Err(
                        "policy-shadow startup active-policy authorization must use the exact canonical JSON profile"
                            .to_string(),
                    );
                }
                Some(authorization)
            }
            _ => {
                return Err(format!(
                    "{STARTUP_ACTIVE_AUTHORIZATION_PATH_ENV} and {STARTUP_ACTIVE_AUTHORIZATION_SHA256_ENV} must be configured together"
                ))
            }
        };

        Ok(Arc::new(Self {
            native_workers: None,
            #[cfg(target_os="linux")]
            native_custody_lifecycle:None,
            native_activation:Mutex::new(None),
            is_production,
            trust_manifest_sha256,
            key_trust,
            runtime_verifier,
            webauthn_verifier,
            publication_handoff,
            custody_config,
            installation_lock: Mutex::new(()),
            #[cfg(target_os = "linux")]
            installed_custody: Mutex::new(None),
            startup_request,
            startup_active_authorization,
            retained_generation: Mutex::new(None),
        }))
    }

    pub(crate) fn is_production(&self) -> bool {
        self.is_production
    }

    pub(crate) fn startup_request(&self) -> Option<&[u8]> {
        self.startup_request.as_deref()
    }

    pub(crate) fn authorize_startup_active_snapshot(
        &self,
        snapshot: &Snapshot,
    ) -> Result<(), String> {
        let Some(authorization) =
            self.startup_active_authorization.as_ref()
        else {
            if self.is_production {
                return Err(
                    "production startup active-policy authorization is unavailable"
                        .to_string(),
                );
            }
            return Ok(());
        };
        authorization.validate_intrinsic()?;
        let active_policy_sha256 =
            Sha256Digest::parse(snapshot.hash.clone()).map_err(shadow_error)?;
        let active_snapshot_identity_sha256 = domain_digest(
            b"serverware.policyShadowStartupActiveSnapshotIdentity/v1",
            &(
                snapshot.hash.as_str(),
                snapshot.policy_id.as_str(),
                snapshot.policy_sequence,
                snapshot.rollback_epoch,
                snapshot.compiled_behavior_sha256.as_str(),
                snapshot.policy_signing_key_id.as_str(),
                snapshot
                    .response_verifying_key
                    .as_ref()
                    .map(|key| key.to_bytes()),
                snapshot.response_signing_key_id.as_deref(),
                snapshot.attested_response_context.as_ref(),
            ),
        )?;
        if authorization.active_policy_sha256 != active_policy_sha256
            || authorization.active_policy_sequence
                != snapshot.policy_sequence
            || authorization.active_rollback_epoch
                != snapshot.rollback_epoch
            || authorization.active_snapshot_identity_sha256
                != active_snapshot_identity_sha256
        {
            return Err(
                "startup active-policy authorization does not name the exact initial snapshot"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub(crate) fn activate(
        &self,
        state: &GateState,
        body: &[u8],
    ) -> Result<GenerationActivationResponse, GenerationInstallError> {
        if body.is_empty()
            || body.len() as u64 > MAX_ACTIVATION_BODY_BYTES
        {
            return Err(GenerationInstallError::invalid(
                "policy-shadow activation body is outside its fixed bound",
            ));
        }
        let request: GenerationActivationRequest =
            strict_json_from_slice(body).map_err(|_| {
                GenerationInstallError::invalid(
                    "policy-shadow activation body is not strict JSON",
                )
            })?;
        let canonical_request = canonical_json_bytes(&request)
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        if canonical_request != body {
            return Err(GenerationInstallError::invalid(
                "policy-shadow activation request must use the exact canonical JSON profile",
            ));
        }
        let request_sha256 = Sha256Digest::compute(&canonical_request);
        if request.api_version != ACTIVATION_REQUEST_API_VERSION
            || !bounded_ascii_token(
                &request.request_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || !bounded_ascii_token(
                &request.replay_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || request.request_id == request.replay_id
            || request.members.is_empty()
            || request.members.len() > MAX_TRUST_KEYS
        {
            return Err(GenerationInstallError::invalid(
                "policy-shadow activation request metadata is invalid",
            ));
        }
        let activation_request_id = request.request_id.clone();
        let activation_replay_id = request.replay_id.clone();
        let activation_request_identifier =
            Identifier::parse(activation_request_id.clone()).map_err(
                |error| {
                    GenerationInstallError::invalid(error.to_string())
                },
            )?;
        let activation_replay_identifier =
            Identifier::parse(activation_replay_id.clone()).map_err(
                |error| {
                    GenerationInstallError::invalid(error.to_string())
                },
            )?;
        let _activation = self.installation_lock.try_lock().map_err(|_| {
            GenerationInstallError::conflict(
                "policy-shadow generation mutation is already in progress",
            )
        })?;
        let retained = self
            .retained_generation
            .try_lock()
            .map_err(|_| {
                GenerationInstallError::conflict(
                    "retained policy-shadow generation is busy",
                )
            })?
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                GenerationInstallError::conflict(
                    "no exactly retained policy-shadow generation is available",
                )
            })?;
        let selection_now_unix_nanos = retained
            .trusted_time
            .now_unix_nanos()
            .map_err(|error| {
                GenerationInstallError::conflict(error.to_string())
            })?;
        self.key_trust
            .authorize_at(selection_now_unix_nanos)
            .map_err(GenerationInstallError::conflict)?;
        if request.generation_id
                != *retained.generation_identity.generation_id()
            || request.generation_publication_envelope_sha256
                != retained
                    .publication_receipt
                    .internal_envelope_sha256
        {
            return Err(GenerationInstallError::conflict(
                "activation does not name the exact retained generation publication",
            ));
        }
        let mut retained_activation =
            retained.activation.try_lock().map_err(|_| {
                GenerationInstallError::conflict(
                    "retained activation result is busy",
                )
            })?;
        if let Some(previous) = retained_activation.as_mut() {
            if previous.request_sha256 != request_sha256 {
                return Err(GenerationInstallError::conflict(
                    "the retained generation was already activated by different canonical bytes",
                ));
            }
            let replay_now_unix_nanos = retained
                .trusted_time
                .now_unix_nanos()
                .map_err(|error| {
                    GenerationInstallError::conflict(error.to_string())
                })?;
            self.key_trust
                .authorize_at(replay_now_unix_nanos)
                .map_err(GenerationInstallError::conflict)?;
            let response = if let Some(response) = previous.response.clone() {
                response
            } else {
                let response = build_activation_response(
                    &retained,
                    &activation_request_id,
                    &activation_replay_id,
                    &request_sha256,
                    &previous.receipt,
                    previous.trusted_now_unix_nanos,
                )?;
                previous.response = Some(response.clone());
                response
            };
            let activation_receipt = previous.receipt.clone();
            drop(retained_activation);
            state
                .policy_shadow
                .retain_activation_publication(
                    &retained.generation_identity,
                    &activation_receipt,
                )
                .map_err(GenerationInstallError::conflict)?;
            return Ok(response);
        }
        drop(retained_activation);

        let signers = activation_authority_signers(&retained.assignment)
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let authority_analysis = verify_policy_authority_analysis(
            request.policy_authority_analysis,
            &retained.assignment,
            signers.analysis,
            self.key_trust.as_ref(),
            retained.trusted_time.as_ref(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "policy authority analysis is invalid: {error}"
            ))
        })?;

        let mut attestation_members = Vec::with_capacity(request.members.len());
        let mut previous_instance_id: Option<String> = None;
        for member in &request.members {
            let instance_id = member
                .load_receipt
                .untrusted_payload()
                .runtime_identity()
                .instance_id()
                .as_str()
                .to_string();
            if previous_instance_id
                .as_ref()
                .is_some_and(|previous| previous >= &instance_id)
            {
                return Err(GenerationInstallError::invalid(
                    "activation member evidence must be unique and sorted by instance identity",
                ));
            }
            previous_instance_id = Some(instance_id);
            attestation_members.push(
                self.verify_activation_member_attestation(
                    member,
                    &retained.assignment,
                )?,
            );
        }
        let fleet_attestation = FleetRuntimeAttestation {
            members: attestation_members,
        };
        let mut load_receipts = Vec::with_capacity(request.members.len());
        let mut final_checkpoints = Vec::with_capacity(request.members.len());
        let mut retained_local_member_seen = false;
        for member in request.members {
            let load_receipt = verify_load_receipt(
                member.load_receipt.clone(),
                &retained.assignment,
                &fleet_attestation,
                self.key_trust.as_ref(),
                retained.trusted_time.as_ref(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(format!(
                    "activation load receipt is invalid: {error}"
                ))
            })?;
            if load_receipt.envelope_sha256()
                    == retained.load_receipt.envelope_sha256()
            {
                if retained_local_member_seen
                    || member.runtime_attestation
                        != retained.startup_attestation
                    || member.runtime_attestation_verification
                        != retained.runtime_attestation_verification
                    || load_receipt.payload().runtime_identity()
                        != &retained.runtime_identity
                {
                    return Err(GenerationInstallError::conflict(
                        "local activation evidence is not the exact retained runtime context",
                    ));
                }
                retained_local_member_seen = true;
            }
            let final_checkpoint = verify_activation_checkpoint_chain(
                member.checkpoints,
                &retained.assignment,
                &load_receipt,
                &authority_analysis,
                self.key_trust.as_ref(),
                retained.trusted_time.as_ref(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(format!(
                    "activation checkpoint chain is invalid: {error}"
                ))
            })?;
            load_receipts.push(load_receipt);
            final_checkpoints.push(final_checkpoint);
        }
        if !retained_local_member_seen {
            return Err(GenerationInstallError::conflict(
                "activation omitted the exact retained local generation member",
            ));
        }
        let webauthn = ExternalWebAuthnVerifier {
            command: &self.webauthn_verifier,
            native_workers: self.native_workers.as_ref(),
            key_trust: self.key_trust.as_ref(),
            trusted_time: retained.trusted_time.as_ref(),
        };
        let readiness = verify_activation_readiness(
            request.readiness,
            &retained.assignment,
            &authority_analysis,
            &load_receipts,
            &final_checkpoints,
            signers.readiness,
            signers.approval,
            &fleet_attestation,
            retained.custody.as_ref(),
            self.key_trust.as_ref(),
            &webauthn,
            retained.trusted_time.as_ref(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "activation readiness is invalid: {error}"
            ))
        })?;
        let trusted_now_unix_nanos = retained
            .trusted_time
            .now_unix_nanos()
            .map_err(|error| {
                GenerationInstallError::conflict(error.to_string())
            })?;
        self.key_trust
            .authorize_at(trusted_now_unix_nanos)
            .map_err(GenerationInstallError::conflict)?;
        let mut retained_activation =
            retained.activation.try_lock().map_err(|_| {
                GenerationInstallError::conflict(
                    "retained activation result is busy",
                )
            })?;
        if retained_activation.is_some() {
            return Err(GenerationInstallError::conflict(
                "activation result raced with another publication",
            ));
        }
        let activation_receipt = readiness
            .consume_and_publish(
                request_sha256.clone(),
                activation_request_identifier,
                activation_replay_identifier,
                self.key_trust.as_ref(),
                retained.trusted_time.as_ref(),
                &fleet_attestation,
                &webauthn,
                retained.custody.as_ref(),
            )
            .map_err(|error| {
                GenerationInstallError::conflict(format!(
                    "activation publication failed: {error}"
                ))
            })?;
        *retained_activation = Some(RetainedActivationResult {
            request_sha256: request_sha256.clone(),
            receipt: activation_receipt.clone(),
            trusted_now_unix_nanos,
            response: None,
        });
        let response = build_activation_response(
            &retained,
            &activation_request_id,
            &activation_replay_id,
            &request_sha256,
            &activation_receipt,
            trusted_now_unix_nanos,
        )?;
        let Some(retained_result) = retained_activation.as_mut() else {
            return Err(GenerationInstallError::conflict(
                "committed activation result was not retained",
            ));
        };
        retained_result.response = Some(response.clone());
        drop(retained_activation);
        state
            .policy_shadow
            .retain_activation_publication(
                &retained.generation_identity,
                &activation_receipt,
            )
            .map_err(GenerationInstallError::conflict)?;
        Ok(response)
    }

    fn verify_activation_member_attestation(
        &self,
        member: &ActivationMemberEvidence,
        assignment: &VerifiedAssignment,
    ) -> Result<VerifiedRuntimeAttestation, GenerationInstallError> {
        let load_receipt_payload_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(member.load_receipt.untrusted_payload())
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?,
        );
        let runtime = member.load_receipt.untrusted_payload().runtime_identity();
        let runtime_identity_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(runtime).map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let result = member
            .runtime_attestation_verification
            .untrusted_payload();
        let chain = PublicationAttestationChain {
            startup_attestation: member.runtime_attestation.clone(),
            runtime_attestation_verification: member
                .runtime_attestation_verification
                .clone(),
            runtime_attestation_verification_envelope_sha256:
                Sha256Digest::compute(
                    &canonical_json_bytes(
                        &member.runtime_attestation_verification,
                    )
                    .map_err(|error| {
                        GenerationInstallError::invalid(
                            error.to_string(),
                        )
                    })?,
                ),
            attestation_mode: result.attestation_mode.clone(),
            hardware_attested: result.hardware_attested,
        };
        self.verify_embedded_attestation_chain_values(
            &chain,
            assignment.payload_sha256(),
            &load_receipt_payload_sha256,
            &runtime_identity_sha256,
            Some(runtime),
        )?;
        let signed_time = FixedTrustedTime {
            now_unix_nanos: result.trusted_now_unix_nanos,
        };
        let verified = verify_envelope(
            member.runtime_attestation_verification.clone(),
            ExpectedSigner {
                key_id: &self
                    .key_trust
                    .runtime_attestation_verifier_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .runtime_attestation_verifier_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            &signed_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        let expected_verifier_sha256 = Sha256Digest::parse(
            self.runtime_verifier.expected_sha256.clone(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        verified
            .payload()
            .validate(
                &self.key_trust.checkpoint,
                assignment.payload_sha256(),
                &load_receipt_payload_sha256,
                &runtime_identity_sha256,
                runtime,
                &member.runtime_attestation,
                &member.runtime_attestation.evidence,
                &self.key_trust.runtime_attestation_policy_sha256,
                &expected_verifier_sha256,
            )
            .map_err(GenerationInstallError::invalid)?;
        Ok(VerifiedRuntimeAttestation {
            result: verified.payload().clone(),
            runtime_identity_sha256,
            assignment_payload_sha256:
                assignment.payload_sha256().clone(),
            signed_verification_sha256:
                verified.envelope_sha256().clone(),
        })
    }

    pub(crate) fn with_native_generation_origin<T>(&self,state:&GateState,assignment:&str,generation:&str,
        consume:impl FnOnce(String,u64)->Result<T,String>)->Result<T,String>{
        if !self.is_production || self.native_workers.is_none(){return Err("origin requires native installed generation".into());}
        let _installation=self.installation_lock.try_lock().map_err(|_|"origin installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"origin generation busy")?;
        let retained=retained.as_ref().ok_or("origin has no installed generation")?;
        let now=retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?;
        self.key_trust.authorize_at(now)?;
        let scope=super::policy_shadow::native_heartbeat::scope(&retained.generation_identity,&retained.assignment,
            &retained.load_receipt,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|e|e.to_string())?;
        if retained.assignment.payload_sha256().as_str()!=assignment || retained.generation_identity.generation_id().as_str()!=generation
            || now<=0 || now>=scope["expiresAtUnixNanos"].as_i64().ok_or("origin assignment window absent")? {
            return Err("origin generation, assignment or original lifetime differs".into());
        }
        let configuration=retained.custody.production_configuration_binding_sha256().ok_or("origin installed custody absent")?;
        let baseline=state.policy_shadow.native_accounting_snapshot(retained.generation_identity.generation_id(),retained.trusted_time.as_ref())?;
        // Only the genuine virgin installed generation is admitted by this
        // initialization profile. A used generation needs its complete
        // historical continuation, not an empty replacement spool.
        if baseline.original_count()!=0 || baseline.last_ingress().is_some()
            || baseline.event_ordinal()!=retained.generation_identity.authoritative_ledger_event_ordinal()
            || baseline.head_sha256()!=retained.generation_identity.authoritative_ledger_head_sha256()
            || baseline.event_ordinal()!=baseline.baseline_event_ordinal()
            || baseline.head_sha256()!=baseline.baseline_head_sha256() {
            return Err("origin requires the actual unused installed baseline".into());
        }
        let value=serde_json::json!({"apiVersion":"serverware.nativeInstalledGenerationOriginals/v1",
            "installRequestSha256":retained.install_request_sha256,"generation":retained.generation_identity,
            "assignment":retained.assignment.wire(),"loadReceipt":retained.load_receipt.wire(),
            "runtimeAttestation":retained.startup_attestation,"runtimeAttestationVerification":retained.runtime_attestation_verification,
            "runtimeIdentity":retained.runtime_identity,"publication":retained.publication_receipt,
            "productionConfigurationBindingSha256":configuration,"trustCheckpoint":self.key_trust.current_checkpoint().map_err(|e|e.to_string())?,
            "ledgerBaseline":{"eventOrdinal":baseline.event_ordinal(),"headSha256":baseline.head_sha256(),
                "originalCount":baseline.original_count(),"lastIngress":baseline.last_ingress(),
                "observedAtUnixNanos":baseline.observed_at_unix_nanos()}});
        let raw=super::native_response_profile::canonical_ascii_bytes(&value)?;
        if raw.is_empty() || raw.len()>serverware_decision_gate::native_generation_origin_v1::MAX_ORIGINALS{return Err("complete generation originals exceed bound".into());}
        // Both actual owner guards remain held through the purpose-specific
        // signature and fresh quote. This is provenance, not an initialization.
        let result=consume(String::from_utf8(raw).map_err(|_|"origin original not ASCII")?,now as u64)?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?)?;
        Ok(result)
    }

    pub(crate) fn native_opening(&self, admission:&super::policy_shadow::PersistedIngressAdmission)
        ->Result<super::policy_shadow::native_opening::Opening,String> {
        if !self.is_production || self.native_workers.is_none() {
            return Err("native opening requires the actual native custody generation owner".into());
        }
        let _installation=self.installation_lock.try_lock().map_err(|_|"opening generation installation is busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"opening retained generation is busy")?;
        let retained=retained.as_ref().ok_or("opening has no successfully installed generation")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|error|error.to_string())?)?;
        let configuration=retained.custody.production_configuration_binding_sha256()
            .ok_or("opening custody lacks its production configuration")?;
        super::policy_shadow::native_opening::Opening::from_admission(admission,&retained.generation_identity,
            &retained.assignment,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            &configuration,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|error|error.to_string())
    }

    pub(crate) fn native_request_facts_selected(&self)->Result<bool,String>{
        let _installation=self.installation_lock.try_lock().map_err(|_|"facts selection installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"facts selection generation busy")?;
        let retained=retained.as_ref().ok_or("facts selection lacks installed generation")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?)?;
        retained.custody.native_request_facts_selected().map_err(|e|e.to_string())
    }
    pub(crate) fn commit_native_request_facts(&self,generation:&Sha256Digest,ingress:u64,observed:i64,
        facts:&super::policy_shadow::ProtectedRequestFacts)->Result<super::policy_shadow::RequestCommitment,String>{
        if !self.is_production || self.native_workers.is_none(){return Err("facts require actual native installed generation".into());}
        let _installation=self.installation_lock.try_lock().map_err(|_|"facts installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"facts generation busy")?;
        let retained=retained.as_ref().ok_or("facts have no installed generation")?;
        if !retained.custody.native_request_facts_selected().map_err(|e|e.to_string())? {
            return Err("facts commitment requires the actual effects runtime successor".into());
        }
        if retained.generation_identity.generation_id()!=generation{return Err("facts crossed installed generation".into());}
        let now=retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?;
        self.key_trust.authorize_at(now)?;
        let scope=super::policy_shadow::native_heartbeat::finalization_scope(&retained.generation_identity,&retained.assignment,
            &retained.load_receipt,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|e|e.to_string())?;
        if observed>now || now>=scope["sealDeadlineUnixNanos"].as_i64().ok_or("original facts seal deadline")? {
            return Err("facts capture or processing exceeds original generation lifetime".into());
        }
        let context=super::policy_shadow::RequestCommitmentContext::from_verified_binding(
            &retained.assignment,&retained.runtime_identity,ingress,observed).map_err(|e|e.to_string())?;
        // Actual installation/retained-generation guards survive the one call,
        // its definite settlement and exact returned context validation.
        let commitment=super::policy_core::native_request_facts::commit(retained.custody.as_ref(),facts,&context)?;
        commitment.validate_binding(&retained.assignment,&retained.runtime_identity,ingress,observed).map_err(|e|e.to_string())?;
        let completed=retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?;
        self.key_trust.authorize_at(completed)?;
        if completed<now || completed>=scope["sealDeadlineUnixNanos"].as_i64().ok_or("original facts seal deadline")? {
            return Err("facts completion exceeded the original generation deadline".into());
        }
        Ok(commitment)
    }

    pub(crate) fn with_native_heartbeat_snapshot<T>(&self,state:&GateState,
        consume:impl FnOnce(super::policy_core::NativeAccountingSnapshot,Value)->Result<T,String>)
        ->Result<T,String>{
        if !self.is_production || self.native_workers.is_none(){return Err("heartbeat requires native installed generation".into());}
        let _installation=self.installation_lock.try_lock().map_err(|_|"heartbeat installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"heartbeat generation busy")?;
        let retained=retained.as_ref().ok_or("heartbeat has no installed generation")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?)?;
        let scope=super::policy_shadow::native_heartbeat::scope(&retained.generation_identity,&retained.assignment,
            &retained.load_receipt,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|e|e.to_string())?;
        let snapshot=state.policy_shadow.native_accounting_snapshot(retained.generation_identity.generation_id(),retained.trusted_time.as_ref())?;
        if snapshot.observed_at_unix_nanos()<scope["startsAtUnixNanos"].as_i64().ok_or("heartbeat window start")?
            || snapshot.observed_at_unix_nanos()>=scope["expiresAtUnixNanos"].as_i64().ok_or("heartbeat window end")? {
            return Err("heartbeat outside actual assignment window".into());
        }
        // Retain these actual installation/generation guards through signing
        // and definite delivery. The ledger lock itself was released above.
        consume(snapshot,scope)
    }

    pub(crate) fn with_native_finalization_snapshot<T>(&self,state:&GateState,
        consume:impl FnOnce(super::policy_core::NativeAccountingSnapshot,Value,Option<super::policy_core::NativeDrainSnapshot>)->Result<T,String>)
        ->Result<Option<T>,String>{
        if !self.is_production || self.native_workers.is_none(){return Err("finalization needs native generation".into());}
        let _installation=match self.installation_lock.try_lock(){
            Ok(guard)=>guard,Err(std::sync::TryLockError::WouldBlock)=>return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_))=>return Err("finalization installation poisoned".into())};
        let retained=match self.retained_generation.try_lock(){
            Ok(guard)=>guard,Err(std::sync::TryLockError::WouldBlock)=>return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_))=>return Err("finalization generation poisoned".into())};
        let Some(retained)=retained.as_ref() else{return Ok(None);};
        let now=retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?;
        self.key_trust.authorize_at(now)?;
        let scope=super::policy_shadow::native_heartbeat::finalization_scope(&retained.generation_identity,&retained.assignment,
            &retained.load_receipt,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|e|e.to_string())?;
        let start=scope["startsAtUnixNanos"].as_i64().ok_or("finalization start")?;
        let end=scope["windowEndsAtUnixNanos"].as_i64().ok_or("finalization end")?;
        let expires=scope["expiresAtUnixNanos"].as_i64().ok_or("finalization expiry")?;
        state.policy_shadow.native_drain_arm(retained.generation_identity.generation_id(),now,end,
            scope["sealDeadlineUnixNanos"].as_i64().ok_or("original seal deadline")?)?;
        if now<=start {return Ok(None);}
        if now>=expires {return Err("original finalization window elapsed".into());}
        let seal=if now>=end {state.policy_shadow.native_drain_snapshot(retained.generation_identity.generation_id(),now,end,
            scope["sealDeadlineUnixNanos"].as_i64().ok_or("original seal deadline")?)?}else{None};
        let snapshot=state.policy_shadow.native_accounting_snapshot(retained.generation_identity.generation_id(),retained.trusted_time.as_ref())?;
        if snapshot.observed_at_unix_nanos()>=expires {return Err("snapshot passed original finalization expiry".into());}
        if let Some(seal)=&seal {seal.require_complete(&snapshot)?;}
        // SAME installed generation and key/trusted-time guards survive the
        // signature and definite heartbeat delivery; no retained DTO adoption.
        consume(snapshot,scope,seal).map(Some)
    }

    pub(crate) fn native_final_cumulative_observation(&self,heartbeat:&super::native_canary_finalization::RetainedHeartbeat,
        attempt:&super::policy_core::NativeCumulativeAttempt,interval:Option<&Sha256Digest>)
        ->Result<super::policy_shadow::native_final_cumulative::Checkpoint,String>{
        let _installation=self.installation_lock.try_lock().map_err(|_|"final cumulative installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"final cumulative generation busy")?;
        let retained=retained.as_ref().ok_or("final cumulative generation absent")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|e|e.to_string())?)?;
        let snapshot=heartbeat.snapshot();
        if snapshot.generation_id()!=retained.generation_identity.generation_id(){return Err("final heartbeat generation changed".into());}
        let configuration=retained.custody.production_configuration_binding_sha256().ok_or("final custody configuration absent")?;
        super::policy_shadow::native_final_cumulative::Checkpoint::from_originals(&retained.generation_identity,
            snapshot.baseline_event_ordinal(),snapshot.baseline_head_sha256(),snapshot.event_ordinal(),snapshot.head_sha256(),
            snapshot.observed_at_unix_nanos(),snapshot.originals(),heartbeat.original(),heartbeat.sha256(),attempt.sequence(),attempt.previous(),
            interval,heartbeat.seal(),&retained.assignment,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            &configuration,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|e|e.to_string())
    }

    pub(crate) fn native_runtime_observation(&self,receipt:&super::policy_shadow::VerifiedShadowSpillReceipt,
        opening:&Sha256Digest,terminal:Option<&Sha256Digest>)
        ->Result<super::policy_shadow::native_runtime::Observation,String> {
        self.native_observation(receipt,opening,terminal,None)
    }
    pub(crate) fn native_checkpoint_window(&self)->Result<(Sha256Digest,u64),String> {
        if !self.is_production || self.native_workers.is_none() {
            return Err("checkpoint window requires actual native custody".into());
        }
        let _installation=self.installation_lock.try_lock().map_err(|_|"checkpoint installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"checkpoint generation busy")?;
        let retained=retained.as_ref().ok_or("checkpoint generation absent")?;
        let remaining=super::policy_shadow::native_checkpoint::remaining_window(&retained.assignment,&retained.load_receipt,
            &retained.generation_identity,retained.trusted_time.as_ref()).map_err(|error|error.to_string())?;
        Ok((retained.generation_identity.generation_id().clone(),remaining))
    }
    pub(crate) fn native_checkpoint_observation(&self,applied:&super::policy_core::AppliedSpoolCheckpoint)
        ->Result<super::policy_shadow::native_checkpoint::Checkpoint,String> {
        if !self.is_production || self.native_workers.is_none() {
            return Err("checkpoint requires the actual native custody generation owner".into());
        }
        let _installation=self.installation_lock.try_lock().map_err(|_|"checkpoint generation installation is busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"checkpoint retained generation is busy")?;
        let retained=retained.as_ref().ok_or("checkpoint has no successfully installed generation")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|error|error.to_string())?)?;
        let configuration=retained.custody.production_configuration_binding_sha256().ok_or("checkpoint custody configuration absent")?;
        super::policy_shadow::native_checkpoint::Checkpoint::from_receipt(applied.receipt(),applied.ordered_range(),&retained.generation_identity,
            &retained.assignment,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            &configuration,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|error|error.to_string())
    }
    pub(crate) fn native_response_observation(&self,receipt:&super::policy_shadow::VerifiedShadowSpillReceipt,
        opening:&Sha256Digest,terminal:&Sha256Digest,request:&Sha256Digest)
        ->Result<super::policy_shadow::native_runtime::Observation,String> {
        self.native_observation(receipt,opening,Some(terminal),Some(request))
    }
    pub(crate) fn native_cumulative_observation(&self,heartbeat:&super::native_canary_heartbeat::RetainedHeartbeat,
        attempt:&super::policy_core::NativeCumulativeAttempt,interval:&Sha256Digest)
        ->Result<super::policy_shadow::native_cumulative::Checkpoint,String> {
        if !self.is_production || self.native_workers.is_none() {return Err("cumulative checkpoint needs actual native custody".into());}
        let _installation=self.installation_lock.try_lock().map_err(|_|"cumulative installation busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"cumulative generation busy")?;
        let retained=retained.as_ref().ok_or("cumulative generation absent")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|error|error.to_string())?)?;
        let snapshot=heartbeat.snapshot();
        if snapshot.generation_id()!=retained.generation_identity.generation_id() {return Err("cumulative heartbeat generation changed".into());}
        let configuration=retained.custody.production_configuration_binding_sha256().ok_or("cumulative custody configuration absent")?;
        super::policy_shadow::native_cumulative::Checkpoint::from_originals(&retained.generation_identity,
            snapshot.baseline_event_ordinal(),snapshot.baseline_head_sha256(),snapshot.event_ordinal(),snapshot.head_sha256(),
            snapshot.observed_at_unix_nanos(),snapshot.originals(),heartbeat.original(),heartbeat.sha256(),attempt.sequence(),attempt.previous(),
            interval,&retained.assignment,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
            &configuration,self.key_trust.as_ref(),retained.trusted_time.as_ref()).map_err(|error|error.to_string())
    }
    fn native_observation(&self,receipt:&super::policy_shadow::VerifiedShadowSpillReceipt,
        opening:&Sha256Digest,terminal:Option<&Sha256Digest>,request:Option<&Sha256Digest>)
        ->Result<super::policy_shadow::native_runtime::Observation,String> {
        if !self.is_production || self.native_workers.is_none() {
            return Err("runtime observation requires the actual native custody generation owner".into());
        }
        let _installation=self.installation_lock.try_lock().map_err(|_|"runtime generation installation is busy")?;
        let retained=self.retained_generation.try_lock().map_err(|_|"runtime retained generation is busy")?;
        let retained=retained.as_ref().ok_or("runtime observation has no installed generation")?;
        self.key_trust.authorize_at(retained.trusted_time.now_unix_nanos().map_err(|error|error.to_string())?)?;
        let configuration=retained.custody.production_configuration_binding_sha256().ok_or("runtime custody configuration absent")?;
        match (terminal,request) {
            (Some(terminal),Some(request))=>super::policy_shadow::native_runtime::Observation::from_response(receipt,opening,terminal,request,
                &retained.generation_identity,&retained.assignment,&retained.runtime_identity,
                &retained.publication_receipt.internal_envelope_sha256,&configuration,self.key_trust.as_ref(),retained.trusted_time.as_ref()),
            (_,None)=>super::policy_shadow::native_runtime::Observation::from_receipt(receipt,opening,terminal,&retained.generation_identity,
                &retained.assignment,&retained.runtime_identity,&retained.publication_receipt.internal_envelope_sha256,
                &configuration,self.key_trust.as_ref(),retained.trusted_time.as_ref()),
            _=>return Err("response observation lacks its terminal".into()),
        }.map_err(|error|error.to_string())
    }

    pub(crate) fn install(
        &self,
        state: &GateState,
        body: &[u8],
    ) -> Result<GenerationPublicationReceipt, GenerationInstallError> {
        if body.is_empty() || body.len() as u64 > MAX_INSTALL_BODY_BYTES {
            return Err(GenerationInstallError::invalid(
                "policy-shadow generation body is outside its fixed bound",
            ));
        }
        let mut request: GenerationInstallRequest =
            strict_json_from_slice(body).map_err(|_| {
                GenerationInstallError::invalid(
                    "policy-shadow generation body is not strict JSON",
                )
            })?;
        let canonical_request = canonical_json_bytes(&request).map_err(
            |error| GenerationInstallError::invalid(error.to_string()),
        )?;
        if canonical_request != body {
            return Err(GenerationInstallError::invalid(
                "policy-shadow generation request must use the exact canonical JSON profile",
            ));
        }
        let request_sha256 = Sha256Digest::compute(&canonical_request);
        let _installation = self.installation_lock.try_lock().map_err(|_| {
            GenerationInstallError::conflict(
                "policy-shadow generation installation is already in progress",
            )
        })?;
        if let Some(retained) = self
            .retained_generation
            .try_lock()
            .map_err(|_| {
                GenerationInstallError::conflict(
                    "retained policy-shadow generation is busy",
                )
            })?
            .as_ref()
            .cloned()
        {
            if retained.install_request_sha256 == request_sha256 {
                retained
                    .trusted_time
                    .now_unix_nanos()
                    .map_err(|error| {
                        GenerationInstallError::conflict(
                            error.to_string(),
                        )
                    })?;
                let exact_active = current_snapshot(state);
                if state
                    .policy_shadow
                    .recover_exact_publication(
                        &retained.generation_identity,
                        &exact_active,
                    )
                    .map_err(GenerationInstallError::conflict)?
                    .is_none()
                {
                    return Err(GenerationInstallError::conflict(
                        "exact generation replay is not currently published",
                    ));
                }
                return Ok(retained.publication_receipt.clone());
            }
        }
        let result =
            self.install_parsed(state, &mut request, request_sha256);
        result
    }

    fn install_parsed(
        &self,
        state: &GateState,
        request: &mut GenerationInstallRequest,
        request_sha256: Sha256Digest,
    ) -> Result<GenerationPublicationReceipt, GenerationInstallError> {
        if request.api_version != INSTALL_REQUEST_API_VERSION
            || !bounded_ascii_token(
                &request.request_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || !bounded_ascii_token(
                &request.replay_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || !bounded_ascii_token(
                &request.management_handoff_id,
                MAX_REPLAY_IDENTIFIER_BYTES,
            )
            || request.request_id == request.replay_id
            || request.request_id == request.management_handoff_id
            || request.replay_id == request.management_handoff_id
            || request.runtime_attestation.api_version
                != STARTUP_ATTESTATION_HANDOFF_API_VERSION
            || request.runtime_attestation.receipt_revision == 0
            || request
                    .runtime_attestation
                    .role_authorization_revision
                == 0
            || request.runtime_attestation.evidence.evidence_revision
                == 0
            || !matches!(
                request
                    .runtime_attestation
                    .evidence
                    .evidence_type
                    .as_str(),
                "trusted-host-no-tee"
                    | "aws-nitro-enclave"
                    | "amd-sev-snp"
                    | "intel-tdx"
            )
            || self.is_production
                && (request
                    .runtime_attestation
                    .evidence
                    .evidence_type
                        == "trusted-host-no-tee")
        {
            return Err(GenerationInstallError::invalid(
                "policy-shadow generation artifact type is unsupported",
            ));
        }
        let assignment_payload_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(
                request.assignment.untrusted_payload(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let load_receipt_payload_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(
                request.load_receipt.untrusted_payload(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let load_receipt_envelope_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(&request.load_receipt).map_err(
                |error| {
                    GenerationInstallError::invalid(error.to_string())
                },
            )?,
        );
        let runtime = request
            .load_receipt
            .untrusted_payload()
            .runtime_identity();
        let runtime_identity_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(runtime).map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let receipt_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(
                &request.runtime_attestation.receipt,
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let receipt_payload_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(
                request
                    .runtime_attestation
                    .receipt
                    .untrusted_payload(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let role_authorization_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(
                &request.runtime_attestation.role_authorization,
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let role_authorization_payload_sha256 =
            Sha256Digest::compute(
                &canonical_json_bytes(
                    request
                        .runtime_attestation
                        .role_authorization
                        .untrusted_payload(),
                )
                .map_err(|error| {
                    GenerationInstallError::invalid(
                        error.to_string(),
                    )
                })?,
            );
        let attestation_evidence_bytes = canonical_json_bytes(
            &request.runtime_attestation.evidence.evidence,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        let attestation_chain_sha256 =
            startup_attestation_handoff_chain_sha256(
                &request.runtime_attestation,
                &assignment_payload_sha256,
                &load_receipt_payload_sha256,
                &runtime_identity_sha256,
                &self.key_trust.runtime_attestation_policy_sha256,
            )
            .map_err(GenerationInstallError::invalid)?;
        if receipt_sha256
                != request.runtime_attestation.receipt_sha256
            || receipt_payload_sha256
                != request
                    .runtime_attestation
                    .receipt_payload_sha256
            || role_authorization_sha256
                != request
                    .runtime_attestation
                    .role_authorization_sha256
            || role_authorization_payload_sha256
                != request
                    .runtime_attestation
                    .role_authorization_payload_sha256
            || attestation_evidence_bytes.is_empty()
            || attestation_evidence_bytes.len()
                > MAX_RUNTIME_EVIDENCE_BYTES
            || Sha256Digest::compute(&attestation_evidence_bytes)
                != request
                    .runtime_attestation
                    .evidence
                    .evidence_sha256
            || attestation_chain_sha256
                != request.runtime_attestation.chain_sha256
        {
            return Err(GenerationInstallError::invalid(
                "runtime attestation signed artifact digests are not exact",
            ));
        }
        let management_handoff_sha256 = domain_digest(
            b"serverware.policyShadowGenerationManagementHandoff/v1",
            &(
                request.request_id.as_str(),
                request.replay_id.as_str(),
                request.management_handoff_id.as_str(),
                &request_sha256,
                &runtime_identity_sha256,
            ),
        )
        .map_err(GenerationInstallError::invalid)?;
        let request_binding = PublicationRequestBinding {
            request_id: request.request_id.clone(),
            replay_id: request.replay_id.clone(),
            management_handoff_id:
                request.management_handoff_id.clone(),
            management_handoff_sha256,
            request_sha256,
        };
        let expected_verifier_sha256 = Sha256Digest::parse(
            self.runtime_verifier.expected_sha256.clone(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        let verifier_request = json!({
            "apiVersion":RUNTIME_VERIFIER_REQUEST_API_VERSION,
            "operation":"verify-generation-runtime",
            "request":&request_binding,
            "assignmentPayloadSha256":assignment_payload_sha256,
            "loadReceiptPayloadSha256":load_receipt_payload_sha256,
            "runtimeIdentity":runtime,
            "runtimeIdentitySha256":runtime_identity_sha256,
            "runtimeAttestation":&request.runtime_attestation,
            "trustCheckpointSha256":self.trust_manifest_sha256,
            "attestationPolicySha256":
                self.key_trust.runtime_attestation_policy_sha256,
            "verifierExecutableSha256":expected_verifier_sha256,
        });
        let verifier_value = native::run_command(
            self.native_workers.as_ref(),
            serverware_decision_gate::native_shadow_workers::Purpose::Runtime,
            &self.runtime_verifier,
            &verifier_request,
            "policy-shadow runtime attestation verifier",
            64 * 1024,
        )
        .map_err(|error| {
            GenerationInstallError::unavailable(error)
        })?;
        let verifier_response: RuntimeAttestationVerifierResponse =
            serde_json::from_value(verifier_value).map_err(|_| {
                GenerationInstallError::invalid(
                    "runtime attestation verifier returned an unknown shape",
                )
            })?;
        let evidence_bytes =
            canonical_json_bytes(&verifier_response.evidence.evidence)
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?;
        if verifier_response.api_version
                != RUNTIME_VERIFIER_RESPONSE_API_VERSION
            || verifier_response.evidence.api_version
                != RUNTIME_EVIDENCE_API_VERSION
            || verifier_response.evidence
                != request.runtime_attestation.evidence
            || evidence_bytes.is_empty()
            || evidence_bytes.len() > MAX_RUNTIME_EVIDENCE_BYTES
            || Sha256Digest::compute(&evidence_bytes)
                != verifier_response.evidence.evidence_sha256
        {
            return Err(GenerationInstallError::invalid(
                "runtime attestation verifier did not return the exact locally obtained evidence",
            ));
        }
        let runtime_attestation_evidence =
            verifier_response.evidence;
        let verifier_envelope = verifier_response.verification;
        let verifier_trusted_time = FixedTrustedTime {
            now_unix_nanos: verifier_envelope
                .untrusted_payload()
                .trusted_now_unix_nanos,
        };
        let verified_verifier = verify_envelope(
            verifier_envelope.clone(),
            ExpectedSigner {
                key_id: &self
                    .key_trust
                    .runtime_attestation_verifier_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .runtime_attestation_verifier_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            &verifier_trusted_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "runtime attestation verifier signature is invalid: {error}"
            ))
        })?;
        let verifier_result = verified_verifier.payload().clone();
        verifier_result
            .validate(
                &self.key_trust.checkpoint,
                &assignment_payload_sha256,
                &load_receipt_payload_sha256,
                &runtime_identity_sha256,
                runtime,
                &request.runtime_attestation,
                &runtime_attestation_evidence,
                &self.key_trust.runtime_attestation_policy_sha256,
                &expected_verifier_sha256,
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error)
            })?;
        let trusted_time = Arc::new(
            AnchoredTrustedTime::from_signed_runtime_verification(
                &verifier_result,
            )
            .map_err(|error| {
                GenerationInstallError::invalid(format!(
                    "runtime attestation trusted time is invalid: {error}"
                ))
            })?,
        );
        self.key_trust
            .authorize_at(
                trusted_time.now_unix_nanos().map_err(|error| {
                    GenerationInstallError::conflict(error.to_string())
                })?,
            )
            .map_err(GenerationInstallError::conflict)?;
        let verified_startup_receipt = verify_envelope(
            request
                .runtime_attestation
                .receipt
                .clone(),
            ExpectedSigner {
                key_id: &self
                    .key_trust
                    .startup_attestation_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .startup_attestation_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            trusted_time.as_ref(),
            MAX_TRUST_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "startup runtime attestation receipt is invalid: {error}"
            ))
        })?;
        let role_authorization_signer = request
            .runtime_attestation
            .role_authorization
            .untrusted_signer();
        let verified_role_authorization = verify_envelope(
            request
                .runtime_attestation
                .role_authorization
                .clone(),
            ExpectedSigner {
                key_id: role_authorization_signer.0,
                key_spki_sha256: role_authorization_signer.1,
            },
            self.key_trust.as_ref(),
            trusted_time.as_ref(),
            MAX_TRUST_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "shadow role authorization is invalid: {error}"
            ))
        })?;
        let assignment = verify_assignment(
            request.assignment.clone(),
            ExpectedSigner {
                key_id: &self.key_trust.assignment_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .assignment_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            trusted_time.as_ref(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        verify_startup_attestation_bindings(
            &request.runtime_attestation,
            verified_startup_receipt.payload(),
            verified_role_authorization.payload(),
            &assignment,
            &load_receipt_envelope_sha256,
            &load_receipt_payload_sha256,
            runtime,
            &runtime_identity_sha256,
            &self.key_trust,
            self.is_production,
        )?;
        let runtime_attestation = VerifiedRuntimeAttestation {
            result: verifier_result.clone(),
            runtime_identity_sha256: runtime_identity_sha256.clone(),
            assignment_payload_sha256:
                assignment_payload_sha256.clone(),
            signed_verification_sha256:
                verified_verifier.envelope_sha256().clone(),
        };
        let load_receipt = verify_load_receipt(
            request.load_receipt.clone(),
            &assignment,
            &runtime_attestation,
            self.key_trust.as_ref(),
            trusted_time.as_ref(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;

        let expected_active = current_snapshot(state);
        let active_policy_bundle_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(&request.active_policy_bundle)
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?,
        );
        let candidate_policy_bundle_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(&request.candidate_policy_bundle)
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?,
        );
        let active_raw =
            std::mem::take(&mut request.active_policy_bundle);
        let candidate_raw =
            std::mem::take(&mut request.candidate_policy_bundle);
        let (active, candidate) = load_shadow_snapshot_pair(
            active_raw,
            candidate_raw,
            &state.policy_trust_root_source,
            &state.binary_digest,
            self.is_production,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error)
        })?;
        let active = bind_shadow_active_runtime_identity(
            active,
            &expected_active,
        )
        .map_err(|error| {
            GenerationInstallError::conflict(error)
        })?;
        let candidate = bind_next_active_runtime_identity(
            candidate,
            &active,
        )
        .map_err(GenerationInstallError::conflict)?;
        self.verify_compilation_contract(
            &assignment,
            &active,
            &candidate,
            &state.binary_digest,
        )?;
        self.custody_config.revalidate().map_err(|error| {
            GenerationInstallError::unavailable(error)
        })?;
        #[cfg(target_os="linux")]
        if let Some(owner)=&self.native_custody_lifecycle {
            owner.check(self.custody_config.content_sha256())
                .map_err(GenerationInstallError::unavailable)?;
        }
        let generation_identity = ShadowGenerationIdentity::derive(
            &assignment,
            &load_receipt,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        let runtime_binding = self.publication_runtime_binding(
            state,
            runtime,
            &active,
            &verifier_result,
        )?;
        let generation_binding = publication_generation_binding(
            &generation_identity,
            &active,
            &candidate,
            &active_policy_bundle_sha256,
            &candidate_policy_bundle_sha256,
        )?;
        verify_local_runtime_attestation_binding(
            &runtime_binding,
            &request.runtime_attestation,
            &verifier_result,
            &self.key_trust,
        )?;
        let trust_binding = PublicationTrustBinding {
            trust_checkpoint_sha256:
                self.trust_manifest_sha256.clone(),
            revocation_generation:
                self.key_trust.checkpoint.revocation_generation,
            revocation_root_sha256: self
                .key_trust
                .checkpoint
                .revocation_root_sha256
                .clone(),
            runtime_attestation_policy_sha256: self
                .key_trust
                .runtime_attestation_policy_sha256
                .clone(),
            runtime_attestation_verifier_signing_key_id: self
                .key_trust
                .runtime_attestation_verifier_signing_key_id
                .clone(),
            runtime_attestation_verifier_signing_key_spki_sha256: self
                .key_trust
                .runtime_attestation_verifier_signing_key_spki_sha256
                .clone(),
            publication_signing_key_id: self
                .key_trust
                .publication_signing_key_id
                .clone(),
            publication_signing_key_spki_sha256: self
                .key_trust
                .publication_signing_key_spki_sha256
                .clone(),
            publication_replay_store_sha256: self
                .key_trust
                .publication_replay_store_sha256
                .clone(),
            replay_store_revision:
                generation_identity.assignment_revision(),
        };
        let attestation_chain = PublicationAttestationChain {
            startup_attestation:
                request.runtime_attestation.clone(),
            runtime_attestation_verification:
                verifier_envelope.clone(),
            runtime_attestation_verification_envelope_sha256:
                verified_verifier.envelope_sha256().clone(),
            attestation_mode:
                verifier_result.attestation_mode.clone(),
            hardware_attested:
                verifier_result.hardware_attested,
        };
        let (_, assignment_ends_at_unix_nanos) =
            generation_identity.assignment_window_unix_nanos();
        let issued_at_unix_nanos =
            verifier_result.trusted_now_unix_nanos;
        let expires_at_unix_nanos = [
            assignment_ends_at_unix_nanos,
            verifier_result.expires_at_unix_nanos,
            self.key_trust.expires_at_unix_nanos,
            issued_at_unix_nanos
                .checked_add(
                    MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
                )
                .ok_or_else(|| {
                    GenerationInstallError::invalid(
                        "publication receipt expiry overflow",
                    )
                })?,
        ]
        .into_iter()
        .min()
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "publication receipt expiry is unavailable",
            )
        })?;
        let proposed_preparation =
            GenerationPublicationPreparationPayload {
                schema_version:
                    PUBLICATION_PREPARATION_API_VERSION.to_string(),
                signature_domain:
                    PUBLICATION_PREPARATION_SIGNATURE_DOMAIN.to_string(),
                signature_algorithm:
                    SIGNATURE_ALGORITHM.to_string(),
                canonicalization_profile:
                    CANONICAL_PROFILE.to_string(),
                status: "prepared".to_string(),
                request: request_binding.clone(),
                generation: generation_binding.clone(),
                runtime: runtime_binding.clone(),
                trust: trust_binding.clone(),
                attestation_chain: attestation_chain.clone(),
                durable_reservation_receipt_sha256:
                    publication_reservation_receipt_sha256(
                        &request_binding,
                        &generation_binding,
                        &trust_binding,
                    )
                    .map_err(|error| {
                        GenerationInstallError::invalid(
                            error.to_string(),
                        )
                    })?,
                not_before_unix_nanos: issued_at_unix_nanos,
                issued_at_unix_nanos,
                expires_at_unix_nanos,
            };
        proposed_preparation
            .validate_intrinsic()
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let handoff = self.publication_handoff_request(
            "prepare-or-recover",
            json!({
                "proposedPreparation":proposed_preparation,
            }),
        )?;
        if handoff.status == "completed" {
            return Err(GenerationInstallError::conflict(
                "durable publication exists without the exact in-process retained generation context",
            ));
        }
        if handoff.status != "prepared"
            || handoff.publication.is_some()
            || handoff.internal_publication.is_some()
        {
            return Err(GenerationInstallError::conflict(
                "publication handoff rejected or conflicted with the replay identity",
            ));
        }
        let preparation = handoff.preparation.ok_or_else(|| {
            GenerationInstallError::invalid(
                "publication handoff omitted its signed preparation",
            )
        })?;
        let preparation_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(&preparation).map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let prepared = self.verify_publication_preparation(
            preparation,
            &request_binding,
            &generation_binding,
            &runtime_binding,
            &trust_binding,
            runtime,
            &assignment_payload_sha256,
            &load_receipt_payload_sha256,
            &runtime_identity_sha256,
            trusted_time.as_ref(),
        )?;

        let _active_policy_mutation =
            state.upstream_dispatch_authority.begin_mutation();
        let exact_active = current_snapshot(state);
        if !policy_trust_is_fresh(state)
            || !same_exact_snapshot_identity(&exact_active, &active)
        {
            return Err(GenerationInstallError::conflict(
                "active policy changed before shadow publication",
            ));
        }

        let active = Arc::new(active);
        let candidate = Arc::new(candidate);
        let recovered_publication = state
            .policy_shadow
            .recover_exact_publication(
                &generation_identity,
                &exact_active,
            )
            .map_err(GenerationInstallError::conflict)?;
        #[cfg(target_os = "linux")]
        let (publication, generation, custody) =
            if let Some(recovered) = recovered_publication {
                let custody = self
                    .installed_custody
                    .try_lock()
                    .map_err(|_| {
                        GenerationInstallError::conflict(
                            "retained policy-shadow custody is busy",
                        )
                    })?
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| {
                        GenerationInstallError::unavailable(
                            "recovered generation omits its retained custody supervisor",
                        )
                    })?;
                let custody: Arc<
                    dyn PolicyShadowCustodyRpcSupervisor,
                > = custody;
                (recovered.0, recovered.1, custody)
            } else {
                let custody = {
                    let mut retained = self
                        .installed_custody
                        .try_lock()
                        .map_err(|_| {
                            GenerationInstallError::conflict(
                                "policy-shadow custody generation installation is already in progress",
                            )
                        })?;
                    let key_trust: Arc<
                        dyn EnvelopeKeyTrust + Send + Sync,
                    > = self.key_trust.clone();
                    let trusted_time_authority: Arc<
                        dyn TrustedTime + Send + Sync,
                    > = trusted_time.clone();
                    let installed = if let Some(owner)=&self.native_custody_lifecycle {
                        install_native_custody_generation_from_retained_owner(Arc::clone(owner),
                            self.custody_config.content_sha256().clone(),assignment.clone(),key_trust,trusted_time_authority)
                    }else{
                        install_policy_shadow_custody_generation_from_retained_file(
                            self.custody_config
                                .retained_file()
                                .map_err(GenerationInstallError::unavailable)?,
                            self.custody_config.content_sha256().clone(),
                            assignment.clone(),
                            key_trust,
                            trusted_time_authority,
                        )}
                        .map_err(|error| {
                            GenerationInstallError::unavailable(
                                error.to_string(),
                            )
                        })?;
                    if let Some(current) = retained.as_ref() {
                        if !Arc::ptr_eq(current, &installed) {
                            return Err(
                                GenerationInstallError::unavailable(
                                    "custody generation install replaced the runtime supervisor",
                                ),
                            );
                        }
                    } else {
                        *retained = Some(Arc::clone(&installed));
                    }
                    installed
                };
                let custody: Arc<
                    dyn PolicyShadowCustodyRpcSupervisor,
                > = custody;
                let installed = match state.policy_shadow.install_verified_artifacts(
                    &assignment,
                    &load_receipt,
                    &active,
                    &candidate,
                    Arc::clone(&custody),
                ) {
                    Ok(installed) => installed,
                    Err(error) => {
                        state
                            .policy_shadow
                            .quarantine_for_cleanup_failure();
                        return Err(GenerationInstallError::conflict(
                            error,
                        ));
                    }
                };
                (installed.0, installed.1, custody)
            };
        #[cfg(not(target_os = "linux"))]
        return Err(GenerationInstallError::unavailable(
            "policy-shadow custody installation requires Linux",
        ));

        #[cfg(target_os = "linux")]
        {
            if generation != generation_identity
                || !publication.authorizes(&exact_active)
                || publication.publication_revision()
                    != generation.signed_publication_revision()
            {
                state.policy_shadow.quarantine_for_cleanup_failure();
                return Err(GenerationInstallError::unavailable(
                    "published generation does not authorize the exact signed policy and revision",
                ));
            }
            let custody_binding = PublicationCustodyBinding {
                custody_configuration_sha256:
                    self.custody_config.content_sha256().clone(),
                preparation_receipt_sha256: Sha256Digest::parse(
                    publication.custody_receipt_sha256().to_string(),
                )
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?,
                publication_receipt_sha256: Sha256Digest::parse(
                    publication
                        .publication_receipt_sha256()
                        .to_string(),
                )
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?,
                publication_revision:
                    publication.publication_revision(),
                publication_reconciliation_receipt_sha256: generation
                    .publication_reconciliation_receipt_sha256()
                    .clone(),
                authoritative_ledger_event_ordinal: generation
                    .authoritative_ledger_event_ordinal(),
                authoritative_ledger_head_sha256: generation
                    .authoritative_ledger_head_sha256()
                    .clone(),
                authoritative_spool_root_sha256: generation
                    .authoritative_spool_root_sha256()
                    .clone(),
            };
            let durable_commit_receipt_sha256 =
                publication_commit_receipt_sha256(
                    &prepared.request,
                    &preparation_sha256,
                    &prepared.generation,
                    &custody_binding,
                    &prepared.trust,
                )
                .map_err(|error| {
                    GenerationInstallError::invalid(
                        error.to_string(),
                    )
                })?;
            let mut publication_payload = GenerationPublicationPayload {
                schema_version:
                    INSTALL_RECEIPT_API_VERSION.to_string(),
                signature_domain:
                    PUBLICATION_SIGNATURE_DOMAIN.to_string(),
                signature_algorithm:
                    SIGNATURE_ALGORITHM.to_string(),
                canonicalization_profile:
                    CANONICAL_PROFILE.to_string(),
                status: "published".to_string(),
                request: prepared.request.clone(),
                preparation_envelope_sha256:
                    preparation_sha256,
                generation: prepared.generation.clone(),
                custody: custody_binding.clone(),
                runtime: prepared.runtime.clone(),
                trust: prepared.trust.clone(),
                attestation_chain:
                    prepared.attestation_chain.clone(),
                external_record_sha256:
                    Sha256Digest::compute(
                        b"unbound-external-publication-record",
                    ),
                durable_commit_receipt_sha256,
                not_before_unix_nanos:
                    prepared.not_before_unix_nanos,
                issued_at_unix_nanos:
                    prepared.issued_at_unix_nanos,
                expires_at_unix_nanos:
                    prepared.expires_at_unix_nanos,
            };
            let provisional_external_record =
                generation_publication_external_record(
                    &request_binding,
                    &request.runtime_attestation,
                    &publication_payload,
                    &active_policy_bundle_sha256,
                    &candidate_policy_bundle_sha256,
                )?;
            publication_payload.external_record_sha256 =
                external_record_projection_sha256(
                    &provisional_external_record,
                )?;
            publication_payload
                .validate_intrinsic()
                .map_err(|error| {
                    GenerationInstallError::invalid(
                        error.to_string(),
                    )
                })?;
            let external_record =
                generation_publication_external_record(
                    &request_binding,
                    &request.runtime_attestation,
                    &publication_payload,
                    &active_policy_bundle_sha256,
                    &candidate_policy_bundle_sha256,
                )?;
            let external_publication_payload =
                GenerationPublicationExternalPayload {
                    issued_at_epoch_ns:
                        prepared.issued_at_unix_nanos,
                    expires_at_epoch_ns:
                        prepared.expires_at_unix_nanos,
                    record: external_record,
                };
            external_publication_payload
                .validate_intrinsic()
                .map_err(|error| {
                    GenerationInstallError::invalid(
                        error.to_string(),
                    )
                })?;
            let expected_publication_payload =
                publication_payload.clone();
            let expected_external_publication_payload =
                external_publication_payload.clone();
            let handoff = self.publication_handoff_request(
                "commit",
                json!({
                    "preparationEnvelopeSha256":
                        publication_payload.preparation_envelope_sha256,
                    "internalPublicationPayload":publication_payload,
                    "publicationPayload":external_publication_payload,
                }),
            )?;
            if handoff.status != "completed"
                || handoff.preparation.is_some()
            {
                state.policy_shadow.quarantine_for_cleanup_failure();
                return Err(GenerationInstallError::unavailable(
                    "publication handoff did not durably commit one signed envelope",
                ));
            }
            let internal_envelope =
                handoff.internal_publication.ok_or_else(|| {
                    GenerationInstallError::invalid(
                        "publication handoff omitted its signed internal publication",
                    )
                })?;
            let envelope = handoff.publication.ok_or_else(|| {
                GenerationInstallError::invalid(
                    "publication handoff omitted its signed publication",
                )
            })?;
            if internal_envelope.untrusted_payload()
                != &expected_publication_payload
                || envelope.untrusted_payload()
                    != &expected_external_publication_payload
            {
                state.policy_shadow.quarantine_for_cleanup_failure();
                return Err(GenerationInstallError::unavailable(
                    "publication handoff signed a divergent publication payload",
                ));
            }
            let receipt = self.verify_completed_publication(
                internal_envelope,
                envelope,
                &request_binding,
                &generation_binding,
                &runtime_binding,
                &trust_binding,
                trusted_time.as_ref(),
            )?;
            self.retain_generation_activation_context(
                request_binding.request_sha256.clone(),
                assignment,
                load_receipt,
                request.runtime_attestation.clone(),
                verifier_envelope,
                runtime_attestation,
                trusted_time,
                custody,
                generation,
                runtime.clone(),
                receipt.clone(),
            )?;
            Ok(receipt)
        }
    }

    fn publication_handoff_request(
        &self,
        operation: &str,
        body: Value,
    ) -> Result<PublicationHandoffResponse, GenerationInstallError> {
        let request = json!({
            "apiVersion":PUBLICATION_HANDOFF_API_VERSION,
            "operation":operation,
            "shadowRoleSigningKeyId":
                self.key_trust.publication_signing_key_id,
            "shadowRoleSigningKeySpkiSha256":
                self.key_trust.publication_signing_key_spki_sha256,
            "durableReplayStoreSha256":
                self.key_trust.publication_replay_store_sha256,
            "body":body,
        });
        let value =
            native::run_command(
                self.native_workers.as_ref(),
                serverware_decision_gate::native_shadow_workers::Purpose::Publication,
                &self.publication_handoff,
                &request,
                "policy-shadow publication handoff",
                MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES,
            )
            .map_err(GenerationInstallError::unavailable)?;
        let response: PublicationHandoffResponse =
            serde_json::from_value(value).map_err(|_| {
                GenerationInstallError::invalid(
                    "publication handoff returned an unknown shape",
                )
            })?;
        if response.api_version != PUBLICATION_HANDOFF_API_VERSION
            || response.operation != operation
            || !matches!(
                response.status.as_str(),
                "prepared" | "completed" | "conflict"
            )
        {
            return Err(GenerationInstallError::invalid(
                "publication handoff response metadata is invalid",
            ));
        }
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn retain_generation_activation_context(
        &self,
        install_request_sha256: Sha256Digest,
        assignment: VerifiedAssignment,
        load_receipt: VerifiedLoadReceipt,
        startup_attestation: RuntimeAttestationHandoff,
        runtime_attestation_verification:
            SignedEnvelope<RuntimeAttestationVerificationResult>,
        runtime_attestation: VerifiedRuntimeAttestation,
        trusted_time: Arc<AnchoredTrustedTime>,
        custody: Arc<dyn PolicyShadowCustodyRpcSupervisor>,
        generation_identity: ShadowGenerationIdentity,
        runtime_identity: RuntimeIdentity,
        publication_receipt: GenerationPublicationReceipt,
    ) -> Result<(), GenerationInstallError> {
        trusted_time.now_unix_nanos().map_err(|error| {
            GenerationInstallError::conflict(error.to_string())
        })?;
        if generation_identity.assignment_sha256()
                != assignment.envelope_sha256()
            || generation_identity.assignment_payload_sha256()
                != assignment.payload_sha256()
            || generation_identity.load_receipt_sha256()
                != load_receipt.envelope_sha256()
            || generation_identity.load_receipt_payload_sha256()
                != load_receipt.payload_sha256()
            || generation_identity.runtime_boot_id_sha256()
                != runtime_identity.boot_id_sha256()
            || publication_receipt
                .internal_envelope
                .untrusted_payload()
                .generation
                .generation_id
                != *generation_identity.generation_id()
        {
            return Err(GenerationInstallError::conflict(
                "retained activation context diverges from the published generation",
            ));
        }
        let retained = Arc::new(RetainedGenerationActivationContext {
            install_request_sha256,
            assignment,
            load_receipt,
            startup_attestation,
            runtime_attestation_verification,
            runtime_attestation,
            trusted_time,
            custody,
            generation_identity,
            runtime_identity,
            publication_receipt,
            activation: Mutex::new(None),
        });
        let mut slot = self.retained_generation.try_lock().map_err(|_| {
            GenerationInstallError::conflict(
                "retained policy-shadow generation is busy",
            )
        })?;
        if let Some(current) = slot.as_ref() {
            if current.generation_identity == retained.generation_identity {
                if current.install_request_sha256
                    != retained.install_request_sha256
                {
                    return Err(GenerationInstallError::conflict(
                        "the published generation was replayed with different canonical bytes",
                    ));
                }
                return Ok(());
            }
            if retained.generation_identity.generation_epoch()
                <= current.generation_identity.generation_epoch()
                || retained.generation_identity.assignment_revision()
                    <= current.generation_identity.assignment_revision()
            {
                return Err(GenerationInstallError::conflict(
                    "retained policy-shadow generation replacement regressed",
                ));
            }
        }
        *slot = Some(retained);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_publication_preparation(
        &self,
        envelope:
            SignedEnvelope<GenerationPublicationPreparationPayload>,
        request: &PublicationRequestBinding,
        generation: &PublicationGenerationBinding,
        runtime_binding: &PublicationRuntimeBinding,
        trust: &PublicationTrustBinding,
        runtime: &RuntimeIdentity,
        assignment_payload_sha256: &Sha256Digest,
        load_receipt_payload_sha256: &Sha256Digest,
        runtime_identity_sha256: &Sha256Digest,
        trusted_time: &dyn TrustedTime,
    ) -> Result<
        GenerationPublicationPreparationPayload,
        GenerationInstallError,
    > {
        let verified = verify_envelope(
            envelope,
            ExpectedSigner {
                key_id: &self.key_trust.publication_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .publication_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            trusted_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "publication preparation signature is invalid: {error}"
            ))
        })?;
        let payload = verified.payload();
        if payload.request != *request
            || payload.generation != *generation
            || payload.runtime != *runtime_binding
            || payload.trust != *trust
        {
            return Err(GenerationInstallError::conflict(
                "publication preparation conflicts with the exact request or runtime",
            ));
        }
        self.verify_attestation_chain(
            &payload.attestation_chain,
            runtime,
            assignment_payload_sha256,
            load_receipt_payload_sha256,
            runtime_identity_sha256,
        )?;
        Ok(payload.clone())
    }

    fn verify_completed_publication(
        &self,
        internal_envelope: SignedEnvelope<GenerationPublicationPayload>,
        envelope: SignedEnvelope<GenerationPublicationExternalPayload>,
        request: &PublicationRequestBinding,
        generation: &PublicationGenerationBinding,
        runtime_binding: &PublicationRuntimeBinding,
        trust: &PublicationTrustBinding,
        trusted_time: &dyn TrustedTime,
    ) -> Result<GenerationPublicationReceipt, GenerationInstallError> {
        let canonical_internal_envelope =
            canonical_json_bytes(&internal_envelope).map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let canonical_envelope =
            canonical_json_bytes(&envelope).map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        if canonical_internal_envelope.is_empty()
            || canonical_internal_envelope.len()
                > MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES
            || canonical_envelope.is_empty()
            || canonical_envelope.len()
                > MAX_PUBLICATION_HANDOFF_OUTPUT_BYTES
        {
            return Err(GenerationInstallError::invalid(
                "signed publication envelope is outside its fixed bound",
            ));
        }
        let verified_internal = verify_envelope(
            internal_envelope,
            ExpectedSigner {
                key_id: &self.key_trust.publication_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .publication_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            trusted_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "publication envelope signature is invalid: {error}"
            ))
        })?;
        let payload = verified_internal.payload();
        if payload.request != *request
            || payload.generation != *generation
            || payload.runtime != *runtime_binding
            || payload.trust != *trust
            || payload.custody.publication_revision
                != payload.generation.signed_publication_revision
        {
            return Err(GenerationInstallError::conflict(
                "signed publication conflicts with the exact request, generation, or high-water revision",
            ));
        }
        self.verify_embedded_attestation_chain(
            &payload.attestation_chain,
            &payload.runtime,
            &payload.generation,
        )?;
        let verified_external = verify_envelope(
            envelope.clone(),
            ExpectedSigner {
                key_id: &self.key_trust.publication_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .publication_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            trusted_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "external publication envelope signature is invalid: {error}"
            ))
        })?;
        let external = verified_external.payload();
        if external.record.generation_evidence != *payload
            || external.issued_at_epoch_ns
                != payload.issued_at_unix_nanos
            || external.expires_at_epoch_ns
                != payload.expires_at_unix_nanos
        {
            return Err(GenerationInstallError::conflict(
                "external publication record diverges from the signed internal evidence",
            ));
        }
        verify_external_publication_record(
            &external.record,
            payload,
        )?;
        Ok(GenerationPublicationReceipt {
            envelope,
            internal_envelope: verified_internal.wire().clone(),
            internal_envelope_sha256:
                verified_internal.envelope_sha256().clone(),
            canonical_envelope,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_attestation_chain(
        &self,
        chain: &PublicationAttestationChain,
        runtime: &RuntimeIdentity,
        assignment_payload_sha256: &Sha256Digest,
        load_receipt_payload_sha256: &Sha256Digest,
        runtime_identity_sha256: &Sha256Digest,
    ) -> Result<(), GenerationInstallError> {
        self.verify_embedded_attestation_chain_values(
            chain,
            assignment_payload_sha256,
            load_receipt_payload_sha256,
            runtime_identity_sha256,
            Some(runtime),
        )
    }

    fn verify_embedded_attestation_chain(
        &self,
        chain: &PublicationAttestationChain,
        runtime: &PublicationRuntimeBinding,
        generation: &PublicationGenerationBinding,
    ) -> Result<(), GenerationInstallError> {
        self.verify_embedded_attestation_chain_values(
            chain,
            &generation.assignment_payload_sha256,
            &generation.load_receipt_payload_sha256,
            &runtime.runtime_identity_sha256,
            None,
        )
    }

    fn verify_embedded_attestation_chain_values(
        &self,
        chain: &PublicationAttestationChain,
        assignment_payload_sha256: &Sha256Digest,
        load_receipt_payload_sha256: &Sha256Digest,
        runtime_identity_sha256: &Sha256Digest,
        runtime: Option<&RuntimeIdentity>,
    ) -> Result<(), GenerationInstallError> {
        let signed_time = FixedTrustedTime {
            now_unix_nanos: chain
                .runtime_attestation_verification
                .untrusted_payload()
                .trusted_now_unix_nanos,
        };
        let verified = verify_envelope(
            chain.runtime_attestation_verification.clone(),
            ExpectedSigner {
                key_id: &self
                    .key_trust
                    .runtime_attestation_verifier_signing_key_id,
                key_spki_sha256: &self
                    .key_trust
                    .runtime_attestation_verifier_signing_key_spki_sha256,
            },
            self.key_trust.as_ref(),
            &signed_time,
            MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(format!(
                "embedded runtime attestation signature is invalid: {error}"
            ))
        })?;
        let result = verified.payload();
        let evidence_chain_sha256 =
            startup_attestation_handoff_chain_sha256(
                &chain.startup_attestation,
                assignment_payload_sha256,
                load_receipt_payload_sha256,
                runtime_identity_sha256,
                &self.key_trust.runtime_attestation_policy_sha256,
            )
            .map_err(GenerationInstallError::invalid)?;
        let runtime_exact = runtime.is_none_or(|runtime| {
            result.tee_evidence_sha256
                    == *runtime.tee_evidence_sha256()
                && result.attestation_mode
                    == runtime.tee_platform_label()
        });
        if verified.envelope_sha256()
                != &chain
                    .runtime_attestation_verification_envelope_sha256
            || result.assignment_payload_sha256
                != *assignment_payload_sha256
            || result.load_receipt_payload_sha256
                != *load_receipt_payload_sha256
            || result.runtime_identity_sha256
                != *runtime_identity_sha256
            || result.attestation_policy_sha256
                != self.key_trust.runtime_attestation_policy_sha256
            || result.trust_checkpoint_sha256
                != self.key_trust.checkpoint.checkpoint_id
            || result.revocation_generation
                != self.key_trust.checkpoint.revocation_generation
            || result.revocation_root_sha256
                != self.key_trust.checkpoint.revocation_root_sha256
            || result.evidence_chain_sha256
                != evidence_chain_sha256
            || result.tee_evidence_sha256
                != chain
                    .startup_attestation
                    .evidence
                    .evidence_sha256
            || result.runtime_attestation_receipt_sha256
                != chain.startup_attestation.receipt_sha256
            || result.runtime_attestation_payload_sha256
                != chain.startup_attestation.receipt_payload_sha256
            || result.role_authorization_sha256
                != chain
                    .startup_attestation
                    .role_authorization_sha256
            || result.role_authorization_payload_sha256
                != chain
                    .startup_attestation
                    .role_authorization_payload_sha256
            || result.attestation_evidence_id
                != chain
                    .startup_attestation
                    .evidence
                    .evidence_id
            || result.attestation_evidence_revision
                != chain
                    .startup_attestation
                    .evidence
                    .evidence_revision
            || result.attestation_mode != chain.attestation_mode
            || result.hardware_attested != chain.hardware_attested
            || !runtime_exact
        {
            return Err(GenerationInstallError::invalid(
                "embedded runtime attestation chain is not exact",
            ));
        }
        verify_embedded_startup_attestation_signatures(
            &chain.startup_attestation,
            self.key_trust.as_ref(),
            &signed_time,
        )?;
        self.key_trust
            .authorize_at(result.trusted_now_unix_nanos)
            .map_err(GenerationInstallError::conflict)
    }

    fn publication_runtime_binding(
        &self,
        state: &GateState,
        runtime: &RuntimeIdentity,
        active: &Snapshot,
        verifier_result: &RuntimeAttestationVerificationResult,
    ) -> Result<PublicationRuntimeBinding, GenerationInstallError> {
        let runtime_instance_id =
            runtime.instance_id().as_str().to_string();
        if state.server_instance_id.as_deref()
            != Some(runtime_instance_id.as_str())
        {
            return Err(GenerationInstallError::conflict(
                "runtime instance does not match the startup-pinned decision-gate instance",
            ));
        }
        let decision_gate_executable_sha256 = Sha256Digest::parse(
            state.binary_digest.clone(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        let release_provenance_sha256 =
            required_runtime_release_digest(
                super::release_provenance_digest(
                    &state.release_provenance_path,
                ),
                "release provenance",
            )?;
        let image_signatures_sha256 =
            required_runtime_release_digest(
                super::image_signatures_digest(
                    &state.image_signatures_path,
                ),
                "image signatures",
            )?;
        let active_policy_signing_key_id = Sha256Digest::parse(
            active.policy_signing_key_id.clone(),
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
        let runtime_identity_sha256 = Sha256Digest::compute(
            &canonical_json_bytes(runtime).map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
        );
        let runtime_attestation_verifier_executable_sha256 =
            Sha256Digest::parse(
                self.runtime_verifier.expected_sha256.clone(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let publication_handoff_executable_sha256 =
            Sha256Digest::parse(
                self.publication_handoff.expected_sha256.clone(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let measurement = domain_digest(
            b"serverware.policyShadowDecisionGateRuntimeMeasurement/v1",
            &(
                &decision_gate_executable_sha256,
                &release_provenance_sha256,
                &image_signatures_sha256,
                &self.trust_manifest_sha256,
                self.custody_config.content_sha256(),
                &runtime_identity_sha256,
                &active_policy_signing_key_id,
                &runtime_attestation_verifier_executable_sha256,
                &publication_handoff_executable_sha256,
                active.policy_sequence,
                active.rollback_epoch,
                active.trust_generation,
                &self.key_trust.compiler.policy_compiler_binary_sha256,
                &self
                    .key_trust
                    .compiler
                    .policy_compiler_configuration_sha256,
            ),
        )
        .map_err(GenerationInstallError::invalid)?;
        Ok(PublicationRuntimeBinding {
            decision_gate_executable_sha256,
            decision_gate_runtime_measurement_sha256: measurement,
            release_provenance_sha256,
            runtime_configuration_sha256:
                verifier_result.runtime_config_sha256.clone(),
            runtime_policy_sha256:
                verifier_result.runtime_policy_sha256.clone(),
            image_signatures_sha256,
            generation_trust_manifest_sha256:
                self.trust_manifest_sha256.clone(),
            policy_compiler_binary_sha256: self
                .key_trust
                .compiler
                .policy_compiler_binary_sha256
                .clone(),
            policy_compiler_configuration_sha256: self
                .key_trust
                .compiler
                .policy_compiler_configuration_sha256
                .clone(),
            policy_schema_sha256:
                self.key_trust.compiler.policy_schema_sha256.clone(),
            adapter_schema_sha256:
                self.key_trust.compiler.adapter_schema_sha256.clone(),
            policy_semantic_model_sha256: self
                .key_trust
                .compiler
                .policy_semantic_model_sha256
                .clone(),
            policy_plan_schema_sha256: self
                .key_trust
                .compiler
                .policy_plan_schema_sha256
                .clone(),
            request_facts_schema_sha256: self
                .key_trust
                .compiler
                .request_facts_schema_sha256
                .clone(),
            runtime_attestation_verifier_executable_sha256,
            publication_handoff_executable_sha256,
            active_policy_signing_key_id,
            runtime_instance_id,
            runtime_identity_sha256,
            runtime_boot_id_sha256:
                runtime.boot_id_sha256().clone(),
            runtime_tee_measurement_sha256:
                runtime.tee_measurement_sha256().clone(),
        })
    }

    fn verify_compilation_contract(
        &self,
        assignment: &super::policy_shadow::VerifiedAssignment,
        active: &Snapshot,
        candidate: &Snapshot,
        running_binary_digest: &str,
    ) -> Result<(), GenerationInstallError> {
        let compiler = &self.key_trust.compiler;
        let active_policy_sha256 =
            Sha256Digest::parse(active.hash.clone())
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?;
        let candidate_policy_sha256 =
            Sha256Digest::parse(candidate.hash.clone())
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?;
        let active_compiled_behavior_sha256 =
            Sha256Digest::parse(
                active.compiled_behavior_sha256.clone(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let candidate_compiled_behavior_sha256 =
            Sha256Digest::parse(
                candidate.compiled_behavior_sha256.clone(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?;
        let decision_gate_binary_sha256 =
            Sha256Digest::parse(running_binary_digest.to_string())
                .map_err(|error| {
                    GenerationInstallError::invalid(error.to_string())
                })?;
        let policy_bundle_sha256 = policy_pair_bundle_sha256(
            &active_policy_sha256,
            active.policy_sequence,
            active.rollback_epoch,
            &candidate_policy_sha256,
            candidate.policy_sequence,
            candidate.rollback_epoch,
            compiler,
        )
        .map_err(|error| {
            GenerationInstallError::invalid(error)
        })?;
        let active_compiled_snapshot_sha256 =
            compiled_snapshot_sha256(
                "active",
                &active_policy_sha256,
                active.policy_sequence,
                active.rollback_epoch,
                &policy_bundle_sha256,
                &active_compiled_behavior_sha256,
                compiler,
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error)
            })?;
        let candidate_compiled_snapshot_sha256 =
            compiled_snapshot_sha256(
                "candidate",
                &candidate_policy_sha256,
                candidate.policy_sequence,
                candidate.rollback_epoch,
                &policy_bundle_sha256,
                &candidate_compiled_behavior_sha256,
                compiler,
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error)
            })?;
        let payload = assignment.payload();
        if !payload.policy_identity().matches_runtime_compiler_contract(
            &policy_bundle_sha256,
            &compiler.policy_compiler_binary_sha256,
            &compiler.policy_compiler_configuration_sha256,
            &compiler.policy_schema_sha256,
            &compiler.policy_semantic_model_sha256,
            &decision_gate_binary_sha256,
        ) || !payload.expected_loaded_snapshots().matches_runtime_compilation(
            &active_policy_sha256,
            active.policy_sequence,
            active.rollback_epoch,
            &active_compiled_snapshot_sha256,
            &candidate_policy_sha256,
            candidate.policy_sequence,
            candidate.rollback_epoch,
            &candidate_compiled_snapshot_sha256,
            &compiler.policy_compiler_binary_sha256,
            &compiler.policy_compiler_configuration_sha256,
            &compiler.policy_schema_sha256,
            &compiler.adapter_schema_sha256,
            &compiler.policy_semantic_model_sha256,
            &compiler.policy_plan_schema_sha256,
            &compiler.request_facts_schema_sha256,
        ) {
            return Err(GenerationInstallError::invalid(
                "signed policy-shadow compiler identity does not match the local exact compilation",
            ));
        }
        Ok(())
    }
}

fn policy_pair_bundle_sha256(
    active_policy_sha256: &Sha256Digest,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    candidate_policy_sha256: &Sha256Digest,
    candidate_policy_sequence: u64,
    candidate_rollback_epoch: u64,
    compiler: &CompilerTrustManifest,
) -> Result<Sha256Digest, String> {
    domain_digest(
        b"serverware.policyShadowPolicyPairBundle/v1",
        &(
            active_policy_sha256,
            active_policy_sequence,
            active_rollback_epoch,
            candidate_policy_sha256,
            candidate_policy_sequence,
            candidate_rollback_epoch,
            &compiler.policy_compiler_binary_sha256,
            &compiler.policy_compiler_configuration_sha256,
            &compiler.policy_schema_sha256,
            &compiler.adapter_schema_sha256,
            &compiler.policy_semantic_model_sha256,
            &compiler.policy_plan_schema_sha256,
            &compiler.request_facts_schema_sha256,
        ),
    )
}

fn compiled_snapshot_sha256(
    lane: &str,
    policy_sha256: &Sha256Digest,
    policy_sequence: u64,
    rollback_epoch: u64,
    policy_bundle_sha256: &Sha256Digest,
    compiled_behavior_sha256: &Sha256Digest,
    compiler: &CompilerTrustManifest,
) -> Result<Sha256Digest, String> {
    domain_digest(
        b"serverware.policyShadowCompiledSnapshot/v1",
        &(
            lane,
            policy_sha256,
            policy_sequence,
            rollback_epoch,
            policy_bundle_sha256,
            compiled_behavior_sha256,
            &compiler.policy_compiler_binary_sha256,
            &compiler.policy_compiler_configuration_sha256,
            &compiler.policy_schema_sha256,
            &compiler.adapter_schema_sha256,
            &compiler.policy_semantic_model_sha256,
            &compiler.policy_plan_schema_sha256,
            &compiler.request_facts_schema_sha256,
        ),
    )
}

fn startup_attestation_handoff_chain_sha256(
    handoff: &RuntimeAttestationHandoff,
    assignment_payload_sha256: &Sha256Digest,
    load_receipt_payload_sha256: &Sha256Digest,
    runtime_identity_sha256: &Sha256Digest,
    attestation_policy_sha256: &Sha256Digest,
) -> Result<Sha256Digest, String> {
    domain_digest(
        b"serverware.policyShadowRuntimeAttestationEvidenceChain/v1",
        &(
            STARTUP_ATTESTATION_HANDOFF_API_VERSION,
            &handoff.receipt_id,
            handoff.receipt_revision,
            &handoff.receipt_sha256,
            &handoff.receipt_payload_sha256,
            &handoff.role_authorization_id,
            handoff.role_authorization_revision,
            &handoff.role_authorization_sha256,
            &handoff.role_authorization_payload_sha256,
            &handoff.evidence,
            assignment_payload_sha256,
            load_receipt_payload_sha256,
            runtime_identity_sha256,
            attestation_policy_sha256,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_startup_attestation_bindings(
    handoff: &RuntimeAttestationHandoff,
    receipt: &StartupRuntimeAttestationReceiptPayload,
    role_payload: &ShadowRoleAuthorizationPayload,
    assignment: &super::policy_shadow::VerifiedAssignment,
    load_receipt_sha256: &Sha256Digest,
    load_receipt_payload_sha256: &Sha256Digest,
    runtime: &RuntimeIdentity,
    runtime_identity_sha256: &Sha256Digest,
    trust: &PinnedEnvelopeKeyTrust,
    is_production: bool,
) -> Result<(), GenerationInstallError> {
    let assignment_payload = assignment.payload();
    let fleet = assignment_payload.fleet();
    let role = &role_payload.record;
    let assigned_member = fleet
        .members()
        .iter()
        .enumerate()
        .find(|(_, member)| {
            member.instance_id().as_str()
                == runtime.instance_id().as_str()
        })
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "runtime attestation is not for an assigned fleet member",
            )
        })?;
    let member_ordinal = u64::try_from(assigned_member.0)
        .ok()
        .and_then(|ordinal| ordinal.checked_add(1))
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "assigned member ordinal is not representable",
            )
        })?;
    let member_id = domain_digest(
        b"serverware.policyShadowFleetMember/v1",
        assigned_member.1,
    )
    .map_err(GenerationInstallError::invalid)?;
    let expected_chain_sha256 =
        startup_attestation_handoff_chain_sha256(
            handoff,
            assignment.payload_sha256(),
            load_receipt_payload_sha256,
            runtime_identity_sha256,
            &trust.runtime_attestation_policy_sha256,
        )
        .map_err(GenerationInstallError::invalid)?;
    let hardware_attested =
        handoff.evidence.evidence_type != "trusted-host-no-tee";
    if handoff.receipt_id
            != role.runtime_attestation_receipt_id
        || handoff.receipt_revision
            != role.runtime_attestation_receipt_revision
        || handoff.receipt_sha256
            != role.runtime_attestation_receipt_sha256
        || handoff.receipt_payload_sha256
            != role.runtime_attestation_payload_sha256
        || handoff.role_authorization_id != role.authorization_id
        || handoff.role_authorization_revision
            != role.authorization_revision
        || handoff.evidence.evidence_id
            != role.attestation_evidence_id
        || handoff.evidence.evidence_revision
            != role.attestation_evidence_revision
        || handoff.evidence.evidence_sha256
            != role.attestation_evidence_sha256
        || handoff.chain_sha256 != expected_chain_sha256
        || role.assignment_sha256 != *assignment.envelope_sha256()
        || role.assignment_payload_sha256
            != *assignment.payload_sha256()
        || role.assignment_revision
            != assignment_payload.assignment_revision()
        || role.canary_id != *assignment_payload.canary_id()
        || role.load_receipt_sha256 != *load_receipt_sha256
        || role.load_receipt_payload_sha256
            != *load_receipt_payload_sha256
        || role.fleet_id != *fleet.fleet_id()
        || role.fleet_membership_revision
            != fleet.membership_revision()
        || role.membership_root_sha256
            != *fleet.membership_root_sha256()
        || role.member_ordinal != member_ordinal
        || role.member_id != member_id
        || role.instance_id != runtime.instance_id().as_str()
        || role.boot_id_sha256 != *runtime.boot_id_sha256()
        || role.runtime_identity_sha256 != *runtime_identity_sha256
        || role.attestation_policy_sha256
            != trust.runtime_attestation_policy_sha256
        || role.attestation_trust_checkpoint_sha256
            != trust.checkpoint.checkpoint_id
        || role.revocation_generation
            != trust.checkpoint.revocation_generation
        || role.revocation_root_sha256
            != trust.checkpoint.revocation_root_sha256
        || role.shadow_signing_key_id
            != *runtime.shadow_signing_key_id()
        || role.shadow_signing_key_spki_sha256
            != *runtime.shadow_signing_key_spki_sha256()
        || role.shadow_signing_key_id
            != trust.publication_signing_key_id
        || role.shadow_signing_key_spki_sha256
            != trust.publication_signing_key_spki_sha256
        || role.tee_measurement_sha256
            != *runtime.tee_measurement_sha256()
        || receipt.record.fleet_id != role.fleet_id
        || receipt.record.membership_revision
            != role.fleet_membership_revision
        || receipt.record.member_ordinal != role.member_ordinal
        || receipt.record.member_id != role.member_id
        || receipt.record.instance_id != role.instance_id
        || receipt.record.boot_id_sha256 != role.boot_id_sha256
        || receipt.record.spiffe_id != runtime.spiffe_id().as_str()
        || receipt.record.tee_platform
            != handoff.evidence.evidence_type
        || receipt.record.tee_evidence_sha256
            != handoff.evidence.evidence_sha256
        || receipt.record.tee_evidence_sha256
            != *runtime.tee_evidence_sha256()
        || receipt.record.tee_measurement_sha256
            != role.tee_measurement_sha256
        || receipt.record.tee_measurement_sha256
            != *runtime.tee_measurement_sha256()
        || is_production && !hardware_attested
    {
        return Err(GenerationInstallError::invalid(
            "runtime attestation handoff is not exactly bound to the signed assignment, load receipt, runtime, and shadow role",
        ));
    }
    Ok(())
}

fn verify_embedded_startup_attestation_signatures(
    handoff: &RuntimeAttestationHandoff,
    trust: &PinnedEnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<(), GenerationInstallError> {
    let receipt = verify_envelope(
        handoff.receipt.clone(),
        ExpectedSigner {
            key_id: &trust.startup_attestation_signing_key_id,
            key_spki_sha256:
                &trust.startup_attestation_signing_key_spki_sha256,
        },
        trust,
        trusted_time,
        MAX_TRUST_LIFETIME_NANOS,
    )
    .map_err(|error| {
        GenerationInstallError::invalid(format!(
            "embedded startup attestation receipt is invalid: {error}"
        ))
    })?;
    let role_signer = handoff.role_authorization.untrusted_signer();
    let role = verify_envelope(
        handoff.role_authorization.clone(),
        ExpectedSigner {
            key_id: role_signer.0,
            key_spki_sha256: role_signer.1,
        },
        trust,
        trusted_time,
        MAX_TRUST_LIFETIME_NANOS,
    )
    .map_err(|error| {
        GenerationInstallError::invalid(format!(
            "embedded shadow role authorization is invalid: {error}"
        ))
    })?;
    let receipt_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(&handoff.receipt)
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
    );
    let receipt_payload_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(receipt.payload()).map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?,
    );
    let role_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(&handoff.role_authorization)
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
    );
    let role_payload_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(role.payload()).map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?,
    );
    if receipt_sha256 != handoff.receipt_sha256
        || receipt_payload_sha256 != handoff.receipt_payload_sha256
        || role_sha256 != handoff.role_authorization_sha256
        || role_payload_sha256
            != handoff.role_authorization_payload_sha256
    {
        return Err(GenerationInstallError::invalid(
            "embedded startup attestation signed artifact bytes changed",
        ));
    }
    Ok(())
}

fn verify_local_runtime_attestation_binding(
    runtime: &PublicationRuntimeBinding,
    handoff: &RuntimeAttestationHandoff,
    verification: &RuntimeAttestationVerificationResult,
    trust: &PinnedEnvelopeKeyTrust,
) -> Result<(), GenerationInstallError> {
    let role = &handoff
        .role_authorization
        .untrusted_payload()
        .record;
    if runtime.decision_gate_executable_sha256
            != verification.runtime_executable_sha256
        || runtime.release_provenance_sha256
            != verification.runtime_release_sha256
        || runtime.runtime_configuration_sha256
            != verification.runtime_config_sha256
        || runtime.runtime_policy_sha256
            != verification.runtime_policy_sha256
        || runtime.runtime_instance_id != role.instance_id
        || runtime.runtime_boot_id_sha256 != role.boot_id_sha256
        || runtime.runtime_tee_measurement_sha256
            != role.tee_measurement_sha256
        || verification.runtime_executable_sha256
            != role.runtime_executable_sha256
        || verification.runtime_release_sha256
            != role.runtime_release_sha256
        || verification.runtime_config_sha256
            != role.runtime_config_sha256
        || verification.runtime_policy_sha256
            != role.runtime_policy_sha256
        || trust.publication_signing_key_id
            != role.shadow_signing_key_id
        || trust.publication_signing_key_spki_sha256
            != role.shadow_signing_key_spki_sha256
        || trust.publication_signing_key_id
            != trust.publication_signing_key_spki_sha256
    {
        return Err(GenerationInstallError::invalid(
            "local runtime and startup-attested shadow publication identity diverge",
        ));
    }
    Ok(())
}

fn framed_domain_digest(
    domain: &[u8],
    frames: &[&[u8]],
) -> Sha256Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    bytes.push(0);
    for frame in frames {
        bytes.extend_from_slice(
            &u64::try_from(frame.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(frame);
    }
    Sha256Digest::compute(&bytes)
}

fn generation_publication_high_water_digests(
    request: &PublicationRequestBinding,
    generation: &PublicationGenerationBinding,
    custody: &PublicationCustodyBinding,
    role: &ShadowRoleAuthorizationRecord,
) -> Result<(Sha256Digest, Sha256Digest), GenerationInstallError> {
    let custody_value = json!({
        "assignmentSha256":generation.assignment_envelope_sha256,
        "bootIdSha256":generation.runtime_boot_id_sha256,
        "canaryId":role.canary_id,
        "custodyPreparationReceiptSha256":
            custody.preparation_receipt_sha256,
        "custodySequence":
            custody.authoritative_ledger_event_ordinal,
        "generationId":generation.generation_id,
        "instanceId":role.instance_id,
        "memberOrdinal":role.member_ordinal,
    });
    let custody_bytes = canonical_json_bytes(&custody_value)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    let custody_high_water_sha256 = framed_domain_digest(
        b"serverware.policyShadowCustodyPublicationHighWater/v1",
        &[&custody_bytes],
    );
    let ingress_sequence = generation
        .ingress_range_start_sequence
        .checked_sub(1)
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "generation ingress range has no predecessor sequence",
            )
        })?;
    let ingress_value = json!({
        "assignmentSha256":generation.assignment_envelope_sha256,
        "bootIdSha256":generation.runtime_boot_id_sha256,
        "canaryId":role.canary_id,
        "custodyHighWaterSha256":custody_high_water_sha256,
        "generationId":generation.generation_id,
        "ingressSequence":ingress_sequence,
        "instanceId":role.instance_id,
        "memberOrdinal":role.member_ordinal,
    });
    let ingress_bytes = canonical_json_bytes(&ingress_value)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    let ingress_high_water_sha256 = framed_domain_digest(
        b"serverware.policyShadowIngressPublicationHighWater/v1",
        &[&ingress_bytes],
    );
    if custody.authoritative_ledger_head_sha256
            != custody_high_water_sha256
        || generation.ingress_range_predecessor_head_sha256
            != ingress_high_water_sha256
        || request.request_sha256.as_str().is_empty()
    {
        return Err(GenerationInstallError::conflict(
            "custody or ingress publication high-water evidence is not exact",
        ));
    }
    Ok((
        custody_high_water_sha256,
        ingress_high_water_sha256,
    ))
}

fn publication_attestation_chain_sha256(
    payload: &GenerationPublicationPayload,
) -> Result<Sha256Digest, GenerationInstallError> {
    let chain_bytes = canonical_json_bytes(&payload.attestation_chain)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    let binding = json!({
        "attestationRoleAuthorizationSha256":
            payload
                .attestation_chain
                .startup_attestation
                .role_authorization_sha256,
        "runtimeAttestationPayloadSha256":
            payload
                .attestation_chain
                .startup_attestation
                .receipt_payload_sha256,
        "runtimeAttestationReceiptSha256":
            payload
                .attestation_chain
                .startup_attestation
                .receipt_sha256,
        "runtimeAttestationVerificationReceiptSha256":
            payload
                .attestation_chain
                .runtime_attestation_verification_envelope_sha256,
        "signingKeySpkiSha256":
            payload.trust.publication_signing_key_spki_sha256,
    });
    let binding_bytes = canonical_json_bytes(&binding)
        .map_err(|error| {
            GenerationInstallError::invalid(error.to_string())
        })?;
    Ok(framed_domain_digest(
        b"serverware.policyShadowRuntimeAttestationChain/v1",
        &[&chain_bytes, &binding_bytes],
    ))
}

fn generation_publication_external_record(
    request: &PublicationRequestBinding,
    startup_attestation: &RuntimeAttestationHandoff,
    payload: &GenerationPublicationPayload,
    active_policy_bundle_sha256: &Sha256Digest,
    candidate_policy_bundle_sha256: &Sha256Digest,
) -> Result<
    GenerationPublicationExternalRecord,
    GenerationInstallError,
> {
    let role = &startup_attestation
        .role_authorization
        .untrusted_payload()
        .record;
    if payload.request != *request
        || payload.generation.active_policy_bundle_sha256
            != *active_policy_bundle_sha256
        || payload.generation.candidate_policy_bundle_sha256
            != *candidate_policy_bundle_sha256
    {
        return Err(GenerationInstallError::conflict(
            "external publication inputs diverge from generation evidence",
        ));
    }
    let (custody_high_water_sha256, ingress_high_water_sha256) =
        generation_publication_high_water_digests(
            request,
            &payload.generation,
            &payload.custody,
            role,
        )?;
    let ingress_sequence = payload
        .generation
        .ingress_range_start_sequence
        .checked_sub(1)
        .ok_or_else(|| {
            GenerationInstallError::invalid(
                "generation ingress range has no predecessor sequence",
            )
        })?;
    let attestation_chain_sha256 =
        publication_attestation_chain_sha256(payload)?;
    Ok(GenerationPublicationExternalRecord {
        request_id: request.request_id.clone(),
        replay_id: request.replay_id.clone(),
        management_handoff_id:
            request.management_handoff_id.clone(),
        request_payload_sha256: request.request_sha256.clone(),
        management_handoff_identity_sha256:
            request.management_handoff_sha256.clone(),
        candidate_id: role.candidate_id.clone(),
        canary_id: role.canary_id.clone(),
        assignment_sha256: payload
            .generation
            .assignment_envelope_sha256
            .clone(),
        assignment_payload_sha256: payload
            .generation
            .assignment_payload_sha256
            .clone(),
        assignment_revision:
            payload.generation.assignment_revision,
        generation_epoch: payload.generation.generation_epoch,
        minimum_generation_tombstone_epoch: payload
            .generation
            .minimum_generation_tombstone_epoch,
        fleet_id: role.fleet_id.clone(),
        fleet_membership_revision:
            role.fleet_membership_revision,
        membership_root_sha256:
            role.membership_root_sha256.clone(),
        member_ordinal: role.member_ordinal,
        member_id: role.member_id.clone(),
        instance_id: role.instance_id.clone(),
        boot_id_sha256: role.boot_id_sha256.clone(),
        load_receipt_sha256: payload
            .generation
            .load_receipt_envelope_sha256
            .clone(),
        load_receipt_payload_sha256: payload
            .generation
            .load_receipt_payload_sha256
            .clone(),
        generation_id: payload.generation.generation_id.clone(),
        publication_revision:
            payload.custody.publication_revision,
        custody_preparation_receipt_sha256: payload
            .custody
            .preparation_receipt_sha256
            .clone(),
        custody_high_water_sha256,
        custody_sequence: payload
            .custody
            .authoritative_ledger_event_ordinal,
        ingress_high_water_sha256,
        ingress_sequence,
        active_policy_sha256:
            payload.generation.active.policy_sha256.clone(),
        active_policy_sequence:
            payload.generation.active.policy_sequence,
        active_rollback_epoch:
            payload.generation.active.rollback_epoch,
        active_policy_bundle_sha256:
            active_policy_bundle_sha256.clone(),
        candidate_policy_sha256:
            payload.generation.candidate.policy_sha256.clone(),
        candidate_policy_sequence:
            payload.generation.candidate.policy_sequence,
        candidate_rollback_epoch:
            payload.generation.candidate.rollback_epoch,
        candidate_policy_bundle_sha256:
            candidate_policy_bundle_sha256.clone(),
        runtime_executable_sha256: payload
            .runtime
            .decision_gate_executable_sha256
            .clone(),
        runtime_release_sha256:
            payload.runtime.release_provenance_sha256.clone(),
        runtime_config_sha256: payload
            .runtime
            .runtime_configuration_sha256
            .clone(),
        runtime_policy_sha256:
            payload.runtime.runtime_policy_sha256.clone(),
        attestation_policy_sha256: payload
            .trust
            .runtime_attestation_policy_sha256
            .clone(),
        attestation_trust_checkpoint_sha256:
            payload.trust.trust_checkpoint_sha256.clone(),
        runtime_attestation_receipt_sha256:
            startup_attestation.receipt_sha256.clone(),
        runtime_attestation_payload_sha256:
            startup_attestation.receipt_payload_sha256.clone(),
        runtime_attestation_verification_receipt_sha256: payload
            .attestation_chain
            .runtime_attestation_verification_envelope_sha256
            .clone(),
        attestation_role_authorization_sha256:
            startup_attestation.role_authorization_sha256.clone(),
        attestation_evidence_sha256:
            startup_attestation.evidence.evidence_sha256.clone(),
        tee_measurement_sha256:
            role.tee_measurement_sha256.clone(),
        attestation_chain_sha256,
        attestation_mode:
            payload.attestation_chain.attestation_mode.clone(),
        hardware_attested:
            payload.attestation_chain.hardware_attested,
        generation_evidence: payload.clone(),
    })
}

fn external_record_projection_sha256(
    record: &GenerationPublicationExternalRecord,
) -> Result<Sha256Digest, GenerationInstallError> {
    let mut value = serde_json::to_value(record).map_err(|error| {
        GenerationInstallError::invalid(error.to_string())
    })?;
    let fields = value.as_object_mut().ok_or_else(|| {
        GenerationInstallError::invalid(
            "external publication record is not an object",
        )
    })?;
    if fields.remove("generationEvidence").is_none() {
        return Err(GenerationInstallError::invalid(
            "external publication record omitted generation evidence",
        ));
    }
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        GenerationInstallError::invalid(error.to_string())
    })?;
    Ok(Sha256Digest::compute(&canonical))
}

fn verify_external_publication_record(
    record: &GenerationPublicationExternalRecord,
    payload: &GenerationPublicationPayload,
) -> Result<(), GenerationInstallError> {
    let expected = generation_publication_external_record(
        &payload.request,
        &payload.attestation_chain.startup_attestation,
        payload,
        &payload.generation.active_policy_bundle_sha256,
        &payload.generation.candidate_policy_bundle_sha256,
    )?;
    if record != &expected
        || payload.external_record_sha256
            != external_record_projection_sha256(record)?
    {
        return Err(GenerationInstallError::conflict(
            "external publication record is not the exact authenticated projection",
        ));
    }
    Ok(())
}

fn publication_reservation_receipt_sha256(
    request: &PublicationRequestBinding,
    generation: &PublicationGenerationBinding,
    trust: &PublicationTrustBinding,
) -> Result<Sha256Digest, ShadowError> {
    domain_digest(
        b"serverware.policyShadowGenerationDurableReplayReservation/v1",
        &(
            request,
            &generation.generation_id,
            generation.assignment_revision,
            &trust.publication_replay_store_sha256,
            trust.replay_store_revision,
        ),
    )
    .map_err(|_| {
        ShadowError::CanonicalizationFailure(
            "durable replay reservation digest failed",
        )
    })
}

fn publication_commit_receipt_sha256(
    request: &PublicationRequestBinding,
    preparation_envelope_sha256: &Sha256Digest,
    generation: &PublicationGenerationBinding,
    custody: &PublicationCustodyBinding,
    trust: &PublicationTrustBinding,
) -> Result<Sha256Digest, ShadowError> {
    domain_digest(
        b"serverware.policyShadowGenerationDurableReplayCommit/v1",
        &(
            request,
            preparation_envelope_sha256,
            &generation.generation_id,
            generation.assignment_revision,
            custody,
            &trust.publication_replay_store_sha256,
            trust.replay_store_revision,
        ),
    )
    .map_err(|_| {
        ShadowError::CanonicalizationFailure(
            "durable replay commit digest failed",
        )
    })
}

fn publication_generation_binding(
    generation: &ShadowGenerationIdentity,
    active: &Snapshot,
    candidate: &Snapshot,
    active_policy_bundle_sha256: &Sha256Digest,
    candidate_policy_bundle_sha256: &Sha256Digest,
) -> Result<PublicationGenerationBinding, GenerationInstallError> {
    let (_, request_commitment_key_epoch) =
        generation.request_commitment_key_binding();
    Ok(PublicationGenerationBinding {
        generation_id: generation.generation_id().clone(),
        generation_epoch: generation.generation_epoch(),
        minimum_generation_tombstone_epoch:
            generation.minimum_generation_tombstone_epoch(),
        generation_tombstone_epoch:
            generation.generation_tombstone_epoch(),
        assignment_envelope_sha256:
            generation.assignment_sha256().clone(),
        assignment_payload_sha256:
            generation.assignment_payload_sha256().clone(),
        assignment_revision: generation.assignment_revision(),
        load_receipt_envelope_sha256:
            generation.load_receipt_sha256().clone(),
        load_receipt_payload_sha256:
            generation.load_receipt_payload_sha256().clone(),
        runtime_boot_id_sha256:
            generation.runtime_boot_id_sha256().clone(),
        active: PublicationSnapshotBinding {
            policy_sha256:
                generation.active_policy_sha256().clone(),
            policy_sequence:
                generation.active_policy_sequence(),
            rollback_epoch:
                generation.active_rollback_epoch(),
            compiled_snapshot_sha256: generation
                .active_compiled_snapshot_sha256()
                .clone(),
            compiled_behavior_sha256: Sha256Digest::parse(
                active.compiled_behavior_sha256.clone(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
            runtime_snapshot_epoch: active.epoch,
            policy_trust_generation: active.trust_generation,
        },
        active_policy_bundle_sha256:
            active_policy_bundle_sha256.clone(),
        candidate: PublicationSnapshotBinding {
            policy_sha256:
                generation.candidate_policy_sha256().clone(),
            policy_sequence:
                generation.candidate_policy_sequence(),
            rollback_epoch:
                generation.candidate_rollback_epoch(),
            compiled_snapshot_sha256: generation
                .candidate_compiled_snapshot_sha256()
                .clone(),
            compiled_behavior_sha256: Sha256Digest::parse(
                candidate.compiled_behavior_sha256.clone(),
            )
            .map_err(|error| {
                GenerationInstallError::invalid(error.to_string())
            })?,
            runtime_snapshot_epoch: candidate.epoch,
            policy_trust_generation: candidate.trust_generation,
        },
        candidate_policy_bundle_sha256:
            candidate_policy_bundle_sha256.clone(),
        request_commitment_key_epoch,
        request_facts_schema_sha256:
            generation.request_facts_schema_sha256().clone(),
        ingress_range_start_sequence:
            generation.ingress_range_start_sequence(),
        ingress_range_predecessor_head_sha256: generation
            .ingress_range_predecessor_head_sha256()
            .clone(),
        observation_interval_sha256:
            generation.observation_interval_sha256().clone(),
        response_validation_obligations_root_sha256: generation
            .response_validation_obligations_root_sha256()
            .clone(),
        signed_publication_revision:
            generation.signed_publication_revision(),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_publication_common(
    schema_version: &str,
    expected_schema_version: &str,
    signature_domain: &str,
    expected_signature_domain: &str,
    signature_algorithm: &str,
    canonicalization_profile: &str,
    status: &str,
    expected_status: &str,
    request: &PublicationRequestBinding,
    generation: &PublicationGenerationBinding,
    runtime: &PublicationRuntimeBinding,
    trust: &PublicationTrustBinding,
    attestation_chain: &PublicationAttestationChain,
    not_before_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
) -> Result<(), ShadowError> {
    let startup_attestation =
        &attestation_chain.startup_attestation;
    let evidence = &startup_attestation.evidence;
    let evidence_bytes = canonical_json_bytes(&evidence.evidence)?;
    let expected_handoff_sha256 = domain_digest(
        b"serverware.policyShadowGenerationManagementHandoff/v1",
        &(
            request.request_id.as_str(),
            request.replay_id.as_str(),
            request.management_handoff_id.as_str(),
            &request.request_sha256,
            &runtime.runtime_identity_sha256,
        ),
    )
    .map_err(|_| {
        ShadowError::CanonicalizationFailure(
            "management handoff digest failed",
        )
    })?;
    let verification_envelope_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(
            &attestation_chain.runtime_attestation_verification,
        )?,
    );
    let verification = attestation_chain
        .runtime_attestation_verification
        .untrusted_payload();
    if schema_version != expected_schema_version
        || signature_domain != expected_signature_domain
        || signature_algorithm != SIGNATURE_ALGORITHM
        || canonicalization_profile != CANONICAL_PROFILE
        || status != expected_status
        || !bounded_ascii_token(
            &request.request_id,
            MAX_REPLAY_IDENTIFIER_BYTES,
        )
        || !bounded_ascii_token(
            &request.replay_id,
            MAX_REPLAY_IDENTIFIER_BYTES,
        )
        || !bounded_ascii_token(
            &request.management_handoff_id,
            MAX_REPLAY_IDENTIFIER_BYTES,
        )
        || request.request_id == request.replay_id
        || request.request_id == request.management_handoff_id
        || request.replay_id == request.management_handoff_id
        || request.management_handoff_sha256
            != expected_handoff_sha256
        || generation.generation_epoch == 0
        || generation.minimum_generation_tombstone_epoch == 0
        || generation.generation_tombstone_epoch == 0
        || generation.generation_tombstone_epoch
            > generation.generation_epoch
        || generation.generation_tombstone_epoch
            < generation.minimum_generation_tombstone_epoch
        || generation.assignment_revision == 0
        || generation.active.policy_sequence == 0
        || generation.active.rollback_epoch == 0
        || generation.candidate.policy_sequence
            <= generation.active.policy_sequence
        || generation.candidate.rollback_epoch == 0
        || generation.request_commitment_key_epoch == 0
        || generation.ingress_range_start_sequence == 0
        || generation.signed_publication_revision == 0
        || runtime.runtime_instance_id.is_empty()
        || runtime.runtime_boot_id_sha256
            != generation.runtime_boot_id_sha256
        || runtime.request_facts_schema_sha256
            != generation.request_facts_schema_sha256
        || trust.revocation_generation == 0
        || trust.replay_store_revision == 0
        || trust.replay_store_revision
            != generation.assignment_revision
        || evidence.api_version != RUNTIME_EVIDENCE_API_VERSION
        || evidence_bytes.is_empty()
        || evidence_bytes.len() > MAX_RUNTIME_EVIDENCE_BYTES
        || Sha256Digest::compute(&evidence_bytes)
            != evidence.evidence_sha256
        || verification.attestation_mode
            != attestation_chain.attestation_mode
        || verification.hardware_attested
            != attestation_chain.hardware_attested
        || verification.runtime_identity_sha256
            != runtime.runtime_identity_sha256
        || verification.runtime_executable_sha256
            != runtime.decision_gate_executable_sha256
        || verification.runtime_release_sha256
            != runtime.release_provenance_sha256
        || verification.runtime_config_sha256
            != runtime.runtime_configuration_sha256
        || verification.runtime_policy_sha256
            != runtime.runtime_policy_sha256
        || runtime.runtime_policy_sha256
            != generation.active.policy_sha256
        || verification.assignment_payload_sha256
            != generation.assignment_payload_sha256
        || verification.load_receipt_payload_sha256
            != generation.load_receipt_payload_sha256
        || verification_envelope_sha256
            != attestation_chain
                .runtime_attestation_verification_envelope_sha256
        || verification.evidence_chain_sha256
            != startup_attestation_handoff_chain_sha256(
                startup_attestation,
                &generation.assignment_payload_sha256,
                &generation.load_receipt_payload_sha256,
                &runtime.runtime_identity_sha256,
                &trust.runtime_attestation_policy_sha256,
            )
            .map_err(|_| {
                ShadowError::CanonicalizationFailure(
                    "runtime attestation evidence chain failed",
                )
            })?
        || issued_at_unix_nanos <= 0
        || not_before_unix_nanos != issued_at_unix_nanos
        || expires_at_unix_nanos <= issued_at_unix_nanos
        || expires_at_unix_nanos
            .checked_sub(issued_at_unix_nanos)
            .is_none_or(|lifetime| {
                lifetime > MAX_PUBLICATION_RECEIPT_LIFETIME_NANOS
            })
    {
        return Err(ShadowError::GenerationIdentityMismatch);
    }
    Ok(())
}

fn required_runtime_release_digest(
    value: Value,
    label: &str,
) -> Result<Sha256Digest, GenerationInstallError> {
    let digest = value.as_str().ok_or_else(|| {
        GenerationInstallError::unavailable(format!(
            "{label} digest is unavailable"
        ))
    })?;
    Sha256Digest::parse(digest.to_string()).map_err(|error| {
        GenerationInstallError::invalid(format!(
            "{label} digest is invalid: {error}"
        ))
    })
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Sha256Digest, String> {
    let canonical = canonical_json_bytes(value).map_err(shadow_error)?;
    let mut bytes = Vec::with_capacity(
        domain.len().saturating_add(1).saturating_add(canonical.len()),
    );
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(Sha256Digest::compute(&bytes))
}

fn bounded_ascii_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'@' | b'+' | b'-')
        })
}

fn bounded_ascii_domain(value: &str) -> bool {
    value.starts_with("serverware.")
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'/' | b'_' | b':' | b'-')
        })
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn optional_env_path(name: &str) -> Option<PathBuf> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn optional_env_digest(name: &str) -> Result<Option<Sha256Digest>, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Sha256Digest::parse)
        .transpose()
        .map_err(shadow_error)
}

fn normalized_absolute_path(
    path: PathBuf,
    label: &str,
) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(component, Component::CurDir | Component::ParentDir)
        })
    {
        return Err(format!("{label} must be an absolute normalized path"));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("canonicalize {label}: {error}"))?;
    if canonical != path {
        return Err(format!(
            "{label} must not contain symlinked path components"
        ));
    }
    Ok(path)
}

fn configured_pinned_command_from_env(
    command_env: &str,
    digest_env: &str,
) -> Result<PinnedVerifierCommand, String> {
    let command = required_env(command_env)?;
    let expected_sha256 = required_env(digest_env)?;
    if !is_sha256_digest(&expected_sha256) {
        return Err(format!(
            "{digest_env} must be a lowercase SHA-256 digest"
        ));
    }
    let argv = shlex::split(&command).ok_or_else(|| {
        format!("{command_env} has invalid quoting")
    })?;
    let (executable, arguments) = argv.split_first().ok_or_else(|| {
        format!("{command_env} is empty")
    })?;
    Ok(PinnedVerifierCommand {
        executable: PathBuf::from(executable),
        arguments: arguments.to_vec(),
        expected_sha256,
    })
}

fn validate_configured_pinned_command(
    command: &PinnedVerifierCommand,
    digest_label: &str,
) -> Result<(), String> {
    if !is_sha256_digest(&command.expected_sha256) {
        return Err(format!(
            "{digest_label} must be a lowercase SHA-256 digest"
        ));
    }
    verify_pinned_verifier_executable(command)
}

fn immutable_config_identity(
    path: &Path,
    is_production: bool,
) -> Result<ImmutablePathIdentity, String> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        format!("inspect policy-shadow custody configuration: {error}")
    })?;
    validate_immutable_metadata(
        &path_metadata,
        is_production,
        "policy-shadow custody configuration",
    )?;
    if path_metadata.len() == 0
        || path_metadata.len() > MAX_CUSTODY_CONFIG_BYTES
    {
        return Err(format!(
            "policy-shadow custody configuration must contain 1-{MAX_CUSTODY_CONFIG_BYTES} bytes"
        ));
    }
    let mut retained_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "open policy-shadow custody configuration without following symlinks: {error}"
            )
        })?;
    let before = retained_file.metadata().map_err(|error| {
        format!(
            "inspect opened policy-shadow custody configuration: {error}"
        )
    })?;
    if path_metadata.dev() != before.dev()
        || path_metadata.ino() != before.ino()
    {
        return Err(
            "policy-shadow custody configuration changed while it was opened"
                .to_string(),
        );
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).unwrap_or(0),
    );
    Read::by_ref(&mut retained_file)
        .take(MAX_CUSTODY_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!("read policy-shadow custody configuration: {error}")
        })?;
    let after = retained_file.metadata().map_err(|error| {
        format!(
            "reinspect opened policy-shadow custody configuration: {error}"
        )
    })?;
    let path_after = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "reinspect policy-shadow custody configuration path: {error}"
        )
    })?;
    if bytes.len() as u64 != before.len()
        || !same_metadata(&before, &after)
        || !same_metadata(&after, &path_after)
    {
        return Err(
            "policy-shadow custody configuration changed while it was retained"
                .to_string(),
        );
    }
    let content_sha256 = Sha256Digest::compute(&bytes);
    Ok(ImmutablePathIdentity {
        path: path.to_path_buf(),
        retained_file,
        content_sha256,
        device: after.dev(),
        inode: after.ino(),
        size: after.len(),
        mode: after.mode(),
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
        changed_seconds: after.ctime(),
        changed_nanoseconds: after.ctime_nsec(),
    })
}

fn read_immutable_artifact(
    path: &Path,
    maximum_bytes: u64,
    expected_sha256: &Sha256Digest,
    is_production: bool,
    label: &str,
) -> Result<Vec<u8>, String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label}: {error}"))?;
    validate_immutable_metadata(&path_metadata, is_production, label)?;
    if path_metadata.len() == 0 || path_metadata.len() > maximum_bytes {
        return Err(format!(
            "{label} must contain 1-{maximum_bytes} bytes"
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!("open {label} without following symlinks: {error}")
        })?;
    let before = file
        .metadata()
        .map_err(|error| format!("inspect opened {label}: {error}"))?;
    if path_metadata.dev() != before.dev()
        || path_metadata.ino() != before.ino()
    {
        return Err(format!("{label} changed while it was opened"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).unwrap_or(0),
    );
    Read::by_ref(&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect opened {label}: {error}"))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect {label}: {error}"))?;
    if bytes.len() as u64 != before.len()
        || !same_metadata(&before, &after)
        || !same_metadata(&after, &path_after)
        || path_after.file_type().is_symlink()
    {
        return Err(format!("{label} changed while it was read"));
    }
    let actual_sha256 = Sha256Digest::parse(sha256_prefixed(&bytes))
        .map_err(shadow_error)?;
    if &actual_sha256 != expected_sha256 {
        return Err(format!("{label} SHA-256 mismatch"));
    }
    Ok(bytes)
}

fn validate_immutable_metadata(
    metadata: &fs::Metadata,
    is_production: bool,
    label: &str,
) -> Result<(), String> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
    {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0
        || (is_production && metadata.uid() != 0)
    {
        return Err(format!(
            "{label} must be immutable to non-root writers"
        ));
    }
    Ok(())
}

fn same_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn shadow_error(error: ShadowError) -> String {
    error.to_string()
}
