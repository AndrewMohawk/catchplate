//! Pure active/candidate policy evaluation and bounded shadow dispatch.
//!
//! This module deliberately has no authority to acquire credentials, consume
//! grants or quotas, sign evidence, or contact an upstream. `PolicyPlanSnapshot`
//! contains compiled policy metadata only; effect execution remains in the
//! existing active decision path in `main.rs`.

use super::*;
use super::policy_shadow::{
    ActiveEffectCommitState, ActiveEffectIntent, ActiveEffectPreparation,
    ActiveEffectRequirement, ActiveEffectRequirements,
    ActiveEffectTerminalEvidence, ActiveEffectTerminalState,
    ActiveMutableEffectKind, ActivePolicyPlan, CompactActiveEffectCommitReceipt,
    AuthenticatedSpoolCompactionRequest,
    canonical_json_bytes,
    CandidateEffectIntent, CandidatePolicyPlan, IngressCustodyAdmission,
    PersistedIngressAdmission, Identifier, PolicyOutcome,
    PolicyShadowCustodyCallContext, PolicyShadowCustodyOperation,
    PolicyShadowCustodyRpcSupervisor,
    PublicationReconciliationState,
    PreparedGenerationPublication, SamplingDecision, Sha256Digest, ShadowError,
    ShadowSpoolDisposition, ShadowSpoolEvent, ShadowSpoolPhase,
    SpoolAppendReservationOutcome, TerminalSlotAppendOutcome,
    TerminalSlotAppendRequest, VerifiedActiveEffectCommitReceipt,
    VerifiedActiveEffectPermit, VerifiedAssignment, VerifiedLoadReceipt,
    VerifiedActivationPublicationReceipt,
    VerifiedPublicationReconciliationReceipt, VerifiedShadowSpillReceipt,
    VerifiedSpoolCompactionReceipt, VerifiedUnavailableGenerationReceipt,
    ShadowGenerationIdentity,
    InlineReceiptReference as ModeledInlineReceiptReference,
    InlineSha256Digest as ModeledInlineSha256Digest,
    ModeledReservationKind,
    ModeledReservationToken, ReceiptReferenceKind, ReceiptSlotHandle,
    PolicyCoreModeledReceiptArena,
    MODELED_RECEIPT_REFERENCE_BUDGET_BYTES,
    MODELED_RECEIPT_REFERENCE_BUDGET_LABEL,
};
pub(crate) use super::policy_shadow::PolicyShadowTerminalReason;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{
    AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering,
};
use std::sync::mpsc::{
    self, Receiver, SyncSender, TrySendError,
};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const SHADOW_QUEUE_ITEMS: usize = 1_024;
const SHADOW_QUEUE_BYTES: usize = 128 * 1024 * 1024;
const SHADOW_MAX_JOB_BYTES: usize = 20 * 1024 * 1024;
// Additional inline terminal-reference retention per lifecycle. Charge each
// queued job conservatively even when jobs share that lifecycle. This is not
// an extension of the receipt-arena budget or a total heap/RSS measurement.
const SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES: usize = 384;
// Four inline outer-wrapper slots, plus parent/result context. Conservatively
// charge four simultaneous lifecycle/pending/final/job copies. No wire strings,
// credential metadata graph, provider secret, or receipt-arena allocation is
// retained in this increment. This remains a modeled queue budget, not RSS.
const SHADOW_CREDENTIAL_PREREQUISITE_RETENTION_BYTES: usize = 4 * 4096;

fn shadow_job_bytes_with_terminal_retention(payload_bytes: usize) -> usize {
    payload_bytes.saturating_add(SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES)
        .saturating_add(SHADOW_CREDENTIAL_PREREQUISITE_RETENTION_BYTES)
}
const SHADOW_MAX_FACT_HEADERS: usize = 128;
const SHADOW_MAX_FACT_HEADER_BYTES: usize = 64 * 1024;
const SHADOW_MAX_FACT_BODY_BYTES: usize = 16 * 1024 * 1024;
const SHADOW_MAX_FACT_METADATA_BYTES: usize = 256 * 1024;
const SHADOW_MAX_SNAPSHOT_BYTES: usize = 3 * 1024 * 1024;
const SHADOW_MAX_RESPONSE_HEADERS: usize = 256;
const SHADOW_MAX_RESPONSE_HEADER_BYTES: usize = 128 * 1024;
const SHADOW_MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
fn checked_epoch_ms(value: u128) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| "epoch millisecond value exceeds u64".to_string())
}

fn checked_epoch_ms_to_unix_nanos(value: u64) -> Result<i64, String> {
    i64::try_from(value)
        .map_err(|_| "epoch millisecond value exceeds i64".to_string())?
        .checked_mul(1_000_000)
        .ok_or_else(|| "epoch nanosecond conversion overflow".to_string())
}

fn custody_call_context(
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    custody_operation: PolicyShadowCustodyOperation,
    operation: &str,
    binding: &str,
) -> Result<PolicyShadowCustodyCallContext, String> {
    let context = custody.open_call(
        Sha256Digest::compute(
            format!(
                "serverware.policyShadowCustodyCall/v2\0{operation}\0{binding}\0{}",
                now_epoch_ms()
            )
            .as_bytes(),
        ),
        custody_operation,
    )
    .map_err(shadow_error)?;
    if !context.authorizes(custody_operation) {
        return Err(
            "custody RPC supervisor returned a mismatched operation context"
                .to_string(),
        );
    }
    Ok(context)
}

fn finish_custody_call(
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    context: PolicyShadowCustodyCallContext,
) -> bool {
    let completion_binding = context.completion_binding();
    custody
        .finish_call(context)
        .is_ok_and(|completion| {
            completion.validates_binding(&completion_binding)
        })
}

fn abort_generation_publication_supervised(
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    prepared: PreparedGenerationPublication,
) -> Result<(), String> {
    let binding = prepared.preparation_receipt_sha256().as_str().to_string();
    let context = custody_call_context(
        custody,
        PolicyShadowCustodyOperation::AbortGenerationPublication,
        "abort-generation-publication",
        &binding,
    )?;
    let result = custody
        .abort_generation_publication(&context, prepared)
        .map_err(shadow_error);
    if !finish_custody_call(custody, context) {
        return Err(
            "custody publication abort supervisor did not terminate cleanly"
                .to_string(),
        );
    }
    result
}

fn checked_custody_observed_epoch_ms(
    admission: &PersistedIngressAdmission,
) -> Result<u64, String> {
    let nanos = u64::try_from(admission.observed_at_unix_nanos())
        .map_err(|_| "custody observed time is negative".to_string())?;
    let epoch_ms = nanos
        .checked_div(1_000_000)
        .ok_or_else(|| "custody observed time conversion failed".to_string())?;
    if epoch_ms == 0 {
        return Err("custody observed time is zero".to_string());
    }
    Ok(epoch_ms)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ShadowIngressKind {
    ForwardedHttp,
    ManagementPreview,
    OuterConnect,
    UnsupportedStreamingBody,
}

impl ShadowIngressKind {
    fn is_matched_http(self) -> bool {
        matches!(
            self,
            Self::ForwardedHttp | Self::ManagementPreview
        )
    }

    fn is_shadow_coverage(self) -> bool {
        self == Self::ForwardedHttp
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyLane {
    Active,
    Candidate,
}

/// Effect-free projection of a compiled policy snapshot.
///
/// `Snapshot::credentials` contains only signed injection policy and provider
/// identity metadata. Leased credential values live in `GateState` and are
/// intentionally unreachable from this projection.
#[derive(Clone)]
pub(crate) struct PolicyPlanSnapshot {
    snapshot: Arc<Snapshot>,
    lane: PolicyLane,
    estimated_bytes: usize,
}

impl PolicyPlanSnapshot {
    fn from_snapshot(snapshot: &Arc<Snapshot>, lane: PolicyLane) -> Result<Self, String> {
        if snapshot.rollback_epoch == 0 {
            return Err("policy rollback epoch must be at least one".to_string());
        }
        let projection = Snapshot {
            epoch: snapshot.epoch,
            hash: snapshot.hash.clone(),
            policy_id: snapshot.policy_id.clone(),
            policy_sequence: snapshot.policy_sequence,
            rollback_epoch: snapshot.rollback_epoch,
            trust_generation: snapshot.trust_generation,
            compiled_behavior_sha256: snapshot.compiled_behavior_sha256.clone(),
            policy_signing_key_id: snapshot.policy_signing_key_id.clone(),
            response_verifying_key: None,
            response_signing_key_id: None,
            attested_response_context: None,
            principals: snapshot.principals.clone(),
            credentials: snapshot.credentials.clone(),
            routes: snapshot.routes.clone(),
        };
        let estimated_bytes = estimate_snapshot_bytes(&projection)?;
        if estimated_bytes > SHADOW_MAX_SNAPSHOT_BYTES {
            return Err("policy projection exceeds shadow snapshot bound".to_string());
        }
        Ok(Self {
            snapshot: Arc::new(projection),
            lane,
            estimated_bytes,
        })
    }

    fn active(snapshot: &Arc<Snapshot>) -> Result<Self, String> {
        Self::from_snapshot(snapshot, PolicyLane::Active)
    }

    fn candidate(snapshot: &Arc<Snapshot>) -> Result<Self, String> {
        Self::from_snapshot(snapshot, PolicyLane::Candidate)
    }

    fn identity(&self) -> (&str, u64, u64) {
        (
            self.snapshot.hash.as_str(),
            self.snapshot.policy_sequence,
            self.snapshot.rollback_epoch,
        )
    }
}

fn estimate_snapshot_bytes(snapshot: &Snapshot) -> Result<usize, String> {
    let mut total = snapshot
        .hash
        .len()
        .saturating_add(snapshot.policy_id.len())
        .saturating_add(snapshot.policy_signing_key_id.len());
    for principal in &snapshot.principals {
        total = total
            .saturating_add(principal.id.len())
            .saturating_add(
                principal
                    .required_headers
                    .iter()
                    .map(|(name, value)| name.len().saturating_add(value.len()))
                    .sum::<usize>(),
            );
    }
    for (credential_id, credential) in &snapshot.credentials {
        total = total
            .saturating_add(credential_id.len())
            .saturating_add(credential.provider.len())
            .saturating_add(
                credential
                    .provider_subject
                    .as_ref()
                    .map(String::len)
                    .unwrap_or(0),
            )
            .saturating_add(
                serde_json::to_vec(&credential.injection)
                    .map_err(|_| "serialize credential policy projection")?
                    .len(),
            );
    }
    for route in &snapshot.routes {
        total = total
            .saturating_add(route.id.len())
            .saturating_add(route.host.len())
            .saturating_add(route.adapter_type.len())
            .saturating_add(
                serde_json::to_vec(&route.adapter_config)
                    .map_err(|_| "serialize adapter policy projection")?
                    .len(),
            )
            .saturating_add(
                serde_json::to_vec(&route.constraints)
                    .map_err(|_| "serialize constraint policy projection")?
                    .len(),
            )
            .saturating_add(
                serde_json::to_vec(&route.jit)
                    .map_err(|_| "serialize JIT policy projection")?
                    .len(),
            );
    }
    Ok(total)
}

/// Immutable request material captured before any effectful authorization step.
#[derive(Clone)]
pub(crate) struct AdmittedRequestFacts {
    ingress: ShadowIngressKind,
    captured_at_epoch_ms: u64,
    authenticated_principal_id: Option<String>,
    client_ip: Option<String>,
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Arc<[u8]>,
    body_sha256: Option<String>,
    forwarded_body_length: Option<u64>,
    forwarded_body_utf8_valid: Option<bool>,
    client_request_digest: Option<String>,
}

impl AdmittedRequestFacts {
    #[allow(clippy::too_many_arguments)]
    fn capture(
        request: &DecisionRequest,
        authenticated_principal_id: Option<&str>,
        ingress: ShadowIngressKind,
        captured_at_epoch_ms: u64,
        raw_body: Option<&[u8]>,
    ) -> Result<Self, String> {
        if captured_at_epoch_ms == 0 {
            return Err("shadow capture time is invalid".to_string());
        }
        if request.headers.len() > SHADOW_MAX_FACT_HEADERS {
            return Err("shadow request header count exceeds bound".to_string());
        }
        if request.method.is_empty()
            || request.method.len() > 32
            || request.url.is_empty()
            || request.url.len() > 16 * 1024
            || request
                .client_ip
                .as_ref()
                .is_some_and(|value| value.len() > 256)
            || authenticated_principal_id.is_some_and(|value| value.len() > 256)
            || request
                .client_request_digest
                .as_ref()
                .is_some_and(|value| value.len() > 128)
        {
            return Err("shadow request metadata exceeds bound".to_string());
        }
        let header_bytes = request
            .headers
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum::<usize>();
        if header_bytes > SHADOW_MAX_FACT_HEADER_BYTES {
            return Err("shadow request headers exceed byte bound".to_string());
        }
        let body = raw_body.unwrap_or_else(|| request.body.as_bytes());
        if body.len() > SHADOW_MAX_FACT_BODY_BYTES {
            return Err("shadow request body exceeds capture bound".to_string());
        }
        let metadata_bytes = request
            .method
            .len()
            .saturating_add(request.url.len())
            .saturating_add(header_bytes)
            .saturating_add(request.client_ip.as_ref().map(String::len).unwrap_or(0))
            .saturating_add(authenticated_principal_id.map(str::len).unwrap_or(0))
            .saturating_add(
                request
                    .client_request_digest
                    .as_ref()
                    .map(String::len)
                    .unwrap_or(0),
            );
        if metadata_bytes > SHADOW_MAX_FACT_METADATA_BYTES {
            return Err("shadow request metadata exceeds byte bound".to_string());
        }
        if request
            .body_sha256
            .as_ref()
            .is_some_and(|digest| digest != &sha256_prefixed(body))
        {
            return Err("shadow request body digest does not match body".to_string());
        }
        if request.forwarded_body_length.is_some_and(|length| {
            usize::try_from(length).ok() != Some(body.len())
        }) {
            return Err("shadow request body length does not match raw bytes".to_string());
        }
        if request.forwarded_body_utf8_valid
            != request
                .forwarded_body_utf8_valid
                .map(|_| std::str::from_utf8(body).is_ok())
        {
            return Err("shadow request UTF-8 fact does not match raw bytes".to_string());
        }
        if request.credential_metadata.values().any(|value| !value.is_empty())
            || !request.gmail_proofs.is_empty()
        {
            return Err("effect-derived facts cannot enter shadow capture".to_string());
        }
        Ok(Self {
            ingress,
            captured_at_epoch_ms,
            authenticated_principal_id: authenticated_principal_id.map(str::to_string),
            client_ip: request.client_ip.clone(),
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: Arc::from(body),
            body_sha256: request.body_sha256.clone(),
            forwarded_body_length: request.forwarded_body_length,
            forwarded_body_utf8_valid: request.forwarded_body_utf8_valid,
            client_request_digest: request.client_request_digest.clone(),
        })
    }

    fn to_decision_request(&self) -> Result<DecisionRequest, String> {
        let body = match std::str::from_utf8(&self.body) {
            Ok(body) => body.to_string(),
            Err(_) if self.forwarded_body_utf8_valid == Some(false) => String::new(),
            Err(_) => return Err("captured request body UTF-8 state is inconsistent".to_string()),
        };
        Ok(DecisionRequest {
            client_ip: self.client_ip.clone(),
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body,
            body_sha256: self.body_sha256.clone(),
            forwarded_body_length: self.forwarded_body_length,
            forwarded_body_utf8_valid: self.forwarded_body_utf8_valid,
            credential_metadata: BTreeMap::new(),
            gmail_proofs: Vec::new(),
            client_request_digest: self.client_request_digest.clone(),
        })
    }

    fn estimated_bytes(&self) -> usize {
        self.authenticated_principal_id
            .as_ref()
            .map(String::len)
            .unwrap_or(0)
            .saturating_add(self.client_ip.as_ref().map(String::len).unwrap_or(0))
            .saturating_add(self.method.len())
            .saturating_add(self.url.len())
            .saturating_add(
                self.headers
                    .iter()
                    .map(|(name, value)| name.len().saturating_add(value.len()))
                    .sum::<usize>(),
            )
            .saturating_add(self.body.len())
            .saturating_add(self.body_sha256.as_ref().map(String::len).unwrap_or(0))
            .saturating_add(
                self.client_request_digest
                    .as_ref()
                    .map(String::len)
                    .unwrap_or(0),
            )
    }
}

impl Drop for AdmittedRequestFacts {
    fn drop(&mut self) {
        if let Some(value) = self.authenticated_principal_id.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.client_ip.as_mut() {
            value.zeroize();
        }
        self.method.zeroize();
        self.url.zeroize();
        if let Some(body) = Arc::get_mut(&mut self.body) {
            body.zeroize();
        }
        if let Some(value) = self.body_sha256.as_mut() {
            value.zeroize();
        }
        zeroize_string_map(&mut self.headers);
        if let Some(value) = self.client_request_digest.as_mut() {
            value.zeroize();
        }
    }
}

#[derive(Clone)]
pub(crate) struct PolicyEvaluationContext {
    captured_at_epoch_ms: u64,
    decision_at_epoch_ms: u64,
    lane: PolicyLane,
    resolved_credential_slot: Option<String>,
    resolved_credential_version: Option<u64>,
}

impl PolicyEvaluationContext {
    fn active(
        captured_at_epoch_ms: u64,
        decision_at_epoch_ms: u64,
        resolved_credential_version: Option<u64>,
    ) -> Self {
        Self {
            captured_at_epoch_ms,
            decision_at_epoch_ms,
            lane: PolicyLane::Active,
            resolved_credential_slot: None,
            resolved_credential_version,
        }
    }

    fn candidate(
        captured_at_epoch_ms: u64,
        decision_at_epoch_ms: u64,
        resolved_credential_slot: Option<String>,
        resolved_credential_version: Option<u64>,
    ) -> Self {
        Self {
            captured_at_epoch_ms,
            decision_at_epoch_ms,
            lane: PolicyLane::Candidate,
            resolved_credential_slot,
            resolved_credential_version,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase")]
enum ConditionalIntent {
    MaterializeCredential {
        credential_slot: String,
        destination: String,
    },
    ResolveCredentialVersion {
        credential_slot: String,
        credential_claim_sha256: String,
    },
    RefreshOauthCredential {
        credential_slot: String,
        oauth_authority_sha256: String,
    },
    ExchangeOauthCredential {
        credential_slot: String,
        oauth_authority_sha256: String,
    },
    MintOauthCredential {
        credential_slot: String,
        oauth_authority_sha256: String,
    },
    BindIdempotencyKey {
        idempotency_commitment_sha256: String,
    },
    ResolveRecoveryState {
        recovery_commitment_sha256: String,
    },
    RequireGmailPriorSearchProof {
        route_id: String,
        gmail_user: String,
        message_id_sha256: String,
        maximum_age_days: u64,
    },
    ResolveGmailMetadataFanout {
        route_id: String,
        maximum_age_days: u64,
        maximum_messages: u64,
    },
    RequireJitApproval {
        policy_sha256: String,
    },
    ReserveQuota {
        counter_sha256: String,
        claim_sha256: String,
        weighted_units: u64,
    },
    ReserveDurableBudget {
        budget_sha256: String,
        claim_sha256: String,
        weighted_units: u64,
    },
}

impl ConditionalIntent {
    fn requires_resolution(&self) -> bool {
        !matches!(
            self,
            Self::MaterializeCredential { .. }
                | Self::BindIdempotencyKey { .. }
        )
    }
}

#[derive(Clone)]
enum PureDisposition {
    Permit,
    Conditional,
    Deny {
        status: u16,
        reason: String,
        payload: Value,
    },
    Indeterminate {
        status: u16,
        reason: String,
        payload: Value,
    },
}

#[derive(Clone)]
enum SeparatedPolicyPlan {
    Active(ActivePolicyPlan),
    Candidate(CandidatePolicyPlan),
}

#[derive(Clone)]
pub(crate) struct PolicyEvaluation {
    snapshot_hash: String,
    route_id: Option<String>,
    disposition: PureDisposition,
    plan: SeparatedPolicyPlan,
    operation: Option<Value>,
    rewrite: Option<Value>,
    conditions: Vec<ConditionalIntent>,
    semantic_sha256: String,
}

impl PolicyEvaluation {
    fn active_plan(&self) -> Option<&ActivePolicyPlan> {
        match &self.plan {
            SeparatedPolicyPlan::Active(plan) => Some(plan),
            SeparatedPolicyPlan::Candidate(_) => None,
        }
    }

    fn candidate_plan(&self) -> Option<&CandidatePolicyPlan> {
        match &self.plan {
            SeparatedPolicyPlan::Candidate(plan) => Some(plan),
            SeparatedPolicyPlan::Active(_) => None,
        }
    }

    fn disposition_label(&self) -> &'static str {
        match &self.disposition {
            PureDisposition::Permit => "permit",
            PureDisposition::Conditional => "conditional",
            PureDisposition::Deny { .. } => "deny",
            PureDisposition::Indeterminate { .. } => "indeterminate",
        }
    }
}

fn canonical_digest(value: &Value) -> Result<Sha256Digest, String> {
    Sha256Digest::parse(digest_json_ensure_ascii(value)).map_err(shadow_error)
}

fn shadow_error(error: ShadowError) -> String {
    error.to_string()
}

fn policy_reason(payload: &Value, fallback: &str) -> String {
    payload
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

fn status_from_payload(payload: &Value, fallback: u16) -> u16 {
    payload
        .get("status_code")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .unwrap_or(fallback)
}

fn canonical_reason_identifier(reason: &str) -> Result<Identifier, String> {
    Identifier::parse(reason.to_string())
        .or_else(|_| {
            Identifier::parse(format!(
                "policy-reason-{}",
                sha256_prefixed(reason.as_bytes())
            ))
        })
        .map_err(shadow_error)
}

fn separated_plan(
    lane: PolicyLane,
    outcome: PolicyOutcome,
    rewrites: Vec<Sha256Digest>,
    validations: Vec<Sha256Digest>,
    conditions: &[ConditionalIntent],
) -> Result<SeparatedPolicyPlan, String> {
    let mut active = Vec::new();
    let mut candidate = Vec::new();
    for condition in conditions {
        match condition {
            ConditionalIntent::MaterializeCredential {
                credential_slot,
                destination,
            } => {
                let credential_slot =
                    Sha256Digest::parse(sha256_prefixed(credential_slot.as_bytes()))
                        .map_err(shadow_error)?;
                let destination = Identifier::parse(destination.clone()).map_err(shadow_error)?;
                active.push(ActiveEffectIntent::MaterializeCredential {
                    credential_slot_sha256: credential_slot.clone(),
                    destination: destination.clone(),
                });
                let lease_policy = canonical_digest(&json!({
                    "domain":"serverware.credentialLeaseRequirement/v1",
                    "credentialSlotSha256":credential_slot.as_str(),
                    "destination":destination.as_str(),
                }))?;
                let decryption_context = canonical_digest(&json!({
                    "domain":"serverware.credentialDecryptRequirement/v1",
                    "credentialSlotSha256":credential_slot.as_str(),
                    "destination":destination.as_str(),
                }))?;
                let injection_commitment = canonical_digest(&json!({
                    "domain":"serverware.credentialInjectionRequirement/v1",
                    "credentialSlotSha256":credential_slot.as_str(),
                    "destination":destination.as_str(),
                }))?;
                active.push(ActiveEffectIntent::AcquireCredentialLease {
                    credential_slot_sha256: credential_slot.clone(),
                    lease_policy_sha256: lease_policy.clone(),
                });
                active.push(ActiveEffectIntent::DecryptCredential {
                    credential_slot_sha256: credential_slot.clone(),
                    decryption_context_sha256: decryption_context.clone(),
                });
                active.push(ActiveEffectIntent::InjectCredential {
                    credential_slot_sha256: credential_slot.clone(),
                    injection_commitment_sha256: injection_commitment.clone(),
                });
                candidate.push(CandidateEffectIntent::WouldMaterializeCredential {
                    credential_slot_sha256: credential_slot.clone(),
                    destination: destination.clone(),
                });
                candidate.push(CandidateEffectIntent::WouldAcquireCredentialLease {
                    credential_slot_sha256: credential_slot.clone(),
                    lease_policy_sha256: lease_policy,
                });
                candidate.push(CandidateEffectIntent::WouldDecryptCredential {
                    credential_slot_sha256: credential_slot.clone(),
                    decryption_context_sha256: decryption_context,
                });
                candidate.push(CandidateEffectIntent::WouldInjectCredential {
                    credential_slot_sha256: credential_slot,
                    injection_commitment_sha256: injection_commitment,
                });
            }
            ConditionalIntent::ResolveCredentialVersion {
                credential_slot,
                credential_claim_sha256,
            } => {
                let credential_slot =
                    Sha256Digest::parse(sha256_prefixed(credential_slot.as_bytes()))
                        .map_err(shadow_error)?;
                let claim = Sha256Digest::parse(credential_claim_sha256.clone())
                    .map_err(shadow_error)?;
                active.push(ActiveEffectIntent::ResolveCredentialVersion {
                    credential_slot_sha256: credential_slot.clone(),
                    credential_claim_sha256: claim.clone(),
                });
                candidate.push(CandidateEffectIntent::WouldResolveCredentialVersion {
                    credential_slot_sha256: credential_slot,
                    credential_claim_sha256: claim,
                });
            }
            ConditionalIntent::RefreshOauthCredential {
                credential_slot,
                oauth_authority_sha256,
            }
            | ConditionalIntent::ExchangeOauthCredential {
                credential_slot,
                oauth_authority_sha256,
            }
            | ConditionalIntent::MintOauthCredential {
                credential_slot,
                oauth_authority_sha256,
            } => {
                let slot = Sha256Digest::parse(sha256_prefixed(
                    credential_slot.as_bytes(),
                ))
                .map_err(shadow_error)?;
                let authority = Sha256Digest::parse(
                    oauth_authority_sha256.clone(),
                )
                .map_err(shadow_error)?;
                match condition {
                    ConditionalIntent::RefreshOauthCredential { .. } => {
                        active.push(ActiveEffectIntent::RefreshOauthCredential {
                            credential_slot_sha256: slot.clone(),
                            oauth_authority_sha256: authority.clone(),
                        });
                        candidate.push(
                            CandidateEffectIntent::WouldRefreshOauthCredential {
                                credential_slot_sha256: slot,
                                oauth_authority_sha256: authority,
                            },
                        );
                    }
                    ConditionalIntent::ExchangeOauthCredential { .. } => {
                        active.push(ActiveEffectIntent::ExchangeOauthCredential {
                            credential_slot_sha256: slot.clone(),
                            oauth_authority_sha256: authority.clone(),
                        });
                        candidate.push(
                            CandidateEffectIntent::WouldExchangeOauthCredential {
                                credential_slot_sha256: slot,
                                oauth_authority_sha256: authority,
                            },
                        );
                    }
                    ConditionalIntent::MintOauthCredential { .. } => {
                        active.push(ActiveEffectIntent::MintOauthCredential {
                            credential_slot_sha256: slot.clone(),
                            oauth_authority_sha256: authority.clone(),
                        });
                        candidate.push(
                            CandidateEffectIntent::WouldMintOauthCredential {
                                credential_slot_sha256: slot,
                                oauth_authority_sha256: authority,
                            },
                        );
                    }
                    _ => unreachable!(),
                }
            }
            ConditionalIntent::BindIdempotencyKey {
                idempotency_commitment_sha256,
            } => {
                let commitment = Sha256Digest::parse(
                    idempotency_commitment_sha256.clone(),
                )
                .map_err(shadow_error)?;
                active.push(ActiveEffectIntent::BindIdempotencyKey {
                    idempotency_commitment_sha256: commitment.clone(),
                });
                candidate.push(CandidateEffectIntent::WouldBindIdempotencyKey {
                    idempotency_commitment_sha256: commitment,
                });
            }
            ConditionalIntent::ResolveRecoveryState {
                recovery_commitment_sha256,
            } => {
                let commitment =
                    Sha256Digest::parse(recovery_commitment_sha256.clone())
                        .map_err(shadow_error)?;
                active.push(ActiveEffectIntent::ResolveRecoveryState {
                    recovery_commitment_sha256: commitment.clone(),
                });
                candidate.push(
                    CandidateEffectIntent::WouldResolveRecoveryState {
                        recovery_commitment_sha256: commitment,
                    },
                );
            }
            ConditionalIntent::RequireGmailPriorSearchProof {
                route_id,
                gmail_user,
                message_id_sha256,
                maximum_age_days,
            } => {
                let route_sha256 =
                    Sha256Digest::parse(sha256_prefixed(route_id.as_bytes())).map_err(shadow_error)?;
                let gmail_user_sha256 =
                    Sha256Digest::parse(sha256_prefixed(gmail_user.as_bytes()))
                        .map_err(shadow_error)?;
                let message_id_sha256 =
                    Sha256Digest::parse(message_id_sha256.clone()).map_err(shadow_error)?;
                active.push(ActiveEffectIntent::RequireGmailPriorSearchProof {
                    route_sha256: route_sha256.clone(),
                    gmail_user_sha256: gmail_user_sha256.clone(),
                    message_id_sha256: message_id_sha256.clone(),
                    maximum_age_days: *maximum_age_days,
                });
                candidate.push(CandidateEffectIntent::WouldRequireGmailPriorSearchProof {
                    route_sha256,
                    gmail_user_sha256,
                    message_id_sha256,
                    maximum_age_days: *maximum_age_days,
                });
            }
            ConditionalIntent::ResolveGmailMetadataFanout {
                route_id,
                maximum_age_days,
                maximum_messages,
            } => {
                let route_sha256 =
                    Sha256Digest::parse(sha256_prefixed(route_id.as_bytes()))
                        .map_err(shadow_error)?;
                active.push(ActiveEffectIntent::ResolveGmailMetadataFanout {
                    route_sha256: route_sha256.clone(),
                    maximum_age_days: *maximum_age_days,
                    maximum_messages: *maximum_messages,
                });
                candidate.push(CandidateEffectIntent::WouldUseActiveGmailMetadataEvidence {
                    route_sha256,
                    maximum_age_days: *maximum_age_days,
                    maximum_messages: *maximum_messages,
                });
            }
            ConditionalIntent::RequireJitApproval { policy_sha256 } => {
                let digest = Sha256Digest::parse(policy_sha256.clone()).map_err(shadow_error)?;
                active.push(ActiveEffectIntent::RequireJitApproval {
                    approval_policy_sha256: digest.clone(),
                });
                candidate.push(CandidateEffectIntent::WouldRequireJitApproval {
                    approval_policy_sha256: digest,
                });
            }
            ConditionalIntent::ReserveQuota {
                counter_sha256,
                claim_sha256,
                weighted_units,
            } => {
                let counter =
                    Sha256Digest::parse(counter_sha256.clone()).map_err(shadow_error)?;
                let claim = Sha256Digest::parse(claim_sha256.clone()).map_err(shadow_error)?;
                active.push(ActiveEffectIntent::ReserveQuota {
                    counter_sha256: counter.clone(),
                    claim_sha256: claim.clone(),
                    weighted_units: *weighted_units,
                });
                candidate.push(CandidateEffectIntent::WouldReserveQuota {
                    counter_sha256: counter,
                    claim_sha256: claim,
                    weighted_units: *weighted_units,
                });
            }
            ConditionalIntent::ReserveDurableBudget {
                budget_sha256,
                claim_sha256,
                weighted_units,
            } => {
                let budget = Sha256Digest::parse(budget_sha256.clone()).map_err(shadow_error)?;
                let claim = Sha256Digest::parse(claim_sha256.clone()).map_err(shadow_error)?;
                active.push(ActiveEffectIntent::ReserveDurableBudget {
                    budget_sha256: budget.clone(),
                    claim_sha256: claim.clone(),
                    weighted_units: *weighted_units,
                });
                candidate.push(CandidateEffectIntent::WouldReserveDurableBudget {
                    budget_sha256: budget,
                    claim_sha256: claim,
                    weighted_units: *weighted_units,
                });
            }
        }
    }
    match lane {
        PolicyLane::Active => ActivePolicyPlan::new(outcome, rewrites, validations, active)
            .map(SeparatedPolicyPlan::Active)
            .map_err(shadow_error),
        PolicyLane::Candidate => {
            CandidatePolicyPlan::new_shadow_only(outcome, rewrites, validations, candidate)
                .map(SeparatedPolicyPlan::Candidate)
                .map_err(shadow_error)
        }
    }
}

fn terminal_evaluation(
    snapshot: &PolicyPlanSnapshot,
    status: u16,
    payload: Value,
    indeterminate: bool,
) -> Result<PolicyEvaluation, String> {
    let reason = policy_reason(
        &payload,
        if indeterminate {
            "policy_evaluation_indeterminate"
        } else {
            "policy_denied"
        },
    );
    let outcome = if indeterminate {
        PolicyOutcome::Indeterminate {
            reason: canonical_reason_identifier(&reason)?,
        }
    } else {
        PolicyOutcome::Deny {
            reason: canonical_reason_identifier(&reason)?,
        }
    };
    let plan = separated_plan(snapshot.lane, outcome, Vec::new(), Vec::new(), &[])?;
    let semantic_sha256 = match &plan {
        SeparatedPolicyPlan::Active(plan) => plan.semantic_commitment().map_err(shadow_error)?,
        SeparatedPolicyPlan::Candidate(plan) => {
            plan.semantic_commitment().map_err(shadow_error)?
        }
    }
    .as_str()
    .to_string();
    Ok(PolicyEvaluation {
        snapshot_hash: snapshot.snapshot.hash.clone(),
        route_id: None,
        disposition: if indeterminate {
            PureDisposition::Indeterminate {
                status,
                reason,
                payload,
            }
        } else {
            PureDisposition::Deny {
                status,
                reason,
                payload,
            }
        },
        plan,
        operation: None,
        rewrite: None,
        conditions: Vec::new(),
        semantic_sha256,
    })
}

fn denied(
    snapshot: &PolicyPlanSnapshot,
    payload: Value,
    fallback_status: u16,
) -> Result<PolicyEvaluation, String> {
    terminal_evaluation(
        snapshot,
        status_from_payload(&payload, fallback_status),
        payload,
        false,
    )
}

fn indeterminate(
    snapshot: &PolicyPlanSnapshot,
    error: &str,
) -> Result<PolicyEvaluation, String> {
    terminal_evaluation(
        snapshot,
        503,
        json!({
            "error":"pure_policy_evaluation_indeterminate",
            "detail_sha256":sha256_prefixed(error.as_bytes()),
            "status_code":503,
        }),
        true,
    )
}

fn pure_validate_adapter(
    request: &DecisionRequest,
    forwarded_headers: &BTreeMap<String, String>,
    url: &Url,
    route_match: &RouteMatch<'_>,
) -> Result<(Value, Value, Option<ConditionalIntent>), Value> {
    let route = route_match.route;
    let mut gmail_condition = None;
    if route.adapter_type == "gmail.v1"
        && route_match.params.contains_key("message_id")
        && route
            .adapter_config
            .get("allowMessageGetOnlyFromPriorSearch")
            .and_then(Value::as_bool)
            .unwrap_or(true)
    {
        let message_id = route_match
            .params
            .get("message_id")
            .filter(|value| canonical_gmail_message_id(value))
            .ok_or_else(|| json!({"error":"gmail_message_id_invalid"}))?;
        let gmail_user = route_match
            .params
            .get("user")
            .filter(|value| canonical_gmail_user(value))
            .ok_or_else(|| json!({"error":"gmail_user_id_invalid"}))?;
        gmail_condition = Some(ConditionalIntent::RequireGmailPriorSearchProof {
            route_id: route.id.clone(),
            gmail_user: gmail_user.clone(),
            message_id_sha256: sha256_prefixed(message_id.as_bytes()),
            maximum_age_days: config_u64(&route.adapter_config, "maxAgeDays", 30),
        });
    }
    validate_adapter_deferred_gmail_proof(request, forwarded_headers, url, route_match)
        .map(|(operation, rewrite)| (operation, rewrite, gmail_condition))
}

fn response_validation_commitments(route: &Route) -> Result<Vec<Sha256Digest>, String> {
    let mut by_digest = BTreeMap::new();
    for constraint in &route.constraints {
        if constraint_phase_includes(constraint, "response") {
            let digest = canonical_digest(constraint)?;
            by_digest.insert(digest.as_str().to_string(), digest);
        }
    }
    Ok(by_digest.into_values().collect())
}

fn credential_destination(injection: &Value) -> Result<String, String> {
    match credential_injection_target(injection)? {
        CredentialInjectionTarget::Header(name) => {
            Ok(format!("header.{}", sha256_prefixed(name.as_bytes())))
        }
        CredentialInjectionTarget::Query(name) => {
            Ok(format!("query.{}", sha256_prefixed(name.as_bytes())))
        }
    }
}

fn effect_conditions(
    snapshot: &Snapshot,
    route: &Route,
    request: &DecisionRequest,
    canonical_request: &Value,
    principal_id: &str,
    credential_version: Option<u64>,
    operation: &Value,
    gmail_condition: Option<ConditionalIntent>,
) -> Result<Vec<ConditionalIntent>, String> {
    let mut conditions = Vec::new();
    if let Some(credential_id) = route.credential_ref.as_ref() {
        let credential = snapshot
            .credentials
            .get(credential_id.as_str())
            .ok_or("compiled route credential is missing")?;
        conditions.push(ConditionalIntent::MaterializeCredential {
            credential_slot: credential_id.clone(),
            destination: credential_destination(&credential.injection)?,
        });
        conditions.push(ConditionalIntent::ResolveCredentialVersion {
            credential_slot: credential_id.clone(),
            credential_claim_sha256: canonical_digest(&json!({
                "domain":"serverware.policyShadowCredentialResolutionClaim/v1",
                "credentialSlotSha256":sha256_prefixed(credential_id.as_bytes()),
                "providerSha256":sha256_prefixed(credential.provider.as_bytes()),
                "providerSubjectSha256":credential
                    .provider_subject
                    .as_ref()
                    .map(|subject| sha256_prefixed(subject.as_bytes())),
                "resolvedVersion":credential_version,
            }))?
            .as_str()
            .to_string(),
        });
        if credential.kind() == "oauth2" {
            let oauth_authority_sha256 = canonical_digest(&json!({
                "domain":"serverware.policyShadowOauthAuthority/v1",
                "credentialSlotSha256":sha256_prefixed(
                    credential_id.as_bytes()
                ),
                "providerSha256":sha256_prefixed(
                    credential.provider.as_bytes()
                ),
                "providerSubjectSha256":credential
                    .provider_subject
                    .as_ref()
                    .map(|subject| sha256_prefixed(subject.as_bytes())),
                "oauthClientIdSha256":credential
                    .oauth_client_id()
                    .map(|client| sha256_prefixed(client.as_bytes())),
                "grantedScopesRootSha256":canonical_digest(&json!(
                    credential.scopes().collect::<Vec<_>>()
                ))?,
            }))?
            .as_str()
            .to_string();
            match credential
                .injection
                .get("__serverwareOAuthOperation")
                .and_then(Value::as_str)
                .unwrap_or("exchange")
            {
                "refresh" => {
                    conditions.push(
                        ConditionalIntent::RefreshOauthCredential {
                            credential_slot: credential_id.clone(),
                            oauth_authority_sha256,
                        },
                    );
                }
                "exchange" => {
                    conditions.push(
                        ConditionalIntent::ExchangeOauthCredential {
                            credential_slot: credential_id.clone(),
                            oauth_authority_sha256,
                        },
                    );
                }
                "mint" => {
                    conditions.push(ConditionalIntent::MintOauthCredential {
                        credential_slot: credential_id.clone(),
                        oauth_authority_sha256,
                    });
                }
                _ => {
                    return Err(
                        "compiled OAuth credential operation is invalid"
                            .to_string(),
                    );
                }
            }
        }
    }
    if let Some(idempotency_key) = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"))
        .map(|(_, value)| value)
    {
        conditions.push(ConditionalIntent::BindIdempotencyKey {
            idempotency_commitment_sha256: canonical_digest(&json!({
                "domain":"serverware.policyShadowIdempotencyBinding/v1",
                "routeSha256":sha256_prefixed(route.id.as_bytes()),
                "principalSha256":sha256_prefixed(principal_id.as_bytes()),
                "operationSha256":canonical_digest(operation)?,
                "idempotencyKeySha256":sha256_prefixed(
                    idempotency_key.as_bytes()
                ),
            }))?
            .as_str()
            .to_string(),
        });
    }
    if matches!(
        operation_name(operation),
        "write" | "publish" | "delete" | "administrative"
    ) || !matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS")
    {
        conditions.push(ConditionalIntent::ResolveRecoveryState {
            recovery_commitment_sha256: canonical_digest(&json!({
                "domain":"serverware.policyShadowRecoveryResolution/v1",
                "routeSha256":sha256_prefixed(route.id.as_bytes()),
                "principalSha256":sha256_prefixed(principal_id.as_bytes()),
                "operationSha256":canonical_digest(operation)?,
                "method":request.method.as_str(),
                "clientRequestDigest":
                    request.client_request_digest.as_deref(),
            }))?
            .as_str()
            .to_string(),
        });
    }
    if let Some(condition) = gmail_condition {
        conditions.push(condition);
    }
    if operation
        .get("operation")
        .and_then(Value::as_str)
        == Some("gmail.messages.list")
    {
        if let Some(config) = gmail_metadata_fetch_for_route(route) {
            conditions.push(ConditionalIntent::ResolveGmailMetadataFanout {
                route_id: route.id.clone(),
                maximum_age_days: config_u64(&route.adapter_config, "maxAgeDays", 30),
                maximum_messages: config.max_messages,
            });
        }
    }
    if route
        .jit
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        conditions.push(ConditionalIntent::RequireJitApproval {
            policy_sha256: canonical_digest(&route.jit)?.as_str().to_string(),
        });
    }
    let exact_credential_version = credential_version.unwrap_or(0);
    for quota in expected_shared_release_authorization_quotas(
        route,
        principal_id,
        route.credential_ref.as_deref(),
        exact_credential_version,
        operation,
    )? {
        let counter_sha256 = Sha256Digest::parse(sha256_prefixed(quota.counter_key.as_bytes()))
            .map_err(shadow_error)?
            .as_str()
            .to_string();
        let claim = serde_json::to_value(&quota)
            .map_err(|_| "serialize exact shared quota claim".to_string())?;
        let claim_sha256 = canonical_digest(&json!({
            "domain":"serverware.policyShadowExactQuotaClaim/v1",
            "credentialVersionResolved":credential_version.is_some(),
            "claim":claim,
        }))?
        .as_str()
        .to_string();
        conditions.push(ConditionalIntent::ReserveQuota {
            counter_sha256,
            claim_sha256,
            weighted_units: 1,
        });
    }
    for constraint in &route.constraints {
        if constraint.get("type").and_then(Value::as_str) != Some("rateLimit")
            || constraint.get("store").and_then(Value::as_str) == Some("shared")
            || !constraint_phase_includes(constraint, "request")
        {
            continue;
        }
        let counter_key = rate_limit_key(
            constraint,
            route,
            principal_id,
            route.credential_ref.as_deref(),
            exact_credential_version,
            operation,
        );
        conditions.push(ConditionalIntent::ReserveQuota {
            counter_sha256: sha256_prefixed(counter_key.as_bytes()),
            claim_sha256: canonical_digest(&json!({
                "domain":"serverware.policyShadowExactLocalQuotaClaim/v1",
                "constraint":constraint,
                "counterKey":counter_key,
                "policyHash":snapshot.hash,
                "principalId":principal_id,
                "routeId":route.id,
                "credentialId":route.credential_ref,
                "credentialVersion":exact_credential_version,
                "credentialVersionResolved":credential_version.is_some(),
                "operation":operation_name(operation),
            }))?
            .as_str()
            .to_string(),
            weighted_units: 1,
        });
    }
    for constraint in &route.constraints {
        let kind = constraint.get("type").and_then(Value::as_str);
        let claim = match kind {
            Some("slidingWindowLimit" | "weightedBudget") => Some(durable_budget_claim(
                constraint,
                route,
                principal_id,
                route.credential_ref.as_deref(),
                exact_credential_version,
                &snapshot.hash,
                operation,
            )?),
            Some("traversalBudget") => traversal_budget_claim(
                constraint,
                route,
                request,
                canonical_request,
                principal_id,
                route.credential_ref.as_deref(),
                exact_credential_version,
                &snapshot.hash,
                operation,
            )?,
            _ => None,
        };
        if let Some(claim) = claim {
            let weighted_units = claim
                .get("units")
                .or_else(|| claim.get("request_units"))
                .and_then(Value::as_u64)
                .unwrap_or(1);
            let budget_key = claim
                .get("budget_key")
                .or_else(|| claim.get("counter_key"))
                .or_else(|| claim.get("chain_key"))
                .and_then(Value::as_str)
                .ok_or("durable budget claim key is missing")?;
            let budget_sha256 = sha256_prefixed(budget_key.as_bytes());
            let claim_sha256 = canonical_digest(&json!({
                "domain":"serverware.policyShadowExactDurableClaim/v1",
                "credentialVersionResolved":credential_version.is_some(),
                "claim":claim,
            }))?
            .as_str()
            .to_string();
            conditions.push(ConditionalIntent::ReserveDurableBudget {
                budget_sha256,
                claim_sha256,
                weighted_units,
            });
        }
    }
    Ok(conditions)
}

/// The single pure policy path used for active and candidate snapshots.
///
/// All request time enters through `context`; this function performs no I/O,
/// reads no clock, mutates no shared state, and owns no effect capability.
pub(crate) fn evaluate_policy_plan(
    snapshot: &PolicyPlanSnapshot,
    admitted_facts: &AdmittedRequestFacts,
    context: PolicyEvaluationContext,
) -> Result<PolicyEvaluation, String> {
    let request = match admitted_facts.to_decision_request() {
        Ok(request) => request,
        Err(error) => return indeterminate(snapshot, &error),
    };
    evaluate_policy_plan_request(
        snapshot,
        request,
        admitted_facts.authenticated_principal_id.as_deref(),
        admitted_facts.ingress,
        admitted_facts.captured_at_epoch_ms,
        context,
    )
}

fn evaluate_policy_plan_borrowed(
    snapshot: &PolicyPlanSnapshot,
    request: &DecisionRequest,
    authenticated_principal_id: Option<&str>,
    ingress: ShadowIngressKind,
    captured_at_epoch_ms: u64,
    context: PolicyEvaluationContext,
) -> Result<PolicyEvaluation, String> {
    evaluate_policy_plan_request(
        snapshot,
        request.clone(),
        authenticated_principal_id,
        ingress,
        captured_at_epoch_ms,
        context,
    )
}

fn evaluate_policy_plan_request(
    snapshot: &PolicyPlanSnapshot,
    mut request: DecisionRequest,
    authenticated_principal_id: Option<&str>,
    ingress: ShadowIngressKind,
    captured_at_epoch_ms: u64,
    context: PolicyEvaluationContext,
) -> Result<PolicyEvaluation, String> {
    if context.lane != snapshot.lane
        || context.captured_at_epoch_ms != captured_at_epoch_ms
        || context.decision_at_epoch_ms < context.captured_at_epoch_ms
    {
        return indeterminate(snapshot, "policy evaluation context binding mismatch");
    }
    if !ingress.is_matched_http() {
        return indeterminate(snapshot, "non-HTTP ingress cannot be policy evaluated");
    }
    if validate_canonical_http_method(&request.method).is_err() {
        return denied(
            snapshot,
            json!({"error":"noncanonical_method","status_code":400}),
            400,
        );
    }
    if validate_identity_request_content_encoding(&request.headers).is_err() {
        return denied(
            snapshot,
            json!({"error":"request_content_encoding_denied","status_code":415}),
            415,
        );
    }
    let admitted_headers = match discard_declared_request_headers(&request.headers, &[]) {
        Ok(headers) => headers,
        Err(_) => {
            return denied(
                snapshot,
                json!({"error":"invalid_request_headers","status_code":400}),
                400,
            )
        }
    };
    replace_string_map(&mut request.headers, admitted_headers);
    if enrollment_session_id_from_headers(&request.headers).is_err() {
        return denied(
            snapshot,
            json!({"error":"invalid_enrollment_session_header","status_code":400}),
            400,
        );
    }
    let normalized_headers = lower_headers(&request.headers);
    let (path_validation, url) = match parse_validated_absolute_target(&request.url) {
        Ok(validated) => validated,
        Err(_) => {
            return denied(
                snapshot,
                json!({"error":"invalid_request_target","status_code":400}),
                400,
            )
        }
    };
    if duplicate_query_key(&url).is_some() {
        return denied(
            snapshot,
            json!({"error":"duplicate_query_key_denied","status_code":400}),
            400,
        );
    }
    let compiled = snapshot.snapshot.as_ref();
    let principal = if let Some(principal_id) = authenticated_principal_id {
        compiled
            .principals
            .iter()
            .find(|principal| principal.id == principal_id)
    } else {
        compiled.principals.iter().find(|principal| principal.matches_at(
            request.client_ip.as_deref(), &normalized_headers, None,
            u128::from(context.decision_at_epoch_ms),
        ))
    };
    let Some(principal) = principal else {
        return denied(
            snapshot,
            json!({"error":"client_principal_denied","status_code":403}),
            403,
        );
    };
    let Some(route_match) = compiled.match_route(&principal.id, &request.method, &url) else {
        return denied(
            snapshot,
            json!({"error":"unknown_route_denied","status_code":403}),
            403,
        );
    };
    let route = route_match.route;
    for validation in [
        validate_route_response_release_mode(route),
        validate_runtime_route_identity_headers(route, principal),
        validate_runtime_route_discard_headers(compiled, route, principal),
    ] {
        if validation.is_err() {
            return indeterminate(snapshot, "compiled runtime route invariant failed");
        }
    }
    let identity_stripped = strip_principal_required_headers(&request.headers, principal);
    replace_string_map(&mut request.headers, identity_stripped);
    let retained = match discard_declared_request_headers(&request.headers, &route.discard_headers)
    {
        Ok(headers) => headers,
        Err(_) => {
            return denied(
                snapshot,
                json!({"error":"invalid_request_headers","status_code":400}),
                400,
            )
        }
    };
    replace_string_map(&mut request.headers, retained);
    let normalized_headers = lower_headers(&request.headers);
    if path_validation.has_encoded_slash && route.adapter_type != "npm.registry" {
        return denied(
            snapshot,
            json!({"error":"encoded_path_separator_denied","status_code":400}),
            400,
        );
    }
    if let Err(payload) = validate_runtime_credential_body_policy(route) {
        return denied(snapshot, payload, 500);
    }
    if let Err(payload) = validate_provider_request_admission(&request, &url, route) {
        return denied(snapshot, payload, 403);
    }
    let injection = match route.credential_ref.as_ref() {
        Some(credential_id) => match compiled.credentials.get(credential_id) {
            Some(credential) => credential.injection.clone(),
            None => return indeterminate(snapshot, "compiled route credential is missing"),
        },
        None => Value::Null,
    };
    if route.credential_ref.is_some() {
        if let Err(payload) =
            reject_credential_injection_collision(&request.headers, &url, &injection)
        {
            return denied(snapshot, payload, 403);
        }
    }
    let body_length = match decision_request_body_length(&request) {
        Ok(length) => length,
        Err(_) => {
            return denied(
                snapshot,
                json!({"error":"invalid_request_framing","status_code":400}),
                400,
            )
        }
    };
    let mut forwarded_headers = match canonical_forwarded_request_headers(
        &request.headers,
        &url,
        body_length,
        &injection,
    ) {
        Ok(headers) => headers,
        Err(_) => {
            return denied(
                snapshot,
                json!({"error":"invalid_forwarding_headers","status_code":400}),
                400,
            )
        }
    };
    let proof_requested = normalized_headers.contains_key(RESPONSE_PROOF_NONCE_HEADER)
        || normalized_headers.contains_key(STREAM_RESPONSE_PROOF_NONCE_HEADER)
        || normalized_headers.contains_key(RESPONSE_OBSERVATION_NONCE_HEADER);
    if proof_requested != request.client_request_digest.is_some() {
        return denied(
            snapshot,
            json!({"error":"invalid_response_proof_request_binding","status_code":400}),
            400,
        );
    }
    let (mut operation, rewrite, gmail_condition) =
        match pure_validate_adapter(&request, &forwarded_headers, &url, &route_match) {
            Ok(context) => context,
            Err(payload) => return denied(snapshot, payload, 403),
        };
    let mut provider_url = url.clone();
    if apply_rewrite(&mut provider_url, &rewrite).is_err()
        || duplicate_query_key(&provider_url).is_some()
    {
        return indeterminate(snapshot, "adapter rewrite is invalid");
    }
    let Some(provider_route_match) =
        compiled.match_route(&principal.id, &request.method, &provider_url)
    else {
        return indeterminate(snapshot, "adapter rewrite moved outside route");
    };
    if provider_route_match.route.id != route.id {
        return indeterminate(snapshot, "adapter rewrite changed route");
    }
    if let Err(payload) =
        validate_provider_request_admission(&request, &provider_url, provider_route_match.route)
    {
        return denied(snapshot, payload, 403);
    }
    let (revalidated_operation, revalidated_rewrite, revalidated_gmail_condition) =
        match pure_validate_adapter(
            &request,
            &forwarded_headers,
            &provider_url,
            &provider_route_match,
        ) {
            Ok(context) => context,
            Err(payload) => return denied(snapshot, payload, 403),
        };
    let mut converged = provider_url.clone();
    if apply_rewrite(&mut converged, &revalidated_rewrite).is_err()
        || converged != provider_url
        || revalidated_operation != operation
        || revalidated_gmail_condition.is_some() != gmail_condition.is_some()
    {
        return indeterminate(snapshot, "adapter rewrite did not converge");
    }
    if let Err(payload) =
        reject_credential_injection_collision(&request.headers, &provider_url, &injection)
    {
        return denied(snapshot, payload, 403);
    }
    let credential_policy = route
        .credential_ref
        .as_ref()
        .and_then(|credential_id| compiled.credentials.get(credential_id));
    if let Err(payload) = bind_provider_account_scope(route, credential_policy, &mut operation) {
        return denied(snapshot, payload, 500);
    }
    if let Err(payload) = evaluate_request_semantic_constraints_at_ms(
        route,
        &request,
        &normalized_headers,
        &provider_url,
        &provider_route_match.params,
        &mut operation,
        i128::from(context.decision_at_epoch_ms),
    ) {
        return denied(snapshot, payload, 403);
    }
    if let Err(payload) = validate_response_binding_sources(route, &operation) {
        return denied(snapshot, payload, 403);
    }
    forwarded_headers = match strip_identity_request_content_encoding(&forwarded_headers) {
        Ok(headers) => headers,
        Err(_) => return indeterminate(snapshot, "forwarded content encoding drifted"),
    };
    let resolved_credential_version = route
        .credential_ref
        .as_deref()
        .filter(|credential| {
            context.resolved_credential_slot.as_deref() == Some(*credential)
        })
        .and(context.resolved_credential_version);
    let credential_version = resolved_credential_version.unwrap_or(0);
    let canonical = canonical_request(
        &request,
        &forwarded_headers,
        &provider_url,
        principal,
        route,
        credential_version,
        &compiled.hash,
        &operation,
    );
    let conditions = effect_conditions(
        compiled,
        route,
        &request,
        &canonical,
        &principal.id,
        resolved_credential_version,
        &operation,
        gmail_condition,
    )?;
    let disposition = if conditions.iter().any(ConditionalIntent::requires_resolution) {
        PureDisposition::Conditional
    } else {
        PureDisposition::Permit
    };
    let outcome = if conditions.iter().any(ConditionalIntent::requires_resolution) {
        PolicyOutcome::Conditional {
            reason: Identifier::parse("effect-resolution-required").map_err(shadow_error)?,
        }
    } else {
        PolicyOutcome::Permit
    };
    let rewrites = if rewrite.as_object().is_some_and(|object| object.is_empty()) {
        Vec::new()
    } else {
        vec![canonical_digest(&rewrite)?]
    };
    let mut validations = response_validation_commitments(route)?;
    if !conditions.is_empty() {
        let typed_conditions = serde_json::to_value(&conditions)
            .map_err(|_| "serialize typed conditions".to_string())?;
        validations.push(canonical_digest(&json!({
            "domain":"serverware.policyTypedConditions/v1",
            "conditions":typed_conditions,
        }))?);
        validations.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        validations.dedup_by(|left, right| left.as_str() == right.as_str());
    }
    let plan = separated_plan(snapshot.lane, outcome, rewrites, validations, &conditions)?;
    let semantic_sha256 = match &plan {
        SeparatedPolicyPlan::Active(plan) => plan.semantic_commitment().map_err(shadow_error)?,
        SeparatedPolicyPlan::Candidate(plan) => {
            plan.semantic_commitment().map_err(shadow_error)?
        }
    }
    .as_str()
    .to_string();
    Ok(PolicyEvaluation {
        snapshot_hash: compiled.hash.clone(),
        route_id: Some(route.id.clone()),
        disposition,
        plan,
        operation: Some(operation),
        rewrite: Some(rewrite),
        conditions,
        semantic_sha256,
    })
}

#[derive(Clone)]
pub(crate) struct ShadowAdmission {
    snapshot_sha256: String,
    snapshot_identity_ptr: usize,
    snapshot_epoch: u64,
    policy_sequence: u64,
    rollback_epoch: u64,
    request_binding_sha256: String,
    ingress: ShadowIngressKind,
    captured_at_epoch_ms: u64,
    inactive: bool,
    custody_fail_closed: bool,
    active_projection: Option<Arc<PolicyPlanSnapshot>>,
    active_evaluation: Option<PolicyEvaluation>,
    capture_error_sha256: Option<String>,
    finalization: Option<ShadowRequestHandle>,
}

impl ShadowAdmission {
    fn inactive(snapshot: &Arc<Snapshot>, ingress: ShadowIngressKind) -> Self {
        Self {
            snapshot_sha256: String::new(),
            snapshot_identity_ptr: Arc::as_ptr(snapshot) as usize,
            snapshot_epoch: snapshot.epoch,
            policy_sequence: snapshot.policy_sequence,
            rollback_epoch: snapshot.rollback_epoch,
            request_binding_sha256: String::new(),
            ingress,
            captured_at_epoch_ms: 0,
            inactive: true,
            custody_fail_closed: false,
            active_projection: None,
            active_evaluation: None,
            capture_error_sha256: None,
            finalization: None,
        }
    }

    fn captured(
        snapshot_sha256: String,
        policy_sequence: u64,
        rollback_epoch: u64,
        request_binding_sha256: String,
        ingress: ShadowIngressKind,
        captured_at_epoch_ms: u64,
        active_projection: Arc<PolicyPlanSnapshot>,
        active_evaluation: PolicyEvaluation,
    ) -> Self {
        Self {
            snapshot_sha256,
            snapshot_identity_ptr: 0,
            snapshot_epoch: 0,
            policy_sequence,
            rollback_epoch,
            request_binding_sha256,
            ingress,
            captured_at_epoch_ms,
            inactive: false,
            custody_fail_closed: false,
            active_projection: Some(active_projection),
            active_evaluation: Some(active_evaluation),
            capture_error_sha256: None,
            finalization: None,
        }
    }

    fn failed(
        snapshot: &Arc<Snapshot>,
        request_binding_sha256: String,
        ingress: ShadowIngressKind,
        captured_at_epoch_ms: u64,
        error: &str,
    ) -> Self {
        Self {
            snapshot_sha256: snapshot.hash.clone(),
            snapshot_identity_ptr: Arc::as_ptr(snapshot) as usize,
            snapshot_epoch: snapshot.epoch,
            policy_sequence: snapshot.policy_sequence,
            rollback_epoch: snapshot.rollback_epoch,
            request_binding_sha256,
            ingress,
            captured_at_epoch_ms,
            inactive: false,
            custody_fail_closed: false,
            active_projection: None,
            active_evaluation: None,
            capture_error_sha256: Some(sha256_prefixed(error.as_bytes())),
            finalization: None,
        }
    }

    pub(crate) fn bind_decision_time(
        mut self,
        snapshot: &Arc<Snapshot>,
        request: &DecisionRequest,
        authenticated_principal_id: Option<&str>,
        decision_at_epoch_ms: u128,
    ) -> Self {
        if self.inactive {
            return self;
        }
        let decision_at_epoch_ms = match checked_epoch_ms(decision_at_epoch_ms) {
            Ok(value) => value,
            Err(error) => {
                self.capture_error_sha256 = Some(sha256_prefixed(error.as_bytes()));
                self.active_evaluation = None;
                return self;
            }
        };
        let Some(projection) = self.active_projection.as_ref().filter(|projection| {
            projection.snapshot.hash == snapshot.hash
                && projection.snapshot.epoch == snapshot.epoch
                && projection.snapshot.policy_sequence == snapshot.policy_sequence
                && projection.snapshot.rollback_epoch == snapshot.rollback_epoch
        }) else {
            self.capture_error_sha256 =
                Some(sha256_prefixed(b"cached active policy projection changed"));
            self.active_evaluation = None;
            return self;
        };
        match evaluate_policy_plan_borrowed(
            projection,
            request,
            authenticated_principal_id,
            if request_binding(snapshot, request, authenticated_principal_id)
                != self.request_binding_sha256
            {
                self.capture_error_sha256 =
                    Some(sha256_prefixed(b"decision request binding changed"));
                self.active_evaluation = None;
                return self;
            } else {
                self.ingress
            },
            self.captured_at_epoch_ms,
            PolicyEvaluationContext::active(
                self.captured_at_epoch_ms,
                decision_at_epoch_ms,
                None,
            ),
        ) {
            Ok(active) => {
                let finalization_error: Option<(&'static [u8], bool)> = if let Some(handle) =
                    self.finalization.as_ref()
                {
                    if let Ok(mut state) = handle.inner.state.try_lock() {
                        let requirements = active
                            .active_plan()
                            .map(ActiveEffectRequirements::from_plan);
                        if let Some(effect_requirements) = requirements {
                            if !state.credential_prerequisites.permits_binding(
                                &active.semantic_sha256, decision_at_epoch_ms,
                            ) {
                                Some((b"decision-time binding is frozen by credential prerequisites", false))
                            } else {
                                state.decision_time_binding =
                                    Some(DecisionTimeBinding {
                                        decision_at_epoch_ms,
                                        active_plan_sha256:
                                            active.semantic_sha256.clone(),
                                        effect_requirements,
                                        active_evaluation: active.clone(),
                                    });
                                None
                            }
                        } else {
                            Some((b"decision-time active plan is unavailable", false))
                        }
                    } else {
                        let custody_fail_closed = !handle
                            .record_failure(PolicyShadowTerminalReason::TerminalStateContention);
                        Some((
                            b"decision-time lifecycle state is busy",
                            custody_fail_closed,
                        ))
                    }
                } else {
                    None
                };
                if let Some((error, custody_fail_closed)) = finalization_error {
                    self.custody_fail_closed |= custody_fail_closed;
                    self.capture_error_sha256 = Some(sha256_prefixed(error));
                    self.active_evaluation = None;
                    return self;
                }
                self.active_evaluation = Some(active);
            }
            Err(error) => {
                self.capture_error_sha256 = Some(sha256_prefixed(error.as_bytes()));
                self.active_evaluation = None;
            }
        }
        self
    }

    pub(crate) fn finalization_handle(&self) -> Option<ShadowRequestHandle> {
        self.finalization.clone()
    }

    fn custody_fail_closed(
        snapshot: &Arc<Snapshot>,
        request_binding_sha256: String,
        ingress: ShadowIngressKind,
        reason: PolicyShadowTerminalReason,
    ) -> Self {
        Self {
            snapshot_sha256: snapshot.hash.clone(),
            snapshot_identity_ptr: Arc::as_ptr(snapshot) as usize,
            snapshot_epoch: snapshot.epoch,
            policy_sequence: snapshot.policy_sequence,
            rollback_epoch: snapshot.rollback_epoch,
            request_binding_sha256,
            ingress,
            captured_at_epoch_ms: 0,
            inactive: false,
            custody_fail_closed: true,
            active_projection: None,
            active_evaluation: None,
            capture_error_sha256: Some(sha256_prefixed(
                reason.label().as_bytes(),
            )),
            finalization: None,
        }
    }

    pub(crate) fn must_fail_closed(&self) -> bool {
        self.custody_fail_closed
    }

    pub(crate) fn may_prepare_upstream(&self) -> bool {
        !self.custody_fail_closed
    }

    pub(crate) fn matches(
        &self,
        snapshot: &Arc<Snapshot>,
        request: &DecisionRequest,
        authenticated_principal_id: Option<&str>,
    ) -> bool {
        (if self.inactive {
            self.snapshot_identity_ptr == Arc::as_ptr(snapshot) as usize
                && self.snapshot_epoch == snapshot.epoch
                && self.policy_sequence == snapshot.policy_sequence
                && self.rollback_epoch == snapshot.rollback_epoch
        } else {
            self.snapshot_sha256 == snapshot.hash
                && self.policy_sequence == snapshot.policy_sequence
                && self.rollback_epoch == snapshot.rollback_epoch
        }) && (self.inactive
            || request_binding(snapshot, request, authenticated_principal_id)
                == self.request_binding_sha256)
            && self
                .active_evaluation
                .as_ref()
                .is_none_or(|evaluation| evaluation.snapshot_hash == snapshot.hash)
    }
}

fn request_binding(
    snapshot: &Arc<Snapshot>,
    request: &DecisionRequest,
    authenticated_principal_id: Option<&str>,
) -> String {
    let body_sha256 = request
        .body_sha256
        .clone()
        .unwrap_or_else(|| sha256_prefixed(request.body.as_bytes()));
    let value = json!({
        "domain":"serverware.shadowAdmissionBinding/v1",
        "policyHash":snapshot.hash,
        "policySequence":snapshot.policy_sequence,
        "rollbackEpoch":snapshot.rollback_epoch,
        "authenticatedPrincipalId":authenticated_principal_id,
        "clientIp":request.client_ip,
        "method":request.method,
        "url":request.url,
        "headers":request.headers,
        "bodySha256":body_sha256,
        "forwardedBodyLength":request.forwarded_body_length,
        "forwardedBodyUtf8Valid":request.forwarded_body_utf8_valid,
        "clientRequestDigest":request.client_request_digest,
    });
    digest_json_ensure_ascii(&value)
}

#[derive(Clone)]
struct ShadowRuntimeGenerationBounds {
    generation_epoch: u64,
    generation_tombstone_epoch: u64,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    active_snapshot_sha256: Sha256Digest,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    active_compiled_snapshot_sha256: Sha256Digest,
    candidate_snapshot_sha256: Sha256Digest,
    candidate_policy_sequence: u64,
    candidate_rollback_epoch: u64,
    candidate_compiled_snapshot_sha256: Sha256Digest,
    runtime_boot_sha256: Sha256Digest,
    assignment_starts_at_epoch_ms: u64,
    assignment_ends_at_epoch_ms: u64,
    sampling_basis_points: u16,
    request_commitment_key_id: Sha256Digest,
    request_commitment_key_epoch: u64,
    request_facts_schema_sha256: Sha256Digest,
    ingress_range_start_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    observation_interval_sha256: Sha256Digest,
    response_obligation_root_sha256: Sha256Digest,
}

#[derive(Clone)]
struct ShadowGeneration {
    signed_identity: super::policy_shadow::ShadowGenerationIdentity,
    identity: ShadowRuntimeGenerationBounds,
    sampling_basis_points: u16,
    active: Arc<PolicyPlanSnapshot>,
    candidate: Arc<PolicyPlanSnapshot>,
    candidate_serving_snapshot: Arc<Snapshot>,
}

struct PublicationReconcileCell {
    generation: Arc<ShadowGeneration>,
    publication: Arc<PublishedShadowGeneration>,
    custody_prepare: PreparedGenerationPublication,
    allow_blank_recovery: bool,
    custody_publication:
        OnceLock<VerifiedPublicationReconciliationReceipt>,
    state: AtomicU8,
}

struct PublishedShadowGeneration {
    generation: Arc<ShadowGeneration>,
    active_projection: Arc<PolicyPlanSnapshot>,
    first_ingress_sequence: u64,
    last_ingress_sequence: u64,
    persisted_sequence_range_sha256: String,
    durable_spool_sha256: String,
    preparation_receipt_sha256: String,
    publication_revision: u64,
    publication_receipt_sha256: OnceLock<String>,
    custody: Arc<dyn PolicyShadowCustodyRpcSupervisor>,
}

#[derive(Clone)]
struct ShadowActivationPublicationGate {
    generation_id: Sha256Digest,
    transaction_sha256: Sha256Digest,
    signed_receipt_sha256: Sha256Digest,
    published_publication_revision: u64,
    candidate: Arc<Snapshot>,
}

impl ShadowActivationPublicationGate {
    fn authorizes(&self, generation: &ShadowGeneration, snapshot: &Snapshot) -> bool {
        &self.generation_id == generation.signed_identity.generation_id()
            && self.candidate.hash == snapshot.hash
            && self.candidate.policy_sequence
                == snapshot.policy_sequence
            && self.candidate.rollback_epoch
                == snapshot.rollback_epoch
            && same_exact_snapshot_identity(&self.candidate, snapshot)
    }
}

const PUBLICATION_PREPARED: u8 = 1;
const PUBLICATION_COMMITTED: u8 = 2;
const PUBLICATION_PUBLISHED: u8 = 3;

#[derive(Clone)]
pub(crate) struct ShadowActivePublicationPermit {
    active_snapshot_epoch: u64,
    active_snapshot_sha256: String,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    active_trust_generation: u64,
    active_compiled_behavior_sha256: String,
    active_policy_signing_key_id: String,
    active_response_verifying_key: Option<[u8; 32]>,
    active_response_signing_key_id: Option<String>,
    active_attested_response_context:
        Option<super::AttestedResponseContext>,
    custody_receipt_sha256: String,
    publication_revision: u64,
    publication_receipt_sha256: String,
}

impl ShadowActivePublicationPermit {
    pub(crate) fn authorizes(&self, snapshot: &Snapshot) -> bool {
        self.active_snapshot_epoch == snapshot.epoch
            && self.active_snapshot_sha256 == snapshot.hash
            && self.active_policy_sequence == snapshot.policy_sequence
            && self.active_rollback_epoch == snapshot.rollback_epoch
            && self.active_trust_generation
                == snapshot.trust_generation
            && self.active_compiled_behavior_sha256
                == snapshot.compiled_behavior_sha256
            && self.active_policy_signing_key_id
                == snapshot.policy_signing_key_id
            && self.active_response_verifying_key
                == snapshot
                    .response_verifying_key
                    .as_ref()
                    .map(|key| key.to_bytes())
            && self.active_response_signing_key_id
                == snapshot.response_signing_key_id
            && self.active_attested_response_context
                == snapshot.attested_response_context
    }

    pub(crate) fn custody_receipt_sha256(&self) -> &str {
        &self.custody_receipt_sha256
    }

    pub(crate) fn publication_revision(&self) -> u64 {
        self.publication_revision
    }

    pub(crate) fn publication_receipt_sha256(&self) -> &str {
        &self.publication_receipt_sha256
    }
}

impl ShadowGeneration {
    #[allow(dead_code)]
    fn new(
        signed_identity: super::policy_shadow::ShadowGenerationIdentity,
        identity: ShadowRuntimeGenerationBounds,
        sampling_basis_points: u16,
        active_snapshot: &Arc<Snapshot>,
        candidate_snapshot: &Arc<Snapshot>,
    ) -> Result<Self, String> {
        if identity.generation_epoch == 0
            || identity.generation_tombstone_epoch == 0
            || identity.generation_tombstone_epoch > identity.generation_epoch
            || identity.assignment_revision == 0
            || identity.active_policy_sequence == 0
            || identity.active_rollback_epoch == 0
            || identity.candidate_policy_sequence == 0
            || identity.candidate_rollback_epoch == 0
            || identity.assignment_starts_at_epoch_ms == 0
            || identity.assignment_ends_at_epoch_ms <= identity.assignment_starts_at_epoch_ms
            || identity.ingress_range_start_sequence == 0
            || !(1..=10_000).contains(&sampling_basis_points)
            || sampling_basis_points != identity.sampling_basis_points
        {
            return Err("shadow generation bounds are invalid".to_string());
        }
        let (signed_starts_at_unix_nanos, signed_ends_at_unix_nanos) =
            signed_identity.assignment_window_unix_nanos();
        let signed_starts_at_epoch_ms = u64::try_from(signed_starts_at_unix_nanos)
            .ok()
            .filter(|value| value % 1_000_000 == 0)
            .map(|value| value / 1_000_000)
            .ok_or("signed generation start is not an exact epoch millisecond")?;
        let signed_ends_at_epoch_ms = u64::try_from(signed_ends_at_unix_nanos)
            .ok()
            .filter(|value| value % 1_000_000 == 0)
            .map(|value| value / 1_000_000)
            .ok_or("signed generation end is not an exact epoch millisecond")?;
        let (request_commitment_key_id, request_commitment_key_epoch) =
            signed_identity.request_commitment_key_binding();
        if signed_identity.generation_epoch() != identity.generation_epoch
            || signed_identity.generation_tombstone_epoch()
                != identity.generation_tombstone_epoch
            || signed_identity.assignment_revision()
                != identity.assignment_revision
            || signed_identity.assignment_sha256()
                != &identity.assignment_sha256
            || signed_identity.assignment_payload_sha256()
                != &identity.assignment_payload_sha256
            || signed_identity.load_receipt_sha256()
                != &identity.load_receipt_sha256
            || signed_identity.load_receipt_payload_sha256()
                != &identity.load_receipt_payload_sha256
            || signed_identity.active_policy_sha256()
                != &identity.active_snapshot_sha256
            || signed_identity.active_policy_sequence()
                != identity.active_policy_sequence
            || signed_identity.active_rollback_epoch()
                != identity.active_rollback_epoch
            || signed_identity.active_compiled_snapshot_sha256()
                != &identity.active_compiled_snapshot_sha256
            || signed_identity.candidate_policy_sha256()
                != &identity.candidate_snapshot_sha256
            || signed_identity.candidate_policy_sequence()
                != identity.candidate_policy_sequence
            || signed_identity.candidate_rollback_epoch()
                != identity.candidate_rollback_epoch
            || signed_identity.candidate_compiled_snapshot_sha256()
                != &identity.candidate_compiled_snapshot_sha256
            || signed_identity.runtime_boot_id_sha256()
                != &identity.runtime_boot_sha256
            || signed_starts_at_epoch_ms
                != identity.assignment_starts_at_epoch_ms
            || signed_ends_at_epoch_ms != identity.assignment_ends_at_epoch_ms
            || signed_identity.sampling_basis_points()
                != identity.sampling_basis_points
            || request_commitment_key_id
                != &identity.request_commitment_key_id
            || request_commitment_key_epoch
                != identity.request_commitment_key_epoch
            || signed_identity.request_facts_schema_sha256()
                != &identity.request_facts_schema_sha256
            || signed_identity.ingress_range_start_sequence()
                != identity.ingress_range_start_sequence
            || signed_identity.ingress_range_predecessor_head_sha256()
                != &identity.ingress_range_predecessor_head_sha256
            || signed_identity.observation_interval_sha256()
                != &identity.observation_interval_sha256
            || signed_identity
                .response_validation_obligations_root_sha256()
                != &identity.response_obligation_root_sha256
        {
            return Err(
                "runtime bounds do not match signed generation identity"
                    .to_string(),
            );
        }
        let active = Arc::new(PolicyPlanSnapshot::active(active_snapshot)?);
        let candidate = Arc::new(PolicyPlanSnapshot::candidate(candidate_snapshot)?);
        if identity.active_snapshot_sha256.as_str() != active.snapshot.hash
            || identity.active_policy_sequence != active.snapshot.policy_sequence
            || identity.active_rollback_epoch != active.snapshot.rollback_epoch
        {
            return Err("active snapshot does not match generation identity".to_string());
        }
        if identity.candidate_snapshot_sha256.as_str() != candidate.snapshot.hash
            || identity.candidate_policy_sequence != candidate.snapshot.policy_sequence
            || identity.candidate_rollback_epoch != candidate.snapshot.rollback_epoch
        {
            return Err("candidate snapshot does not match generation identity".to_string());
        }
        Ok(Self {
            signed_identity,
            identity,
            sampling_basis_points,
            active,
            candidate,
            candidate_serving_snapshot: Arc::clone(candidate_snapshot),
        })
    }

    fn generation_id(&self) -> &str {
        self.signed_identity.generation_id().as_str()
    }

    fn matches_active_snapshot(&self, snapshot: &Snapshot) -> bool {
        self.identity.active_snapshot_sha256.as_str() == snapshot.hash
            && self.identity.active_policy_sequence == snapshot.policy_sequence
            && self.identity.active_rollback_epoch == snapshot.rollback_epoch
            && self.active.snapshot.hash == snapshot.hash
            && self.active.snapshot.policy_sequence == snapshot.policy_sequence
            && self.active.snapshot.rollback_epoch == snapshot.rollback_epoch
    }

}

const SHADOW_MAX_ACCOUNTING_GENERATIONS: usize = 8;
const SHADOW_SPOOL_RECEIPT_CACHE_ITEMS: usize = 4_096;
const SHADOW_SPOOL_COMPACTION_TRIGGER_ITEMS: usize = 3_072;
const SHADOW_SPOOL_COMPACTION_PREFIX_ITEMS: usize = 2_048;
const SHADOW_UNAVAILABLE_RECEIPT_CACHE_ITEMS: usize = 256;
const SHADOW_APPEND_RECONCILE_LANES: usize = 64;
const SHADOW_MODELED_RECEIPT_COMPACTION_TRIGGER_BYTES: usize =
    24 * 1024 * 1024;
const SHADOW_RECEIPT_DIGEST_BYTES: usize = 32;
const SHADOW_RECEIPT_RPC_FRAME_BYTES: usize = 2 * 1024 * 1024;
const SHADOW_RECEIPT_MAX_CANONICAL_EVENT_BYTES: usize = 256 * 1024;
const SHADOW_RECEIPT_RPC_FRAME_COPIES: usize = 3;
const SHADOW_RECEIPT_CANONICAL_EVENT_COPIES: usize = 6;
const SHADOW_RECEIPT_TRANSIENT_FIXED_BYTES: usize = 256 * 1024;
const SHADOW_RECEIPT_TRANSIENT_RESERVATION_BYTES: usize =
    SHADOW_RECEIPT_RPC_FRAME_BYTES * SHADOW_RECEIPT_RPC_FRAME_COPIES
        + SHADOW_RECEIPT_MAX_CANONICAL_EVENT_BYTES
            * SHADOW_RECEIPT_CANONICAL_EVENT_COPIES
        + SHADOW_RECEIPT_TRANSIENT_FIXED_BYTES;
const SHADOW_RECEIPT_COMPACTION_TRANSIENT_BYTES: usize = 16 * 1024 * 1024;
const SHADOW_SPILL_RECEIPT_ARENA_SLOTS: usize =
    SHADOW_MAX_ACCOUNTING_GENERATIONS * SHADOW_SPOOL_RECEIPT_CACHE_ITEMS;
const SHADOW_MODELED_RECEIPT_REFERENCE_CAPACITY: usize =
    SHADOW_SPILL_RECEIPT_ARENA_SLOTS
        + SHADOW_UNAVAILABLE_RECEIPT_CACHE_ITEMS;

#[derive(Clone, Copy)]
enum ShadowRuntimeEvent {
    ActivePreDispatchTerminal,
    ResponseTerminalAppended,
    DispatchBarrierAppended,
    ResponseCaptureEnqueued,
    CandidateEvaluated,
    ResponseEvaluated,
    SampledOut,
    TransportExcluded,
    UnsupportedRequiredIngress,
    CleanupQuarantined(PolicyShadowTerminalReason),
    Failure(PolicyShadowTerminalReason),
}

impl ShadowRuntimeEvent {
    fn invalidates_readiness(self) -> bool {
        matches!(
            self,
            Self::UnsupportedRequiredIngress
                | Self::CleanupQuarantined(_)
                | Self::Failure(_)
        )
    }

    fn spool_phase(self) -> ShadowSpoolPhase {
        match self {
            Self::ActivePreDispatchTerminal => {
                ShadowSpoolPhase::PreDispatchTerminal
            }
            Self::ResponseTerminalAppended => {
                ShadowSpoolPhase::PostDispatchTerminal
            }
            Self::DispatchBarrierAppended => ShadowSpoolPhase::DispatchBarrier,
            Self::ResponseCaptureEnqueued => ShadowSpoolPhase::Response,
            Self::CandidateEvaluated => ShadowSpoolPhase::Candidate,
            Self::ResponseEvaluated => ShadowSpoolPhase::Response,
            Self::CleanupQuarantined(_) => ShadowSpoolPhase::Response,
            Self::SampledOut
            | Self::TransportExcluded
            | Self::UnsupportedRequiredIngress => ShadowSpoolPhase::IngressOpen,
            Self::Failure(reason) => reason.spool_phase(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ActivePreDispatchTerminal => "active-pre-dispatch-terminal",
            Self::ResponseTerminalAppended => {
                "response-terminal-appended"
            }
            Self::DispatchBarrierAppended => "dispatch-barrier-appended",
            Self::ResponseCaptureEnqueued => "response-capture-enqueued",
            Self::CandidateEvaluated => "candidate-evaluated",
            Self::ResponseEvaluated => "response-evaluated",
            Self::SampledOut => "sampled-out",
            Self::TransportExcluded => "transport-excluded",
            Self::UnsupportedRequiredIngress => "unsupported-required-ingress",
            Self::CleanupQuarantined(_) => "cleanup-quarantined",
            Self::Failure(_) => "failure",
        }
    }

    fn terminal_reason(self) -> Option<PolicyShadowTerminalReason> {
        match self {
            Self::ActivePreDispatchTerminal
            | Self::ResponseTerminalAppended
            | Self::DispatchBarrierAppended
            | Self::ResponseCaptureEnqueued
            | Self::CandidateEvaluated
            | Self::ResponseEvaluated
            | Self::SampledOut
            | Self::TransportExcluded
            | Self::UnsupportedRequiredIngress => None,
            Self::CleanupQuarantined(reason)
            | Self::Failure(reason) => Some(reason),
        }
    }
}

#[derive(Clone)]
struct ShadowAccountingEvent {
    ingress_sequence: u64,
    request_binding_sha256: String,
    request_commitment_sha256: String,
    event: ShadowRuntimeEvent,
    terminal_detail_sha256: Option<String>,
    active_plan_sha256: Option<String>,
    final_active_decision_sha256: Option<String>,
    active_effect_results_sha256: Option<String>,
    candidate_plan_sha256: Option<String>,
    active_disposition: Option<String>,
    candidate_disposition: Option<String>,
    response_facts_sha256: Option<String>,
    active_response_validation_sha256: Option<String>,
    candidate_response_validation_sha256: Option<String>,
    decision_at_unix_nanos: Option<i64>,
    dispatch_final_request_sha256: Option<String>,
    dispatch_effect_authority_sha256: Option<String>,
}

impl ShadowAccountingEvent {
    fn minimal(
        ingress_sequence: u64,
        request_binding_sha256: String,
        request_commitment_sha256: String,
        event: ShadowRuntimeEvent,
    ) -> Self {
        Self {
            ingress_sequence,
            request_binding_sha256,
            request_commitment_sha256,
            event,
            terminal_detail_sha256: event
                .terminal_reason()
                .map(|reason| sha256_prefixed(reason.label().as_bytes())),
            active_plan_sha256: None,
            final_active_decision_sha256: None,
            active_effect_results_sha256: None,
            candidate_plan_sha256: None,
            active_disposition: None,
            candidate_disposition: None,
            response_facts_sha256: None,
            active_response_validation_sha256: None,
            candidate_response_validation_sha256: None,
            decision_at_unix_nanos: None,
            dispatch_final_request_sha256: None,
            dispatch_effect_authority_sha256: None,
        }
    }

    fn canonical_value(&self) -> Value {
        let phase = self.spool_phase();
        let mut value = json!({
            "domain":"serverware.policyShadowRuntimeAccountingEvent/v1",
            "ingressSequence":self.ingress_sequence,
            "requestBindingSha256":self.request_binding_sha256,
            "requestCommitmentSha256":self.request_commitment_sha256,
            "event":self.event.label(),
            "phase":phase,
            "terminalDetailSha256":self.terminal_detail_sha256,
            "activePlanSha256":self.active_plan_sha256,
            "finalActiveDecisionSha256":self.final_active_decision_sha256,
            "activeEffectResultsSha256":self.active_effect_results_sha256,
            "candidatePlanSha256":self.candidate_plan_sha256,
            "activeDisposition":self.active_disposition,
            "candidateDisposition":self.candidate_disposition,
            "responseFactsSha256":self.response_facts_sha256,
            "activeResponseValidationSha256":self.active_response_validation_sha256,
            "candidateResponseValidationSha256":self.candidate_response_validation_sha256,
            "decisionAtUnixNanos":self.decision_at_unix_nanos,
            "dispatchFinalRequestSha256":self.dispatch_final_request_sha256,
            "dispatchEffectAuthoritySha256":self.dispatch_effect_authority_sha256,
        });
        if let Some(reason) = self.event.terminal_reason() {
            value["reason"] = json!(reason);
        }
        value
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical_json_bytes(&self.canonical_value()).map_err(shadow_error)
    }

    fn commitment(&self) -> Result<Sha256Digest, String> {
        Ok(Sha256Digest::compute(&self.canonical_bytes()?))
    }

    fn spool_phase(&self) -> ShadowSpoolPhase {
        self.event.spool_phase()
    }

    fn set_event(&mut self, event: ShadowRuntimeEvent) {
        self.event = event;
        self.terminal_detail_sha256 = self
            .event
            .terminal_reason()
            .map(|reason| sha256_prefixed(reason.label().as_bytes()));
    }
}

#[derive(Default)]
struct GenerationCounters {
    admitted: u64,
    active_pre_dispatch_terminals: u64,
    active_post_dispatch_terminals: u64,
    dispatch_barriers_appended: u64,
    response_captures_enqueued: u64,
    evaluated: u64,
    responses_evaluated: u64,
    responses_unavailable: u64,
    sampled_out: u64,
    transport_excluded: u64,
    capture_failures: u64,
    serialization_failures: u64,
    oversize: u64,
    queue_full: u64,
    queue_disconnected: u64,
    active_evaluation_failures: u64,
    candidate_evaluation_failures: u64,
    unsupported_required_ingress: u64,
    custody_emission_missing: u64,
    generation_tombstoned: u64,
    queue_accounting_poisoned: u64,
    worker_lost: u64,
    terminal_failures: u64,
}

struct GenerationAccounting {
    generation_id: InlineSha256Digest,
    generation_epoch: u64,
    prepared: bool,
    live: bool,
    counters: GenerationCounters,
    permanent_readiness_invalid: bool,
    receipt_arena_lane: usize,
    last_spill_receipt_sha256: Option<InlineSha256Digest>,
    last_spill_event_ordinal: u64,
    last_spill_head_sha256: InlineSha256Digest,
    last_compaction_receipt_sha256: Option<InlineSha256Digest>,
    last_compaction_retrieval_id_sha256: Option<InlineSha256Digest>,
    compacted_through_event_ordinal: Option<u64>,
    compacted_spool_root_sha256: Option<InlineSha256Digest>,
    compaction_requested: bool,
    local_ordering_gap: bool,
    spool_backpressure: bool,
}

impl GenerationAccounting {
    fn prepared(
        generation_id: InlineSha256Digest,
        generation_epoch: u64,
        receipt_arena_lane: usize,
        spill_predecessor_event_ordinal: u64,
        spill_predecessor_head_sha256: InlineSha256Digest,
    ) -> Self {
        Self {
            generation_id,
            generation_epoch,
            prepared: true,
            live: false,
            counters: GenerationCounters::default(),
            permanent_readiness_invalid: false,
            receipt_arena_lane,
            last_spill_receipt_sha256: None,
            last_spill_event_ordinal: spill_predecessor_event_ordinal,
            last_spill_head_sha256: spill_predecessor_head_sha256,
            last_compaction_receipt_sha256: None,
            last_compaction_retrieval_id_sha256: None,
            compacted_through_event_ordinal: None,
            compacted_spool_root_sha256: None,
            compaction_requested: false,
            local_ordering_gap: false,
            spool_backpressure: false,
        }
    }

    fn increment(&mut self, event: ShadowRuntimeEvent) {
        let increment = |value: &mut u64| *value = value.saturating_add(1);
        match event {
            ShadowRuntimeEvent::ActivePreDispatchTerminal => {
                increment(&mut self.counters.active_pre_dispatch_terminals)
            }
            ShadowRuntimeEvent::ResponseTerminalAppended => {
                increment(&mut self.counters.active_post_dispatch_terminals)
            }
            ShadowRuntimeEvent::DispatchBarrierAppended => {
                increment(&mut self.counters.dispatch_barriers_appended)
            }
            ShadowRuntimeEvent::ResponseCaptureEnqueued => {
                increment(&mut self.counters.response_captures_enqueued)
            }
            ShadowRuntimeEvent::CandidateEvaluated => {
                increment(&mut self.counters.evaluated)
            }
            ShadowRuntimeEvent::ResponseEvaluated => {
                increment(&mut self.counters.responses_evaluated)
            }
            ShadowRuntimeEvent::SampledOut => {
                increment(&mut self.counters.sampled_out)
            }
            ShadowRuntimeEvent::TransportExcluded => {
                increment(&mut self.counters.transport_excluded)
            }
            ShadowRuntimeEvent::UnsupportedRequiredIngress => {
                increment(&mut self.counters.unsupported_required_ingress)
            }
            ShadowRuntimeEvent::CleanupQuarantined(_) => {
                increment(&mut self.counters.terminal_failures)
            }
            ShadowRuntimeEvent::Failure(reason) => match reason {
                PolicyShadowTerminalReason::FactsCaptureError => {
                    increment(&mut self.counters.capture_failures)
                }
                PolicyShadowTerminalReason::ActiveEvaluationError => {
                    increment(&mut self.counters.active_evaluation_failures)
                }
                PolicyShadowTerminalReason::CandidateEvaluationError => {
                    increment(&mut self.counters.candidate_evaluation_failures)
                }
                PolicyShadowTerminalReason::AccountingSerializationFailed => {
                    increment(&mut self.counters.serialization_failures)
                }
                PolicyShadowTerminalReason::AccountingOversize => {
                    increment(&mut self.counters.oversize)
                }
                PolicyShadowTerminalReason::AccountingQueueFull => {
                    increment(&mut self.counters.queue_full)
                }
                PolicyShadowTerminalReason::AccountingQueueDisconnected => {
                    increment(&mut self.counters.queue_disconnected)
                }
                PolicyShadowTerminalReason::AccountingCustodyUnavailable => {
                    increment(&mut self.counters.custody_emission_missing)
                }
                PolicyShadowTerminalReason::AccountingGenerationTombstoned
                | PolicyShadowTerminalReason::GenerationChangedBeforeTerminal => {
                    increment(&mut self.counters.generation_tombstoned)
                }
                PolicyShadowTerminalReason::AccountingLedgerContention
                | PolicyShadowTerminalReason::TerminalStateContention
                | PolicyShadowTerminalReason::DispatchBarrierStateContention => {
                    increment(&mut self.counters.queue_accounting_poisoned)
                }
                PolicyShadowTerminalReason::WorkerLost => {
                    increment(&mut self.counters.worker_lost)
                }
                _ => {
                    increment(&mut self.counters.terminal_failures);
                    if reason.spool_phase() == ShadowSpoolPhase::Response {
                        increment(&mut self.counters.responses_unavailable);
                    }
                }
            }
        }
        self.permanent_readiness_invalid |= event.invalidates_readiness();
    }
}

struct GenerationAccountingTable {
    entries: [Option<GenerationAccounting>; SHADOW_MAX_ACCOUNTING_GENERATIONS],
    length: usize,
}

impl GenerationAccountingTable {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            length: 0,
        }
    }

    fn len(&self) -> usize {
        self.length
    }

    fn get(&self, index: usize) -> Option<&GenerationAccounting> {
        if index >= self.length {
            return None;
        }
        self.entries.get(index).and_then(Option::as_ref)
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &GenerationAccounting> {
        self.entries[..self.length]
            .iter()
            .filter_map(Option::as_ref)
    }

    fn iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = &mut GenerationAccounting> {
        self.entries[..self.length]
            .iter_mut()
            .filter_map(Option::as_mut)
    }

    fn push_back(
        &mut self,
        accounting: GenerationAccounting,
    ) -> Result<(), String> {
        if self.length >= SHADOW_MAX_ACCOUNTING_GENERATIONS {
            return Err("generation accounting table is full".to_string());
        }
        self.entries[self.length] = Some(accounting);
        self.length += 1;
        Ok(())
    }

    fn remove(&mut self, index: usize) -> Option<GenerationAccounting> {
        if index >= self.length {
            return None;
        }
        let removed = self.entries[index].take();
        for current in index..self.length - 1 {
            self.entries[current] = self.entries[current + 1].take();
        }
        self.length -= 1;
        self.entries[self.length] = None;
        removed
    }
}

impl std::ops::Index<usize> for GenerationAccountingTable {
    type Output = GenerationAccounting;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .expect("generation accounting index is validated before access")
    }
}

impl std::ops::IndexMut<usize> for GenerationAccountingTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index >= self.length {
            panic!("generation accounting index is validated before access");
        }
        self.entries[index]
            .as_mut()
            .expect("generation accounting entry is initialized")
    }
}

struct AccountingState {
    generations: GenerationAccountingTable,
    receipt_arena: PolicyCoreModeledReceiptArena,
    receipt_index: ReceiptMetadataIndex,
    last_unavailable_receipt_sha256: Option<InlineSha256Digest>,
    last_unavailable_event_ordinal: u64,
    last_unavailable_head_sha256: Option<InlineSha256Digest>,
    last_unavailable_retrieval_id_sha256: Option<InlineSha256Digest>,
    unavailable_backpressure: bool,
    highest_generation_epoch: u64,
    highest_generation_tombstone_epoch: u64,
    highest_assignment_revision: u64,
    unrecoverable_local_failure: bool,
    hard_unready: bool,
}

struct AccountingLedger {
    state: Mutex<AccountingState>,
    append_reconcile_lanes: [Mutex<()>; SHADOW_APPEND_RECONCILE_LANES],
    custody: Arc<OnceLock<Arc<dyn PolicyShadowCustodyRpcSupervisor>>>,
    hard_unready_signal: AtomicBool,
    compaction_in_progress: AtomicBool,
}

struct ReceiptReconciliationCapacity<'a> {
    ledger: &'a AccountingLedger,
    reservation: ModeledReservationToken,
    scope: ReceiptReservationScope,
    modeled_bytes: usize,
}

impl ReceiptReconciliationCapacity<'_> {
    fn authorizes_event_payload(&self, canonical_event_bytes: usize) -> bool {
        let required = SHADOW_RECEIPT_RPC_FRAME_BYTES
            .checked_mul(SHADOW_RECEIPT_RPC_FRAME_COPIES)
            .and_then(|bytes| {
                canonical_event_bytes
                    .checked_mul(
                        SHADOW_RECEIPT_CANONICAL_EVENT_COPIES,
                    )
                    .and_then(|event_bytes| {
                        bytes.checked_add(event_bytes)
                    })
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    SHADOW_RECEIPT_TRANSIENT_FIXED_BYTES,
                )
            });
        let authorized = canonical_event_bytes > 0
            && canonical_event_bytes
                <= SHADOW_RECEIPT_MAX_CANONICAL_EVENT_BYTES
            && required.is_some_and(|bytes| {
                bytes <= self.modeled_bytes
            });
        if !authorized {
            self.ledger.mark_hard_unready();
        }
        authorized
    }

    fn rebind_to_generation(&mut self, generation_id: &str) -> bool {
        let Ok(mut state) = self.ledger.state.try_lock() else {
            self.ledger.mark_hard_unready();
            return false;
        };
        let Some(receipt_arena_lane) = state
            .generations
            .iter()
            .find(|generation| {
                generation.generation_id == generation_id
                    && !generation.spool_backpressure
            })
            .map(|generation| generation.receipt_arena_lane)
        else {
            state.hard_unready = true;
            self.ledger
                .hard_unready_signal
                .store(true, Ordering::Release);
            return false;
        };
        let replacement = ReceiptReservationScope::Spill {
            lane: receipt_arena_lane,
        };
        if state.receipt_index.reserve_scope(replacement).is_err() {
            state.hard_unready = true;
            self.ledger
                .hard_unready_signal
                .store(true, Ordering::Release);
            return false;
        }
        if state.receipt_index.release_scope(self.scope).is_err()
        {
            let _ = state.receipt_index.release_scope(replacement);
            state.hard_unready = true;
            self.ledger
                .hard_unready_signal
                .store(true, Ordering::Release);
            return false;
        }
        self.scope = replacement;
        true
    }
}

impl Drop for ReceiptReconciliationCapacity<'_> {
    fn drop(&mut self) {
        let Ok(mut state) = self.ledger.state.try_lock() else {
            self.ledger.mark_hard_unready();
            return;
        };
        if state.receipt_arena.release(self.reservation).is_err()
            || state.receipt_index.release_scope(self.scope).is_err()
        {
            state.hard_unready = true;
            self.ledger
                .hard_unready_signal
                .store(true, Ordering::Release);
            return;
        }
        if let ReceiptReservationScope::Spill { lane } = self.scope
        {
            let removable = state.receipt_index.spill_len(lane) == 0
                && state.receipt_index.spill_reserved(lane) == 0;
            let retired_index = removable.then(|| {
                state.generations.iter().position(|generation| {
                    generation.receipt_arena_lane == lane
                        && !generation.live
                        && !generation.prepared
                })
            }).flatten();
            if let Some(index) = retired_index {
                let removed = state.generations.remove(index);
                if removed.is_none()
                    || state.receipt_index.release_spill_lane(lane).is_err()
                {
                    state.hard_unready = true;
                    self.ledger
                        .hard_unready_signal
                        .store(true, Ordering::Release);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct DurableShadowEventReceipt {
    generation_id: InlineSha256Digest,
    ingress_sequence: u64,
    event_ordinal: u64,
    event_sha256: InlineSha256Digest,
    resulting_head_sha256: InlineSha256Digest,
    signed_receipt_sha256: InlineSha256Digest,
    retrieval_id_sha256: InlineSha256Digest,
    retrieval_proof_sha256: InlineSha256Digest,
    verified_payload_sha256: InlineSha256Digest,
    verified_trust_checkpoint_sha256: InlineSha256Digest,
}

fn matching_terminal_append_receipt(
    event: &ShadowSpoolEvent,
    outcome: Result<TerminalSlotAppendOutcome, ShadowError>,
) -> Option<VerifiedShadowSpillReceipt> {
    if !matches!(
        event.phase(),
        ShadowSpoolPhase::PreDispatchTerminal | ShadowSpoolPhase::PostDispatchTerminal
    ) {
        return None;
    }
    match outcome {
        Ok(TerminalSlotAppendOutcome::Committed(receipt)
            | TerminalSlotAppendOutcome::Existing(receipt))
            if receipt.matches_event(event)
                && receipt.disposition() == ShadowSpoolDisposition::Appended =>
        {
            Some(receipt)
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct ImmutableSpillReceiptRef {
    modeled_handle: ReceiptSlotHandle,
    generation_id: InlineSha256Digest,
    ingress_sequence: u64,
    event_ordinal: u64,
    event_sha256: InlineSha256Digest,
    canonical_event_length: usize,
    canonical_event_sha256: InlineSha256Digest,
    predecessor_event_ordinal: u64,
    predecessor_head_sha256: InlineSha256Digest,
    resulting_head_sha256: InlineSha256Digest,
    signed_receipt_sha256: InlineSha256Digest,
    retrieval_id_sha256: InlineSha256Digest,
    retrieval_proof_sha256: InlineSha256Digest,
    verified_payload_sha256: InlineSha256Digest,
    verified_trust_checkpoint_sha256: InlineSha256Digest,
}

impl ImmutableSpillReceiptRef {
    fn from_verified(
        receipt: &VerifiedShadowSpillReceipt,
        modeled_handle: ReceiptSlotHandle,
    ) -> Result<Self, String> {
        Ok(Self {
            modeled_handle,
            generation_id:
                InlineSha256Digest::from_digest(receipt.generation_id())?,
            ingress_sequence: receipt.ingress_sequence(),
            event_ordinal: receipt.event_ordinal(),
            event_sha256:
                InlineSha256Digest::from_digest(receipt.event_sha256())?,
            canonical_event_length: receipt.canonical_event_bytes().len(),
            canonical_event_sha256:
                InlineSha256Digest::compute(receipt.canonical_event_bytes()),
            predecessor_event_ordinal:
                receipt.predecessor_event_ordinal(),
            predecessor_head_sha256: InlineSha256Digest::from_digest(
                receipt.predecessor_head_sha256(),
            )?,
            resulting_head_sha256: InlineSha256Digest::from_digest(
                receipt.resulting_head_sha256(),
            )?,
            signed_receipt_sha256: InlineSha256Digest::from_digest(
                receipt.signed_receipt_sha256(),
            )?,
            retrieval_id_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_id_sha256(),
            )?,
            retrieval_proof_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_proof_sha256(),
            )?,
            verified_payload_sha256: InlineSha256Digest::from_digest(
                receipt.canonical_payload_sha256(),
            )?,
            verified_trust_checkpoint_sha256:
                InlineSha256Digest::from_digest(
                    &receipt.verified_trust_checkpoint().checkpoint_id,
                )?,
        })
    }

    fn modeled_reference(
        receipt: &VerifiedShadowSpillReceipt,
        generation_epoch: u64,
    ) -> Result<ModeledInlineReceiptReference, String> {
        Ok(ModeledInlineReceiptReference {
            kind: ReceiptReferenceKind::Spill,
            flags: 0,
            reserved: [0; 6],
            generation: generation_epoch,
            ordinal: receipt.event_ordinal(),
            canonical_length: u64::try_from(
                receipt.canonical_event_bytes().len(),
            )
            .map_err(|_| {
                "spill receipt canonical length exceeds u64".to_string()
            })?,
            operation_id_sha256:
                InlineSha256Digest::from_digest(
                    receipt.canonical_payload_sha256(),
                )?
                .modeled(),
            request_sha256: InlineSha256Digest::from_digest(
                receipt.event_sha256(),
            )?
            .modeled(),
            predecessor_sha256: InlineSha256Digest::from_digest(
                receipt.predecessor_head_sha256(),
            )?
            .modeled(),
            receipt_sha256: InlineSha256Digest::from_digest(
                receipt.signed_receipt_sha256(),
            )?
            .modeled(),
            retrieval_id_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_id_sha256(),
            )?
            .modeled(),
            retrieval_proof_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_proof_sha256(),
            )?
            .modeled(),
        })
    }

    fn event_ordinal(&self) -> u64 {
        self.event_ordinal
    }

    fn event_sha256(&self) -> &InlineSha256Digest {
        &self.event_sha256
    }

    fn predecessor_event_ordinal(&self) -> u64 {
        self.predecessor_event_ordinal
    }

    fn predecessor_head_sha256(&self) -> &InlineSha256Digest {
        &self.predecessor_head_sha256
    }

    fn resulting_head_sha256(&self) -> &InlineSha256Digest {
        &self.resulting_head_sha256
    }

    fn signed_receipt_sha256(&self) -> &InlineSha256Digest {
        &self.signed_receipt_sha256
    }

    fn durable_receipt(
        &self,
        ingress_sequence: u64,
    ) -> DurableShadowEventReceipt {
        DurableShadowEventReceipt {
            generation_id: self.generation_id,
            ingress_sequence,
            event_ordinal: self.event_ordinal,
            event_sha256: self.event_sha256,
            resulting_head_sha256: self.resulting_head_sha256,
            signed_receipt_sha256: self.signed_receipt_sha256,
            retrieval_id_sha256: self.retrieval_id_sha256,
            retrieval_proof_sha256: self.retrieval_proof_sha256,
            verified_payload_sha256: self.verified_payload_sha256,
            verified_trust_checkpoint_sha256:
                self.verified_trust_checkpoint_sha256,
        }
    }
}

#[derive(Clone, Copy)]
struct ImmutableUnavailableReceiptRef {
    modeled_handle: ReceiptSlotHandle,
    event_ordinal: u64,
    predecessor_event_ordinal: u64,
    predecessor_head_sha256: InlineSha256Digest,
    resulting_head_sha256: InlineSha256Digest,
    signed_receipt_sha256: InlineSha256Digest,
    retrieval_id_sha256: InlineSha256Digest,
}

impl ImmutableUnavailableReceiptRef {
    fn from_verified(
        receipt: &VerifiedUnavailableGenerationReceipt,
        modeled_handle: ReceiptSlotHandle,
    ) -> Result<Self, String> {
        Ok(Self {
            modeled_handle,
            event_ordinal: receipt.event_ordinal(),
            predecessor_event_ordinal:
                receipt.predecessor_event_ordinal(),
            predecessor_head_sha256: InlineSha256Digest::from_digest(
                receipt.predecessor_head_sha256(),
            )?,
            resulting_head_sha256: InlineSha256Digest::from_digest(
                receipt.resulting_head_sha256(),
            )?,
            signed_receipt_sha256: InlineSha256Digest::from_digest(
                receipt.signed_receipt_sha256(),
            )?,
            retrieval_id_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_id_sha256(),
            )?,
        })
    }

    fn modeled_reference(
        receipt: &VerifiedUnavailableGenerationReceipt,
    ) -> Result<ModeledInlineReceiptReference, String> {
        Ok(ModeledInlineReceiptReference {
            kind: ReceiptReferenceKind::Unavailable,
            flags: 0,
            reserved: [0; 6],
            generation: 1,
            ordinal: receipt.event_ordinal(),
            canonical_length: u64::try_from(
                receipt
                    .canonical_payload_length()
                    .map_err(shadow_error)?,
            )
            .map_err(|_| {
                "unavailable receipt canonical length exceeds u64"
                    .to_string()
            })?,
            operation_id_sha256:
                InlineSha256Digest::from_digest(
                    receipt.canonical_payload_sha256(),
                )?
                .modeled(),
            request_sha256: InlineSha256Digest::from_digest(
                receipt.request_binding_sha256(),
            )?
            .modeled(),
            predecessor_sha256: InlineSha256Digest::from_digest(
                receipt.predecessor_head_sha256(),
            )?
            .modeled(),
            receipt_sha256: InlineSha256Digest::from_digest(
                receipt.signed_receipt_sha256(),
            )?
            .modeled(),
            retrieval_id_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_id_sha256(),
            )?
            .modeled(),
            retrieval_proof_sha256: InlineSha256Digest::from_digest(
                receipt.retrieval_proof_sha256(),
            )?
            .modeled(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct InlineSha256Digest {
    bytes: [u8; SHADOW_RECEIPT_DIGEST_BYTES],
}

impl InlineSha256Digest {
    fn from_digest(digest: &Sha256Digest) -> Result<Self, String> {
        Self::from_str(digest.as_str())
    }

    fn from_str(value: &str) -> Result<Self, String> {
        let source = value.as_bytes();
        if source.len() != 7 + SHADOW_RECEIPT_DIGEST_BYTES * 2
            || !source.starts_with(b"sha256:")
        {
            return Err("receipt arena requires a canonical sha256 digest".to_string());
        }
        let mut bytes = [0_u8; SHADOW_RECEIPT_DIGEST_BYTES];
        for (index, encoded) in source[7..].chunks_exact(2).enumerate() {
            let high = Self::hex_nibble(encoded[0]).ok_or_else(|| {
                "receipt arena requires lowercase sha256 hex".to_string()
            })?;
            let low = Self::hex_nibble(encoded[1]).ok_or_else(|| {
                "receipt arena requires lowercase sha256 hex".to_string()
            })?;
            bytes[index] = high << 4 | low;
        }
        Ok(Self { bytes })
    }

    fn compute(value: &[u8]) -> Self {
        let digest = <sha2::Sha256 as sha2::Digest>::digest(value);
        let mut bytes = [0_u8; SHADOW_RECEIPT_DIGEST_BYTES];
        bytes.copy_from_slice(&digest);
        Self { bytes }
    }

    fn modeled(self) -> ModeledInlineSha256Digest {
        ModeledInlineSha256Digest::new(self.bytes)
    }

    fn hex_nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }

    fn encoded(self) -> [u8; 7 + SHADOW_RECEIPT_DIGEST_BYTES * 2] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded =
            [0_u8; 7 + SHADOW_RECEIPT_DIGEST_BYTES * 2];
        encoded[..7].copy_from_slice(b"sha256:");
        for (index, byte) in self.bytes.iter().copied().enumerate() {
            encoded[7 + index * 2] = HEX[usize::from(byte >> 4)];
            encoded[8 + index * 2] =
                HEX[usize::from(byte & 0x0f)];
        }
        encoded
    }

    fn to_digest(self) -> Result<Sha256Digest, String> {
        let encoded = self.encoded();
        let value = std::str::from_utf8(&encoded)
            .map_err(|_| {
                "inline receipt digest encoding failed".to_string()
            })?
            .to_string();
        Sha256Digest::parse(value).map_err(shadow_error)
    }

    fn matches_digest(&self, digest: &Sha256Digest) -> bool {
        Self::from_digest(digest)
            .is_ok_and(|candidate| candidate == *self)
    }

    fn matches_str(&self, value: &str) -> bool {
        Self::from_str(value)
            .is_ok_and(|candidate| candidate == *self)
    }

    fn is_canonical(&self) -> bool {
        let encoded = self.encoded();
        std::str::from_utf8(&encoded)
            .ok()
            .and_then(|value| Self::from_str(value).ok())
            .is_some_and(|candidate| candidate == *self)
    }
}

impl PartialEq<Sha256Digest> for InlineSha256Digest {
    fn eq(&self, other: &Sha256Digest) -> bool {
        self.matches_digest(other)
    }
}

impl PartialEq<InlineSha256Digest> for Sha256Digest {
    fn eq(&self, other: &InlineSha256Digest) -> bool {
        other.matches_digest(self)
    }
}

impl PartialEq<&str> for InlineSha256Digest {
    fn eq(&self, other: &&str) -> bool {
        self.matches_str(other)
    }
}

impl serde::Serialize for InlineSha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.encoded();
        let value = std::str::from_utf8(&encoded)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(value)
    }
}

#[derive(Clone, Copy)]
enum ReceiptReservationScope {
    Spill { lane: usize },
    Unavailable,
    Compaction,
}

struct ReceiptMetadataIndex {
    spill_slots: Box<[Option<ImmutableSpillReceiptRef>]>,
    unavailable_slots:
        Box<[Option<ImmutableUnavailableReceiptRef>]>,
    spill_lane_in_use: [bool; SHADOW_MAX_ACCOUNTING_GENERATIONS],
    spill_lane_lengths: [usize; SHADOW_MAX_ACCOUNTING_GENERATIONS],
    spill_lane_reservations: [usize; SHADOW_MAX_ACCOUNTING_GENERATIONS],
    unavailable_length: usize,
    unavailable_reservations: usize,
    ready: bool,
}

impl ReceiptMetadataIndex {
    fn fixed_slab<T>(
        length: usize,
        mut initialize: impl FnMut() -> T,
    ) -> Result<Box<[T]>, String> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| "receipt arena allocation failed".to_string())?;
        if values.capacity() != length {
            return Err(
                "allocator did not provide exact receipt arena capacity"
                    .to_string(),
            );
        }
        values.resize_with(length, &mut initialize);
        let slab = values.into_boxed_slice();
        if slab.len() != length {
            return Err(
                "receipt arena fixed slab length changed".to_string(),
            );
        }
        Ok(slab)
    }

    fn try_new() -> Result<Self, String> {
        let spill_slots: Box<[Option<ImmutableSpillReceiptRef>]> =
            Self::fixed_slab(
                SHADOW_SPILL_RECEIPT_ARENA_SLOTS,
                || None,
            )?;
        let unavailable_slots:
            Box<[Option<ImmutableUnavailableReceiptRef>]> =
            Self::fixed_slab(
                SHADOW_UNAVAILABLE_RECEIPT_CACHE_ITEMS,
                || None,
            )?;
        let arena = Self {
            spill_slots,
            unavailable_slots,
            spill_lane_in_use: [false; SHADOW_MAX_ACCOUNTING_GENERATIONS],
            spill_lane_lengths: [0; SHADOW_MAX_ACCOUNTING_GENERATIONS],
            spill_lane_reservations: [0; SHADOW_MAX_ACCOUNTING_GENERATIONS],
            unavailable_length: 0,
            unavailable_reservations: 0,
            ready: true,
        };
        Ok(arena)
    }

    fn unavailable() -> Self {
        Self {
            spill_slots: Vec::new().into_boxed_slice(),
            unavailable_slots: Vec::new().into_boxed_slice(),
            spill_lane_in_use: [false; SHADOW_MAX_ACCOUNTING_GENERATIONS],
            spill_lane_lengths: [0; SHADOW_MAX_ACCOUNTING_GENERATIONS],
            spill_lane_reservations: [0; SHADOW_MAX_ACCOUNTING_GENERATIONS],
            unavailable_length: 0,
            unavailable_reservations: 0,
            ready: false,
        }
    }

    fn allocate_spill_lane(&mut self) -> Result<usize, String> {
        if !self.ready {
            return Err("receipt arena is unavailable".to_string());
        }
        let lane = self
            .spill_lane_in_use
            .iter()
            .position(|in_use| !*in_use)
            .ok_or_else(|| "receipt arena has no free generation lane".to_string())?;
        self.spill_lane_in_use[lane] = true;
        Ok(lane)
    }

    fn release_spill_lane(&mut self, lane: usize) -> Result<(), String> {
        if lane >= SHADOW_MAX_ACCOUNTING_GENERATIONS
            || !self.spill_lane_in_use[lane]
            || self.spill_lane_lengths[lane] != 0
            || self.spill_lane_reservations[lane] != 0
        {
            return Err("receipt arena generation lane is not empty".to_string());
        }
        self.spill_lane_in_use[lane] = false;
        Ok(())
    }

    fn spill_range(lane: usize) -> Result<std::ops::Range<usize>, String> {
        if lane >= SHADOW_MAX_ACCOUNTING_GENERATIONS {
            return Err("receipt arena generation lane is invalid".to_string());
        }
        let start = lane
            .checked_mul(SHADOW_SPOOL_RECEIPT_CACHE_ITEMS)
            .ok_or_else(|| "receipt arena generation lane overflow".to_string())?;
        Ok(start..start + SHADOW_SPOOL_RECEIPT_CACHE_ITEMS)
    }

    fn spill_len(&self, lane: usize) -> usize {
        self.spill_lane_lengths.get(lane).copied().unwrap_or(0)
    }

    fn modeled_spill_reference_bytes(&self, lane: usize) -> usize {
        self.spill_len(lane).saturating_mul(
            std::mem::size_of::<ModeledInlineReceiptReference>(),
        )
    }

    fn spill_reserved(&self, lane: usize) -> usize {
        self.spill_lane_reservations
            .get(lane)
            .copied()
            .unwrap_or(usize::MAX)
    }

    fn spill_get(
        &self,
        lane: usize,
        index: usize,
    ) -> Option<&ImmutableSpillReceiptRef> {
        let range = Self::spill_range(lane).ok()?;
        if index >= self.spill_len(lane) {
            return None;
        }
        self.spill_slots
            .get(range.start + index)
            .and_then(Option::as_ref)
    }

    fn spill_iter(
        &self,
        lane: usize,
    ) -> impl DoubleEndedIterator<Item = &ImmutableSpillReceiptRef> {
        let range = Self::spill_range(lane).unwrap_or(0..0);
        let start = range.start.min(self.spill_slots.len());
        let end = range.end.min(self.spill_slots.len());
        let length = self.spill_len(lane).min(end.saturating_sub(start));
        self.spill_slots[start..end]
            .iter()
            .take(length)
            .filter_map(Option::as_ref)
    }

    fn insert_spill(
        &mut self,
        lane: usize,
        index: usize,
        receipt: ImmutableSpillReceiptRef,
    ) -> Result<(), String> {
        if !self.ready
            || !self
                .spill_lane_in_use
                .get(lane)
                .copied()
                .unwrap_or(false)
        {
            return Err("receipt arena generation lane is unavailable".to_string());
        }
        let length = self.spill_len(lane);
        if length >= SHADOW_SPOOL_RECEIPT_CACHE_ITEMS || index > length {
            return Err("receipt arena generation lane is full".to_string());
        }
        let range = Self::spill_range(lane)?;
        self.spill_slots
            .copy_within(range.start + index..range.start + length, range.start + index + 1);
        self.spill_slots[range.start + index] = Some(receipt);
        self.spill_lane_lengths[lane] = length + 1;
        Ok(())
    }

    fn remove_spill_prefix(
        &mut self,
        lane: usize,
        count: usize,
    ) -> Result<Vec<ReceiptSlotHandle>, String> {
        let length = self.spill_len(lane);
        if count == 0 || count > length {
            return Err("receipt arena compaction prefix is invalid".to_string());
        }
        let range = Self::spill_range(lane)?;
        let mut modeled_handles = Vec::new();
        modeled_handles
            .try_reserve_exact(count)
            .map_err(|_| {
                "receipt metadata compaction handle allocation failed"
                    .to_string()
            })?;
        for index in 0..count {
            modeled_handles.push(
                self.spill_slots[range.start + index]
                    .as_ref()
                    .ok_or_else(|| {
                        "receipt metadata compaction prefix is incomplete"
                            .to_string()
                    })?
                    .modeled_handle,
            );
        }
        self.spill_slots.copy_within(
            range.start + count..range.start + length,
            range.start,
        );
        for index in length - count..length {
            self.spill_slots[range.start + index] = None;
        }
        self.spill_lane_lengths[lane] = length - count;
        Ok(modeled_handles)
    }

    fn reserve_scope(
        &mut self,
        scope: ReceiptReservationScope,
    ) -> Result<(), String> {
        if !self.ready {
            return Err("receipt arena is unavailable".to_string());
        }
        match scope {
            ReceiptReservationScope::Spill { lane } => {
                let committed = self.spill_len(lane);
                let reserved = self
                    .spill_lane_reservations
                    .get(lane)
                    .copied()
                    .ok_or_else(|| {
                        "receipt arena generation lane is invalid".to_string()
                    })?;
                if !self.spill_lane_in_use[lane]
                    || committed
                        .checked_add(reserved)
                        .is_none_or(|used| {
                            used >= SHADOW_SPOOL_RECEIPT_CACHE_ITEMS
                        })
                {
                    return Err(
                        "receipt arena generation lane has no transient capacity"
                            .to_string(),
                    );
                }
                self.spill_lane_reservations[lane] = reserved + 1;
            }
            ReceiptReservationScope::Unavailable => {
                if self
                    .unavailable_length
                    .checked_add(self.unavailable_reservations)
                    .is_none_or(|used| {
                        used >= SHADOW_UNAVAILABLE_RECEIPT_CACHE_ITEMS
                    })
                {
                    return Err(
                        "receipt arena unavailable lane has no transient capacity"
                            .to_string(),
                    );
                }
                self.unavailable_reservations += 1;
            }
            ReceiptReservationScope::Compaction => {}
        }
        Ok(())
    }

    fn release_scope(
        &mut self,
        scope: ReceiptReservationScope,
    ) -> Result<(), String> {
        match scope {
            ReceiptReservationScope::Spill { lane } => {
                let reserved = self
                    .spill_lane_reservations
                    .get_mut(lane)
                    .ok_or_else(|| {
                        "receipt arena generation lane is invalid".to_string()
                    })?;
                *reserved = reserved.checked_sub(1).ok_or_else(|| {
                    "receipt arena spill reservation underflow".to_string()
                })?;
            }
            ReceiptReservationScope::Unavailable => {
                self.unavailable_reservations = self
                    .unavailable_reservations
                    .checked_sub(1)
                    .ok_or_else(|| {
                        "receipt arena unavailable reservation underflow"
                            .to_string()
                    })?;
            }
            ReceiptReservationScope::Compaction => {}
        }
        Ok(())
    }

    fn push_unavailable(
        &mut self,
        receipt: ImmutableUnavailableReceiptRef,
    ) -> Result<(), String> {
        if !self.ready
            || self.unavailable_length >= SHADOW_UNAVAILABLE_RECEIPT_CACHE_ITEMS
        {
            return Err("receipt arena unavailable lane is full".to_string());
        }
        self.unavailable_slots[self.unavailable_length] = Some(receipt);
        self.unavailable_length += 1;
        Ok(())
    }
}

pub(crate) struct ShadowDispatchBarrierPermit {
    generation_id: InlineSha256Digest,
    ingress_sequence: u64,
    request_binding_sha256: InlineSha256Digest,
    request_commitment_sha256: InlineSha256Digest,
    active_plan_sha256: InlineSha256Digest,
    decision_at_epoch_ms: u64,
    final_upstream_request_commitment_sha256: InlineSha256Digest,
    effect_authority_commitments_sha256: InlineSha256Digest,
    event_ordinal: u64,
    event_sha256: InlineSha256Digest,
    resulting_head_sha256: InlineSha256Digest,
    signed_receipt_sha256: InlineSha256Digest,
    retrieval_id_sha256: InlineSha256Digest,
    retrieval_proof_sha256: InlineSha256Digest,
    verified_payload_sha256: InlineSha256Digest,
    verified_trust_checkpoint_sha256: InlineSha256Digest,
    active_effect_owner: ShadowRequestHandle,
    provider_send_permit: Option<ShadowActiveEffectPermit>,
    secondary_effect_permit: Option<ShadowActiveEffectPermit>,
}

impl ShadowDispatchBarrierPermit {
    pub(crate) fn authorizes_credentialed_send(
        &self,
        final_upstream_request_commitment_sha256: &str,
    ) -> bool {
        self.ingress_sequence > 0
            && self.request_binding_sha256.is_canonical()
            && self.request_commitment_sha256.is_canonical()
            && self.active_plan_sha256.is_canonical()
            && self.decision_at_epoch_ms > 0
            && self
                .final_upstream_request_commitment_sha256
                .matches_str(final_upstream_request_commitment_sha256)
            && self.final_upstream_request_commitment_sha256
                .is_canonical()
            && self
                .effect_authority_commitments_sha256
                .is_canonical()
            && self.generation_id.is_canonical()
            && self.event_ordinal > 0
            && self.event_sha256.is_canonical()
            && self.resulting_head_sha256.is_canonical()
            && self.signed_receipt_sha256.is_canonical()
            && self.retrieval_id_sha256.is_canonical()
            && self.retrieval_proof_sha256.is_canonical()
            && self.verified_payload_sha256.is_canonical()
            && self
                .verified_trust_checkpoint_sha256
                .is_canonical()
            && self.provider_send_permit.is_some()
    }

    pub(crate) fn commit_provider_send(
        mut self,
        terminal_state: ActiveEffectCommitState,
        result_sha256: &str,
    ) -> Result<(), String> {
        let permit = self.provider_send_permit.take().ok_or_else(|| {
            "provider-send effect permit was already consumed".to_string()
        })?;
        self.active_effect_owner
            .commit_mutable_effect(permit, terminal_state, result_sha256)
            .map(|_| ())?;
        if let Some(secondary) = self.secondary_effect_permit.take() {
            self.active_effect_owner
                .commit_mutable_effect(
                    secondary,
                    terminal_state,
                    result_sha256,
                )
                .map(|_| ())?;
        }
        Ok(())
    }
}

impl AccountingLedger {
    fn new(
        custody: Arc<OnceLock<Arc<dyn PolicyShadowCustodyRpcSupervisor>>>,
    ) -> Self {
        let receipt_arena = PolicyCoreModeledReceiptArena::try_new(
            SHADOW_MODELED_RECEIPT_REFERENCE_CAPACITY,
        );
        let receipt_index = ReceiptMetadataIndex::try_new();
        let receipt_arena_ready =
            receipt_arena.is_ok() && receipt_index.is_ok();
        Self {
            state: Mutex::new(AccountingState {
                generations: GenerationAccountingTable::new(),
                receipt_arena: receipt_arena
                    .unwrap_or_else(|_| {
                        PolicyCoreModeledReceiptArena::unavailable()
                    }),
                receipt_index: receipt_index.unwrap_or_else(|_| {
                    ReceiptMetadataIndex::unavailable()
                }),
                last_unavailable_receipt_sha256: None,
                last_unavailable_event_ordinal: 0,
                last_unavailable_head_sha256: None,
                last_unavailable_retrieval_id_sha256: None,
                unavailable_backpressure: false,
                highest_generation_epoch: 0,
                highest_generation_tombstone_epoch: 0,
                highest_assignment_revision: 0,
                unrecoverable_local_failure: !receipt_arena_ready,
                hard_unready: true,
            }),
            append_reconcile_lanes: std::array::from_fn(|_| Mutex::new(())),
            custody,
            hard_unready_signal: AtomicBool::new(!receipt_arena_ready),
            compaction_in_progress: AtomicBool::new(false),
        }
    }

    fn bind_custody(
        &self,
        custody: Arc<dyn PolicyShadowCustodyRpcSupervisor>,
    ) -> Result<(), String> {
        if custody
            .production_configuration_binding_sha256()
            .is_none()
            || custody.persistence_proof_verifier().is_none()
        {
            self.mark_hard_unready();
            return Err(
                "shadow runtime requires the killable production custody RPC supervisor with signer, persistence, and retrieval hooks"
                    .to_string(),
            );
        }
        if let Some(bound) = self.custody.get() {
            return if Arc::ptr_eq(bound, &custody) {
                Ok(())
            } else {
                Err(
                    "shadow runtime is already bound to a different custody authority"
                        .to_string(),
                )
            };
        }
        self.custody
            .set(custody)
            .map_err(|_| "shadow custody authority could not be bound".to_string())
    }

    fn reserve_reconciliation_capacity(
        &self,
        generation_id: Option<&str>,
    ) -> Option<ReceiptReconciliationCapacity<'_>> {
        let Ok(mut state) = self.state.try_lock() else {
            self.mark_hard_unready();
            return None;
        };
        let scope = if let Some(generation_id) = generation_id {
            let Some(generation) =
                state.generations.iter().find(|generation| {
                    generation.generation_id == generation_id
                        && !generation.spool_backpressure
                })
            else {
                state.hard_unready = true;
                self.hard_unready_signal.store(true, Ordering::Release);
                return None;
            };
            ReceiptReservationScope::Spill {
                lane: generation.receipt_arena_lane,
            }
        } else {
            ReceiptReservationScope::Unavailable
        };
        if state.receipt_index.reserve_scope(scope).is_err() {
            state.hard_unready = true;
            if generation_id.is_none() {
                state.unavailable_backpressure = true;
            }
            self.hard_unready_signal.store(true, Ordering::Release);
            return None;
        }
        match state.receipt_arena.reserve(
            ModeledReservationKind::Reconciliation,
            SHADOW_RECEIPT_TRANSIENT_RESERVATION_BYTES,
        ) {
            Ok(reservation) => Some(ReceiptReconciliationCapacity {
                ledger: self,
                reservation,
                scope,
                modeled_bytes:
                    SHADOW_RECEIPT_TRANSIENT_RESERVATION_BYTES,
            }),
            Err(_) => {
                let _ = state.receipt_index.release_scope(scope);
                state.hard_unready = true;
                if generation_id.is_none() {
                    state.unavailable_backpressure = true;
                }
                self.hard_unready_signal
                    .store(true, Ordering::Release);
                None
            }
        }
    }

    fn prepare_generation_locked(
        state: &mut AccountingState,
        generation: &ShadowGeneration,
        custody_prepare: &PreparedGenerationPublication,
    ) -> Result<usize, String> {
        if state.generations.len() >= SHADOW_MAX_ACCOUNTING_GENERATIONS {
            state.hard_unready = true;
            return Err(
                "authenticated custody compaction is required before generation preparation"
                    .to_string(),
            );
        }
        if generation.identity.generation_epoch <= state.highest_generation_epoch
            || generation.identity.generation_tombstone_epoch
                < state.highest_generation_tombstone_epoch
            || generation.identity.assignment_revision <= state.highest_assignment_revision
            || state
                .generations
                .iter()
                .any(|entry| entry.generation_id == generation.generation_id())
        {
            return Err("shadow generation identity was already installed".to_string());
        }
        let generation_id =
            InlineSha256Digest::from_str(generation.generation_id())?;
        let (spill_predecessor_event_ordinal, spill_predecessor_head_sha256) =
            custody_prepare.spill_predecessor();
        let spill_predecessor_head_sha256 =
            InlineSha256Digest::from_digest(spill_predecessor_head_sha256)?;
        let receipt_arena_lane =
            state.receipt_index.allocate_spill_lane()?;
        let accounting = GenerationAccounting::prepared(
            generation_id,
            generation.identity.generation_epoch,
            receipt_arena_lane,
            spill_predecessor_event_ordinal,
            spill_predecessor_head_sha256,
        );
        if let Err(error) = state.generations.push_back(accounting) {
            let _ = state
                .receipt_index
                .release_spill_lane(receipt_arena_lane);
            state.hard_unready = true;
            return Err(error);
        }
        Ok(state.generations.len() - 1)
    }

    fn abort_prepared_generation_locked(
        state: &mut AccountingState,
        index: usize,
        generation_id: &str,
    ) {
        if state.generations.get(index).is_some_and(|entry| {
            entry.prepared && entry.generation_id == generation_id
        }) {
            if let Some(removed) = state.generations.remove(index) {
                if state
                    .receipt_index
                    .release_spill_lane(removed.receipt_arena_lane)
                    .is_err()
                {
                    state.hard_unready = true;
                }
            }
        }
    }

    fn record_unavailable(
        &self,
        receipt: VerifiedUnavailableGenerationReceipt,
    ) -> bool {
        let modeled_reference =
            match ImmutableUnavailableReceiptRef::modeled_reference(&receipt) {
                Ok(reference) => reference,
                Err(_) => {
                    self.mark_hard_unready();
                    return false;
                }
            };
        let Ok(mut state) = self.state.try_lock() else {
            self.mark_hard_unready();
            return false;
        };
        let previous_unavailable_ordinal =
            state.last_unavailable_event_ordinal;
        let adjacent_to_previous = previous_unavailable_ordinal != 0
            && receipt.predecessor_event_ordinal()
                == previous_unavailable_ordinal;
        if receipt.event_ordinal() <= previous_unavailable_ordinal
            || receipt.predecessor_event_ordinal()
                < previous_unavailable_ordinal
            || adjacent_to_previous
                && state
                    .last_unavailable_head_sha256
                    .as_ref()
                    .is_none_or(|head| {
                        !head.matches_digest(
                            receipt.predecessor_head_sha256(),
                        )
                    })
        {
            state.unrecoverable_local_failure = true;
            state.hard_unready = true;
            self.hard_unready_signal.store(true, Ordering::Release);
            return false;
        }
        let modeled_handle =
            match state.receipt_arena.insert(modeled_reference) {
                Ok(handle) => handle,
                Err(_) => {
                    state.unavailable_backpressure = true;
                    state.unrecoverable_local_failure = true;
                    state.hard_unready = true;
                    self.hard_unready_signal
                        .store(true, Ordering::Release);
                    return false;
                }
            };
        let receipt_ref =
            match ImmutableUnavailableReceiptRef::from_verified(
                &receipt,
                modeled_handle,
            ) {
                Ok(reference) => reference,
                Err(_) => {
                    let _ = state.receipt_arena.remove(modeled_handle);
                    state.unavailable_backpressure = true;
                    state.unrecoverable_local_failure = true;
                    state.hard_unready = true;
                    self.hard_unready_signal
                        .store(true, Ordering::Release);
                    return false;
                }
            };
        if state
            .receipt_index
            .push_unavailable(receipt_ref)
            .is_err()
        {
            let _ = state.receipt_arena.remove(modeled_handle);
            state.unavailable_backpressure = true;
            state.unrecoverable_local_failure = true;
            state.hard_unready = true;
            self.hard_unready_signal.store(true, Ordering::Release);
            return false;
        }
        state.last_unavailable_event_ordinal = receipt.event_ordinal();
        state.last_unavailable_head_sha256 =
            Some(receipt_ref.resulting_head_sha256);
        state.last_unavailable_receipt_sha256 =
            Some(receipt_ref.signed_receipt_sha256);
        state.last_unavailable_retrieval_id_sha256 =
            Some(receipt_ref.retrieval_id_sha256);
        state.hard_unready = true;
        !state.unavailable_backpressure
    }

    fn record_admission(
        &self,
        admission: &PersistedIngressAdmission,
    ) -> bool {
        let lane_index = usize::try_from(
            admission.ingress_sequence()
                % u64::try_from(SHADOW_APPEND_RECONCILE_LANES)
                    .unwrap_or(1),
        )
        .unwrap_or(0);
        let Ok(_lane_guard) =
            self.append_reconcile_lanes[lane_index].try_lock()
        else {
            self.mark_hard_unready();
            return false;
        };
        let Ok(mut state) = self.state.try_lock() else {
            self.mark_hard_unready();
            return false;
        };
        let Some(index) = state.generations.iter().position(|entry| {
            entry.generation_id == admission.generation_id().as_str()
        }) else {
            state.hard_unready = true;
            return false;
        };
        let receipt = admission.opening_spill_receipt();
        let opening_event = match ShadowSpoolEvent::new(
            admission.generation_id().clone(),
            admission.ingress_sequence(),
            admission.request_binding_sha256().clone(),
            admission.request_commitment_sha256().clone(),
            ShadowSpoolPhase::IngressOpen,
            receipt.event_sha256().clone(),
            receipt.canonical_event_bytes().to_vec(),
        ) {
            Ok(event) => event,
            Err(_) => {
                state.generations[index].permanent_readiness_invalid = true;
                state.hard_unready = true;
                return false;
            }
        };
        if !receipt.matches_opening(
            admission.generation_id(),
            admission.ingress_sequence(),
            admission.request_binding_sha256(),
        ) || !receipt.matches_event(&opening_event)
        {
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return false;
        }
        let modeled_reference =
            match ImmutableSpillReceiptRef::modeled_reference(
                receipt,
                state.generations[index].generation_epoch,
            ) {
                Ok(reference) => reference,
                Err(_) => {
                    state.generations[index]
                        .permanent_readiness_invalid = true;
                    state.hard_unready = true;
                    return false;
                }
            };
        let receipt_arena_lane =
            state.generations[index].receipt_arena_lane;
        if state.receipt_index.spill_len(receipt_arena_lane)
                >= SHADOW_SPOOL_RECEIPT_CACHE_ITEMS
            || state
                .receipt_index
                .spill_iter(receipt_arena_lane)
                .any(|cached| {
                    cached.event_ordinal() == receipt.event_ordinal()
                        || cached
                            .signed_receipt_sha256()
                            .matches_digest(
                                receipt.signed_receipt_sha256(),
                            )
                })
        {
            state.generations[index].spool_backpressure = true;
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return false;
        }
        let insert_at = state
            .receipt_index
            .spill_iter(receipt_arena_lane)
            .position(|cached| {
                cached.event_ordinal() > receipt.event_ordinal()
            })
            .unwrap_or_else(|| {
                state.receipt_index.spill_len(receipt_arena_lane)
            });
        let modeled_handle =
            match state.receipt_arena.insert(modeled_reference) {
                Ok(handle) => handle,
                Err(_) => {
                    state.generations[index].spool_backpressure = true;
                    state.generations[index].permanent_readiness_invalid =
                        true;
                    state.hard_unready = true;
                    return false;
                }
            };
        let receipt_ref = match ImmutableSpillReceiptRef::from_verified(
            receipt,
            modeled_handle,
        ) {
            Ok(reference) => reference,
            Err(_) => {
                let _ = state.receipt_arena.remove(modeled_handle);
                state.generations[index].spool_backpressure = true;
                state.generations[index].permanent_readiness_invalid = true;
                state.hard_unready = true;
                return false;
            }
        };
        if state
            .receipt_index
            .insert_spill(receipt_arena_lane, insert_at, receipt_ref)
            .is_err()
        {
            let _ = state.receipt_arena.remove(modeled_handle);
            state.generations[index].spool_backpressure = true;
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return false;
        }
        let mut contiguous_ordinal =
            state.generations[index].last_spill_event_ordinal;
        let mut contiguous_head =
            state.generations[index].last_spill_head_sha256;
        for cached in state.receipt_index.spill_iter(receipt_arena_lane) {
            if cached.event_ordinal() <= contiguous_ordinal {
                continue;
            }
            let Some(next_ordinal) = contiguous_ordinal.checked_add(1)
            else {
                return false;
            };
            if cached.event_ordinal() != next_ordinal
                || cached.predecessor_event_ordinal()
                    != contiguous_ordinal
                || cached.predecessor_head_sha256() != &contiguous_head
            {
                break;
            }
            contiguous_ordinal = cached.event_ordinal();
            contiguous_head = *cached.resulting_head_sha256();
        }
        let cached_receipt_items =
            state.receipt_index.spill_len(receipt_arena_lane);
        let cached_receipt_bytes =
            state
                .receipt_index
                .modeled_spill_reference_bytes(receipt_arena_lane);
        let last_cached_event_ordinal = state
            .receipt_index
            .spill_get(
                receipt_arena_lane,
                cached_receipt_items.saturating_sub(1),
            )
            .map(ImmutableSpillReceiptRef::event_ordinal);
        let accounting = &mut state.generations[index];
        accounting.counters.admitted =
            accounting.counters.admitted.saturating_add(1);
        accounting.last_spill_receipt_sha256 =
            Some(receipt_ref.signed_receipt_sha256);
        accounting.last_spill_event_ordinal = contiguous_ordinal;
        accounting.last_spill_head_sha256 = contiguous_head;
        accounting.local_ordering_gap = last_cached_event_ordinal
            .is_some_and(|ordinal| ordinal != contiguous_ordinal);
        accounting.compaction_requested |=
            !accounting.local_ordering_gap
                && (cached_receipt_items
                    >= SHADOW_SPOOL_COMPACTION_TRIGGER_ITEMS
                    || cached_receipt_bytes
                        >= SHADOW_MODELED_RECEIPT_COMPACTION_TRIGGER_BYTES);
        true
    }

    fn mark_hard_unready(&self) {
        self.hard_unready_signal.store(true, Ordering::Release);
        if let Ok(mut state) = self.state.try_lock() {
            state.unrecoverable_local_failure = true;
            state.hard_unready = true;
        }
    }

    fn record(
        &self,
        generation_id: &str,
        record: ShadowAccountingEvent,
        admitted: bool,
    ) -> bool {
        self.record_with_receipt(generation_id, record, admitted)
            .is_some()
    }

    fn record_with_receipt(
        &self,
        generation_id: &str,
        record: ShadowAccountingEvent,
        _admitted: bool,
    ) -> Option<DurableShadowEventReceipt> {
        let generation_id_digest = match Sha256Digest::parse(
            generation_id.to_string(),
        ) {
            Ok(value) => value,
            Err(_) => {
                self.mark_hard_unready();
                return None;
            }
        };
        let reconciliation_capacity = self
            .reserve_reconciliation_capacity(Some(generation_id))?;
        let request_binding_sha256 = match Sha256Digest::parse(
            record.request_binding_sha256.clone(),
        ) {
            Ok(value) => value,
            Err(_) => {
                self.mark_hard_unready();
                return None;
            }
        };
        let request_commitment_sha256 = match Sha256Digest::parse(
            record.request_commitment_sha256.clone(),
        ) {
            Ok(value) => value,
            Err(_) => {
                self.mark_hard_unready();
                return None;
            }
        };
        let canonical_event_bytes = match record.canonical_bytes() {
            Ok(value) => value,
            Err(_) => {
                self.mark_hard_unready();
                return None;
            }
        };
        if !reconciliation_capacity
            .authorizes_event_payload(canonical_event_bytes.len())
        {
            return None;
        }
        let event_sha256 = Sha256Digest::compute(&canonical_event_bytes);
        let event = match ShadowSpoolEvent::new(
            generation_id_digest,
            record.ingress_sequence,
            request_binding_sha256,
            request_commitment_sha256,
            record.spool_phase(),
            event_sha256,
            canonical_event_bytes,
        ) {
            Ok(event) => event,
            Err(_) => {
                self.mark_hard_unready();
                return None;
            }
        };
        let custody = self.custody.get().cloned();
        let Some(custody) = custody else {
            self.mark_hard_unready();
            return None;
        };
        let terminal_phase = matches!(
            event.phase(),
            ShadowSpoolPhase::PreDispatchTerminal
                | ShadowSpoolPhase::PostDispatchTerminal
        );
        let (receipt, custody_completed) = if terminal_phase {
            let context = match custody_call_context(
                custody.as_ref(),
                PolicyShadowCustodyOperation::AppendTerminal,
                "append-terminal",
                event.event_sha256().as_str(),
            ) {
                Ok(context) => context,
                Err(_) => {
                    self.mark_hard_unready();
                    return None;
                }
            };
            let request = match TerminalSlotAppendRequest::new(event.clone()) {
                Ok(request) => request,
                Err(_) => {
                    self.mark_hard_unready();
                    return None;
                }
            };
            let outcome = custody.append_terminal(&context, &request);
            let completed = finish_custody_call(custody.as_ref(), context);
            let receipt = match matching_terminal_append_receipt(&event, outcome) {
                Some(receipt) => receipt,
                None => {
                    self.mark_hard_unready();
                    return None;
                }
            };
            (receipt, completed)
        } else {
            let reserve_context = match custody_call_context(
                custody.as_ref(),
                PolicyShadowCustodyOperation::ReserveSpoolAppend,
                "reserve-spool-append",
                event.event_sha256().as_str(),
            ) {
                Ok(context) => context,
                Err(_) => {
                    self.mark_hard_unready();
                    return None;
                }
            };
            let reservation =
                custody.reserve_spool_append(&reserve_context, &event);
            if !finish_custody_call(custody.as_ref(), reserve_context) {
                self.mark_hard_unready();
                return None;
            }
            match reservation {
                Ok(SpoolAppendReservationOutcome::Reserved(reservation))
                    if reservation.matches_event(&event) =>
                {
                    let reserved_event_ordinal =
                        reservation.event_ordinal();
                    let (
                        reserved_predecessor_ordinal,
                        reserved_predecessor_head,
                    ) = reservation.predecessor();
                    let reserved_predecessor_head =
                        reserved_predecessor_head.clone();
                    let append_context = match custody_call_context(
                        custody.as_ref(),
                        PolicyShadowCustodyOperation::AppendSpoolEvent,
                        "append-spool-event",
                        event.event_sha256().as_str(),
                    ) {
                        Ok(context) => context,
                        Err(_) => {
                            self.mark_hard_unready();
                            return None;
                        }
                    };
                    let receipt = match custody.append_spool_event(
                        &append_context,
                        reservation,
                        &event,
                    ) {
                        Ok(receipt) => receipt,
                        Err(_) => {
                            self.mark_hard_unready();
                            return None;
                        }
                    };
                    let completed =
                        finish_custody_call(custody.as_ref(), append_context);
                    if !receipt.matches_event_and_predecessor(
                        &event,
                        reserved_predecessor_ordinal,
                        &reserved_predecessor_head,
                    ) || receipt.event_ordinal()
                        != reserved_event_ordinal
                    {
                        self.mark_hard_unready();
                        return None;
                    }
                    (receipt, completed)
                }
                Ok(SpoolAppendReservationOutcome::Unavailable(receipt))
                    if receipt.matches_event(&event)
                        && receipt.disposition()
                            == ShadowSpoolDisposition::Unavailable =>
                {
                    (receipt, true)
                }
                _ => {
                    self.mark_hard_unready();
                    return None;
                }
            }
        };
        let spool_appended =
            receipt.disposition() == ShadowSpoolDisposition::Appended
                && custody_completed;
        let lane_index = usize::try_from(
            record.ingress_sequence
                % u64::try_from(SHADOW_APPEND_RECONCILE_LANES)
                    .unwrap_or(1),
        )
        .unwrap_or(0);
        let Ok(_lane_guard) =
            self.append_reconcile_lanes[lane_index].try_lock()
        else {
            self.mark_hard_unready();
            return None;
        };
        let durable_receipt;
        {
            let Ok(mut state) = self.state.try_lock() else {
                self.mark_hard_unready();
                return None;
            };
            let Some(index) = state
                .generations
                .iter()
                .position(|entry| entry.generation_id == generation_id)
            else {
                state.hard_unready = true;
                return None;
            };
            let modeled_reference =
                match ImmutableSpillReceiptRef::modeled_reference(
                    &receipt,
                    state.generations[index].generation_epoch,
                ) {
                    Ok(reference) => reference,
                    Err(_) => {
                        state.generations[index]
                            .permanent_readiness_invalid = true;
                        state.hard_unready = true;
                        return None;
                    }
                };
            let receipt_arena_lane =
                state.generations[index].receipt_arena_lane;
            let cached = state
                .receipt_index
                .spill_iter(receipt_arena_lane)
                .find(|cached| {
                    cached.event_ordinal() == receipt.event_ordinal()
                        || cached
                            .signed_receipt_sha256()
                            .matches_digest(receipt.signed_receipt_sha256())
                })
                .copied();
            if let Some(cached) = cached {
                if terminal_phase
                    && cached.event_ordinal() == receipt.event_ordinal()
                    && cached
                        .event_sha256()
                        .matches_digest(receipt.event_sha256())
                    && cached
                        .signed_receipt_sha256()
                        .matches_digest(receipt.signed_receipt_sha256())
                {
                    return spool_appended.then_some(
                        cached.durable_receipt(
                            receipt.ingress_sequence(),
                        ),
                    );
                }
                state.generations[index].permanent_readiness_invalid = true;
                state.hard_unready = true;
                return None;
            }
            let spool_unavailable =
                receipt.disposition() == ShadowSpoolDisposition::Unavailable;
            if state.receipt_index.spill_len(receipt_arena_lane)
                >= SHADOW_SPOOL_RECEIPT_CACHE_ITEMS
            {
                state.generations[index].spool_backpressure = true;
                state.generations[index].permanent_readiness_invalid = true;
                state.hard_unready = true;
                return None;
            }
            let insert_at = state
                .receipt_index
                .spill_iter(receipt_arena_lane)
                .position(|cached| {
                    cached.event_ordinal() > receipt.event_ordinal()
                })
                .unwrap_or_else(|| {
                    state.receipt_index.spill_len(receipt_arena_lane)
                });
            let modeled_handle =
                match state.receipt_arena.insert(modeled_reference) {
                    Ok(handle) => handle,
                    Err(_) => {
                        state.generations[index].spool_backpressure = true;
                        state.generations[index]
                            .permanent_readiness_invalid = true;
                        state.hard_unready = true;
                        return None;
                    }
                };
            let receipt_ref =
                match ImmutableSpillReceiptRef::from_verified(
                    &receipt,
                    modeled_handle,
                ) {
                    Ok(reference) => reference,
                    Err(_) => {
                        let _ =
                            state.receipt_arena.remove(modeled_handle);
                        state.generations[index].spool_backpressure = true;
                        state.generations[index]
                            .permanent_readiness_invalid = true;
                        state.hard_unready = true;
                        return None;
                    }
                };
            if state
                .receipt_index
                .insert_spill(
                    receipt_arena_lane,
                    insert_at,
                    receipt_ref,
                )
                .is_err()
            {
                let _ = state.receipt_arena.remove(modeled_handle);
                state.generations[index].spool_backpressure = true;
                state.generations[index].permanent_readiness_invalid = true;
                state.hard_unready = true;
                return None;
            }
            durable_receipt =
                receipt_ref.durable_receipt(receipt.ingress_sequence());
            state.generations[index].increment(record.event);
            state.generations[index].last_spill_receipt_sha256 =
                Some(receipt_ref.signed_receipt_sha256);
            let mut contiguous_ordinal =
                state.generations[index].last_spill_event_ordinal;
            let mut contiguous_head =
                state.generations[index].last_spill_head_sha256;
            for cached in state.receipt_index.spill_iter(receipt_arena_lane) {
                if cached.event_ordinal() <= contiguous_ordinal {
                    continue;
                }
                let Some(next_ordinal) = contiguous_ordinal.checked_add(1)
                else {
                    return None;
                };
                if cached.event_ordinal() != next_ordinal
                    || cached.predecessor_event_ordinal()
                        != contiguous_ordinal
                    || cached.predecessor_head_sha256()
                        != &contiguous_head
                {
                    break;
                }
                contiguous_ordinal = cached.event_ordinal();
                contiguous_head = *cached.resulting_head_sha256();
            }
            let cached_receipt_items =
                state.receipt_index.spill_len(receipt_arena_lane);
            let cached_receipt_bytes =
                state
                    .receipt_index
                    .modeled_spill_reference_bytes(receipt_arena_lane);
            let last_cached_event_ordinal = state
                .receipt_index
                .spill_get(
                    receipt_arena_lane,
                    cached_receipt_items.saturating_sub(1),
                )
                .map(ImmutableSpillReceiptRef::event_ordinal);
            if spool_unavailable {
                state.hard_unready = true;
            }
            let accounting = &mut state.generations[index];
            accounting.last_spill_event_ordinal = contiguous_ordinal;
            accounting.last_spill_head_sha256 = contiguous_head;
            accounting.local_ordering_gap = last_cached_event_ordinal
                .is_some_and(|ordinal| ordinal != contiguous_ordinal);
            if spool_unavailable {
                accounting.spool_backpressure = true;
                accounting.permanent_readiness_invalid = true;
            }
            accounting.compaction_requested |=
                !accounting.local_ordering_gap
                    && (cached_receipt_items
                        >= SHADOW_SPOOL_COMPACTION_TRIGGER_ITEMS
                        || cached_receipt_bytes
                            >= SHADOW_MODELED_RECEIPT_COMPACTION_TRIGGER_BYTES);
        }
        if !spool_appended {
            self.mark_hard_unready();
        }
        spool_appended.then_some(durable_receipt)
    }

    fn apply_custody_compaction(
        &self,
        custody: &dyn PolicyShadowCustodyRpcSupervisor,
        request: &AuthenticatedSpoolCompactionRequest,
    ) -> bool {
        let context = match custody_call_context(
            custody,
            PolicyShadowCustodyOperation::CompactSpool,
            "compact-spool",
            request.old_spool_head_sha256().as_str(),
        ) {
            Ok(context) => context,
            Err(_) => {
                self.compaction_in_progress
                    .store(false, Ordering::Release);
                self.mark_hard_unready();
                return false;
            }
        };
        let receipt = custody.compact_spool(&context, request);
        let completed = finish_custody_call(custody, context);
        let compacted = completed
            && receipt
                .map_err(shadow_error)
                .and_then(|receipt| {
                    if receipt.matches_request(request) {
                        self.apply_authenticated_compaction(
                            request,
                            &receipt,
                        )
                    } else {
                        Err(
                            "custody compaction receipt does not match request"
                                .to_string(),
                        )
                    }
                })
                .is_ok();
        self.compaction_in_progress
            .store(false, Ordering::Release);
        if !compacted {
            self.mark_hard_unready();
        }
        compacted
    }

    fn compact_one_requested(&self) {
        if self
            .compaction_in_progress
            .compare_exchange(
                false,
                true,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let request = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(index) = state.generations.iter().position(|entry| {
                entry.compaction_requested
                    && !entry.local_ordering_gap
                    && state
                        .receipt_index
                        .spill_len(entry.receipt_arena_lane)
                        >= SHADOW_SPOOL_COMPACTION_PREFIX_ITEMS
            }) else {
                self.compaction_in_progress
                    .store(false, Ordering::Release);
                return;
            };
            let scope = ReceiptReservationScope::Compaction;
            if state.receipt_index.reserve_scope(scope).is_err() {
                state.generations[index].permanent_readiness_invalid = true;
                state.hard_unready = true;
                self.compaction_in_progress
                    .store(false, Ordering::Release);
                self.hard_unready_signal
                    .store(true, Ordering::Release);
                return;
            }
            let reservation = match state.receipt_arena.reserve(
                ModeledReservationKind::Compaction,
                SHADOW_RECEIPT_COMPACTION_TRANSIENT_BYTES,
            ) {
                Ok(reservation) => reservation,
                Err(_) => {
                    let _ = state.receipt_index.release_scope(scope);
                    state.generations[index]
                        .permanent_readiness_invalid = true;
                    state.hard_unready = true;
                    self.compaction_in_progress
                        .store(false, Ordering::Release);
                    self.hard_unready_signal
                        .store(true, Ordering::Release);
                    return;
                }
            };
            state.generations[index].compaction_requested = false;
            match Self::compaction_request(
                &state.generations[index],
                &state.receipt_index,
            ) {
                Ok(request) => (request, reservation, scope),
                Err(_) => {
                    let _ = state.receipt_arena.release(reservation);
                    let _ = state.receipt_index.release_scope(scope);
                    state.generations[index].permanent_readiness_invalid = true;
                    state.hard_unready = true;
                    self.compaction_in_progress
                        .store(false, Ordering::Release);
                    self.hard_unready_signal
                        .store(true, Ordering::Release);
                    return;
                }
            }
        };
        let (request, reservation, scope) = request;
        let _capacity = ReceiptReconciliationCapacity {
            ledger: self,
            reservation,
            scope,
            modeled_bytes:
                SHADOW_RECEIPT_COMPACTION_TRANSIENT_BYTES,
        };
        let Some(custody) = self.custody.get() else {
            self.compaction_in_progress
                .store(false, Ordering::Release);
            self.mark_hard_unready();
            return;
        };
        if !self.apply_custody_compaction(custody.as_ref(), &request) {
            self.mark_hard_unready();
        }
    }

    fn compaction_request(
        accounting: &GenerationAccounting,
        receipt_index: &ReceiptMetadataIndex,
    ) -> Result<AuthenticatedSpoolCompactionRequest, String> {
        let compacted = receipt_index
            .spill_iter(accounting.receipt_arena_lane)
            .take(SHADOW_SPOOL_COMPACTION_PREFIX_ITEMS)
            .collect::<Vec<_>>();
        if compacted.len() != SHADOW_SPOOL_COMPACTION_PREFIX_ITEMS {
            return Err("insufficient ordered spill prefix".to_string());
        }
        if compacted.windows(2).any(|pair| {
            pair[0]
                .event_ordinal()
                .checked_add(1)
                .is_none_or(|next| pair[1].event_ordinal() != next)
                || pair[1].predecessor_event_ordinal()
                    != pair[0].event_ordinal()
                || pair[1].predecessor_head_sha256()
                    != pair[0].resulting_head_sha256()
        }) {
            return Err(
                "spill compaction prefix is not an exact predecessor chain"
                    .to_string(),
            );
        }
        let first = compacted
            .first()
            .ok_or_else(|| "compaction prefix is empty".to_string())?;
        let last = compacted
            .last()
            .ok_or_else(|| "compaction prefix is empty".to_string())?;
        let compacted_record_count = u64::try_from(compacted.len())
            .map_err(|_| "compaction record count exceeds u64".to_string())?;
        let ordered_range_root = canonical_digest(&json!({
            "domain":"serverware.policyShadowSpoolCompactedOrderedRange/v1",
            "generationId":accounting.generation_id,
            "firstEventOrdinal":first.event_ordinal(),
            "lastEventOrdinal":last.event_ordinal(),
            "recordCount":compacted_record_count,
            "receipts":compacted.iter().map(|receipt| json!({
                "eventOrdinal":receipt.event_ordinal(),
                "eventSha256":receipt.event_sha256(),
                "canonicalEventLength":receipt.canonical_event_length,
                "canonicalEventSha256":receipt.canonical_event_sha256,
                "predecessorEventOrdinal":receipt.predecessor_event_ordinal(),
                "predecessorHeadSha256":receipt.predecessor_head_sha256(),
                "resultingHeadSha256":receipt.resulting_head_sha256(),
                "signedReceiptSha256":receipt.signed_receipt_sha256(),
                "retrievalIdSha256":receipt.retrieval_id_sha256,
                "retrievalProofSha256":receipt.retrieval_proof_sha256,
            })).collect::<Vec<_>>(),
        }))?;
        let retained = receipt_index.spill_get(
            accounting.receipt_arena_lane,
            SHADOW_SPOOL_COMPACTION_PREFIX_ITEMS,
        );
        let retained_ordinal =
            retained.map(|receipt| receipt.event_ordinal());
        let retained_head = retained
            .map(|receipt| receipt.resulting_head_sha256().to_digest())
            .transpose()?;
        let expected_new_root = canonical_digest(&json!({
            "domain":"serverware.policyShadowCompactedSpoolRoot/v1",
            "generationId":accounting.generation_id,
            "oldSpoolHeadSha256":accounting.last_spill_head_sha256,
            "compactedOrderedRangeRootSha256":ordered_range_root,
            "compactedRecordCount":compacted_record_count,
            "retainedSuccessorEventOrdinal":retained_ordinal,
            "retainedSuccessorHeadSha256":retained_head,
        }))?;
        AuthenticatedSpoolCompactionRequest::new(
            accounting.generation_id.to_digest()?,
            accounting.last_spill_head_sha256.to_digest()?,
            first.event_ordinal(),
            last.event_ordinal(),
            ordered_range_root,
            compacted_record_count,
            last.signed_receipt_sha256().to_digest()?,
            retained_ordinal,
            retained_head,
            expected_new_root,
        )
        .map_err(shadow_error)
    }

    fn apply_authenticated_compaction(
        &self,
        request: &AuthenticatedSpoolCompactionRequest,
        receipt: &VerifiedSpoolCompactionReceipt,
    ) -> Result<(), String> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(index) = state
            .generations
            .iter()
            .position(|entry| {
                entry.generation_id == receipt.generation_id().as_str()
            })
        else {
            state.hard_unready = true;
            return Err(
                "compaction receipt generation is not retained".to_string(),
            );
        };
        if !receipt.matches_request(request) {
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return Err(
                "compaction receipt does not authenticate the exact request"
                    .to_string(),
            );
        }
        let expected_count = usize::try_from(receipt.compacted_record_count())
            .map_err(|_| "compaction record count exceeds usize".to_string())?;
        let accounting = &state.generations[index];
        let receipt_arena_lane = accounting.receipt_arena_lane;
        if expected_count == 0
            || state.receipt_index.spill_len(receipt_arena_lane)
                < expected_count
            || state
                .receipt_index
                .spill_get(receipt_arena_lane, 0)
                .is_none_or(|first| {
                    first.event_ordinal()
                        != receipt.compacted_first_event_ordinal()
                })
            || state
                .receipt_index
                .spill_get(receipt_arena_lane, expected_count - 1)
                .is_none_or(|last| {
                    last.event_ordinal()
                        != receipt.compacted_through_event_ordinal()
                        || !last
                            .signed_receipt_sha256()
                            .matches_digest(
                                receipt
                                    .compacted_through_spill_receipt_sha256(),
                            )
                })
        {
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return Err(
                "compaction receipt range is not the retained ordered prefix"
                    .to_string(),
            );
        }
        let exact_root = {
            let accounting = &state.generations[index];
            canonical_digest(&json!({
                "domain":"serverware.policyShadowSpoolCompactedOrderedRange/v1",
                "generationId":accounting.generation_id,
                "firstEventOrdinal":receipt.compacted_first_event_ordinal(),
                "lastEventOrdinal":receipt.compacted_through_event_ordinal(),
                "recordCount":receipt.compacted_record_count(),
                "receipts":state.receipt_index.spill_iter(receipt_arena_lane).take(expected_count).map(|cached| json!({
                    "eventOrdinal":cached.event_ordinal(),
                    "eventSha256":cached.event_sha256(),
                    "canonicalEventLength":cached.canonical_event_length,
                    "canonicalEventSha256":cached.canonical_event_sha256,
                    "predecessorEventOrdinal":cached.predecessor_event_ordinal(),
                    "predecessorHeadSha256":cached.predecessor_head_sha256(),
                    "resultingHeadSha256":cached.resulting_head_sha256(),
                    "signedReceiptSha256":cached.signed_receipt_sha256(),
                    "retrievalIdSha256":cached.retrieval_id_sha256,
                    "retrievalProofSha256":cached.retrieval_proof_sha256,
                })).collect::<Vec<_>>(),
            }))?
        };
        if &exact_root != receipt.compacted_ordered_range_root_sha256() {
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return Err(
                "compaction receipt ordered range root mismatch".to_string(),
            );
        }
        let (retained_ordinal, retained_head) =
            receipt.retained_successor();
        let expected_new_root = canonical_digest(&json!({
            "domain":"serverware.policyShadowCompactedSpoolRoot/v1",
            "generationId":state.generations[index].generation_id,
            "oldSpoolHeadSha256":state.generations[index].last_spill_head_sha256,
            "compactedOrderedRangeRootSha256":exact_root,
            "compactedRecordCount":receipt.compacted_record_count(),
            "retainedSuccessorEventOrdinal":retained_ordinal,
            "retainedSuccessorHeadSha256":retained_head,
        }))?;
        if !state.generations[index]
                .last_spill_head_sha256
                .matches_digest(receipt.old_spool_head_sha256())
            || receipt.new_spool_root_sha256() != &expected_new_root
        {
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return Err(
                "compaction old head or resulting root mismatch".to_string(),
            );
        }
        let retained_successor_matches = state
            .receipt_index
            .spill_get(receipt_arena_lane, expected_count)
            .is_some_and(|successor| {
                retained_ordinal == Some(successor.event_ordinal())
                    && retained_head.is_some_and(|head| {
                        successor
                            .resulting_head_sha256()
                            .matches_digest(head)
                    })
            })
            || (state.receipt_index.spill_len(receipt_arena_lane)
                    == expected_count
                && retained_ordinal.is_none()
                && retained_head.is_none());
        if !retained_successor_matches {
            state.generations[index].permanent_readiness_invalid = true;
            state.hard_unready = true;
            return Err(
                "compaction retained successor mismatch".to_string(),
            );
        }
        let compaction_receipt_sha256 =
            InlineSha256Digest::from_digest(
                receipt.signed_receipt_sha256(),
            )?;
        let compaction_retrieval_id_sha256 =
            InlineSha256Digest::from_digest(
                receipt.retrieval_id_sha256(),
            )?;
        let compacted_spool_root_sha256 =
            InlineSha256Digest::from_digest(
                receipt.new_spool_root_sha256(),
            )?;
        let remove_retired_generation = {
            let accounting = &state.generations[index];
            !accounting.live
                && !accounting.prepared
        };
        for cached in state
            .receipt_index
            .spill_iter(receipt_arena_lane)
            .take(expected_count)
        {
            if cached.modeled_handle.generation() == u32::MAX {
                return Err(
                    "modeled receipt handle generation is exhausted"
                        .to_string(),
                );
            }
            state
                .receipt_arena
                .get(cached.modeled_handle)
                .map_err(|error| error.to_string())?;
        }
        let modeled_handles = state
            .receipt_index
            .remove_spill_prefix(receipt_arena_lane, expected_count)?;
        for modeled_handle in modeled_handles {
            state
                .receipt_arena
                .remove(modeled_handle)
                .map_err(|error| error.to_string())?;
        }
        {
            let accounting = &mut state.generations[index];
            accounting.last_compaction_receipt_sha256 =
                Some(compaction_receipt_sha256);
            accounting.last_compaction_retrieval_id_sha256 =
                Some(compaction_retrieval_id_sha256);
            accounting.compacted_through_event_ordinal =
                Some(receipt.compacted_through_event_ordinal());
            accounting.compacted_spool_root_sha256 =
                Some(compacted_spool_root_sha256);
            accounting.spool_backpressure = false;
        }
        let remove_retired_generation = remove_retired_generation
            && state.receipt_index.spill_len(receipt_arena_lane) == 0
            && state.receipt_index.spill_reserved(receipt_arena_lane) == 0;
        if remove_retired_generation {
            let removed = state
                .generations
                .remove(index)
                .ok_or_else(|| {
                    "compacted generation disappeared from accounting"
                        .to_string()
                })?;
            state
                .receipt_index
                .release_spill_lane(removed.receipt_arena_lane)?;
        }
        Ok(())
    }

    fn generation_is_live(&self, generation_id: &str, generation_epoch: u64) -> bool {
        !self.hard_unready_signal.load(Ordering::Acquire)
            && self.state.try_lock().is_ok_and(|state| {
            !state.hard_unready
                && state.generations.iter().any(|entry| {
                    entry.generation_id == generation_id
                        && entry.generation_epoch == generation_epoch
                        && entry.live
                })
            })
    }

    fn status(&self) -> Value {
        let Ok(state) = self.state.try_lock() else {
            return json!({
                "api_version":"serverware.policyShadowRuntimeStatus/v2",
                "readiness":false,
                "readiness_reason":"accounting_state_poisoned",
            });
        };
        let items = state
            .generations
            .iter()
            .map(|entry| {
                json!({
                    "generation_id":entry.generation_id,
                    "generation_epoch":entry.generation_epoch,
                    "prepared":entry.prepared,
                    "live":entry.live,
                    "readiness":false,
                    "permanent_readiness_invalid":entry.permanent_readiness_invalid,
                    "custody_emission_available":!entry.spool_backpressure,
                    "signed_spill_receipt_references_retained":state
                        .receipt_index
                        .spill_len(entry.receipt_arena_lane),
                    "modeled_spill_receipt_reference_bytes":
                        state
                            .receipt_index
                            .modeled_spill_reference_bytes(
                                entry.receipt_arena_lane,
                            ),
                    "last_spill_receipt_sha256":entry.last_spill_receipt_sha256,
                    "last_spill_event_ordinal":entry.last_spill_event_ordinal,
                    "last_spill_head_sha256":entry.last_spill_head_sha256,
                    "last_compaction_receipt_sha256":entry.last_compaction_receipt_sha256,
                    "last_compaction_retrieval_id_sha256":entry.last_compaction_retrieval_id_sha256,
                    "compacted_through_event_ordinal":entry.compacted_through_event_ordinal,
                    "compacted_spool_root_sha256":entry.compacted_spool_root_sha256,
                    "spool_backpressure":entry.spool_backpressure,
                    "counters":{
                        "admitted":entry.counters.admitted,
                        "active_pre_dispatch_terminals":entry.counters.active_pre_dispatch_terminals,
                        "active_post_dispatch_terminals":entry.counters.active_post_dispatch_terminals,
                        "dispatch_barriers_appended":entry.counters.dispatch_barriers_appended,
                        "response_captures_enqueued":entry.counters.response_captures_enqueued,
                        "evaluated":entry.counters.evaluated,
                        "responses_evaluated":entry.counters.responses_evaluated,
                        "responses_unavailable":entry.counters.responses_unavailable,
                        "sampled_out":entry.counters.sampled_out,
                        "transport_excluded":entry.counters.transport_excluded,
                        "capture_failures":entry.counters.capture_failures,
                        "serialization_failures":entry.counters.serialization_failures,
                        "oversize":entry.counters.oversize,
                        "queue_full":entry.counters.queue_full,
                        "queue_disconnected":entry.counters.queue_disconnected,
                        "active_evaluation_failures":entry.counters.active_evaluation_failures,
                        "candidate_evaluation_failures":entry.counters.candidate_evaluation_failures,
                        "unsupported_required_ingress":entry.counters.unsupported_required_ingress,
                        "custody_emission_missing":entry.counters.custody_emission_missing,
                        "generation_tombstoned":entry.counters.generation_tombstoned,
                        "queue_accounting_poisoned":entry.counters.queue_accounting_poisoned,
                        "worker_lost":entry.counters.worker_lost,
                        "terminal_failures":entry.counters.terminal_failures,
                    },
                })
            })
            .collect::<Vec<_>>();
        json!({
            "api_version":"serverware.policyShadowRuntimeStatus/v2",
            "readiness":false,
            "readiness_reason":if state.hard_unready
                || self.hard_unready_signal.load(Ordering::Acquire)
            {
                "production_custody_unavailable_or_spool_unhealthy"
            } else {
                "signed_evidence_not_yet_checkpointed"
            },
            "hard_unready":state.hard_unready
                || self.hard_unready_signal.load(Ordering::Acquire),
            "signed_unavailable_receipt_references_retained":
                state.receipt_index.unavailable_length,
            "modeled_receipt_reference_budget_label":
                MODELED_RECEIPT_REFERENCE_BUDGET_LABEL,
            "modeled_receipt_reference_occupied_bytes":
                state.receipt_arena.len().saturating_mul(
                    std::mem::size_of::<ModeledInlineReceiptReference>(),
                ),
            "modeled_receipt_reconciliation_reserved_bytes":
                state.receipt_arena.modeled_reserved_bytes(),
            "modeled_receipt_reference_budget_bytes":
                MODELED_RECEIPT_REFERENCE_BUDGET_BYTES,
            "modeled_receipt_reference_fixed_bytes":
                state.receipt_arena.modeled_fixed_bytes(),
            "modeled_receipt_reference_remaining_bytes":
                state.receipt_arena.modeled_remaining_bytes(),
            "modeled_receipt_reference_capacity":
                state.receipt_arena.capacity(),
            "receipt_reference_arena_ready":
                state.receipt_arena.is_available()
                    && state.receipt_index.ready,
            "real_memory_enforcement":false,
            "last_unavailable_receipt_sha256":state.last_unavailable_receipt_sha256,
            "last_unavailable_event_ordinal":state.last_unavailable_event_ordinal,
            "last_unavailable_head_sha256":state.last_unavailable_head_sha256,
            "last_unavailable_retrieval_id_sha256":state.last_unavailable_retrieval_id_sha256,
            "unavailable_backpressure":state.unavailable_backpressure,
            "unrecoverable_local_failure":state.unrecoverable_local_failure,
            "highest_generation_epoch":state.highest_generation_epoch,
            "highest_generation_tombstone_epoch":state.highest_generation_tombstone_epoch,
            "highest_assignment_revision":state.highest_assignment_revision,
            "generations":items,
        })
    }
}

struct QueueByteReservation {
    counter: Arc<AtomicUsize>,
    poisoned: Arc<AtomicBool>,
    ledger: Arc<AccountingLedger>,
    generation_id: String,
    ingress_sequence: u64,
    request_binding_sha256: String,
    request_commitment_sha256: String,
    bytes: usize,
}

impl QueueByteReservation {
    fn reserve(
        counter: &Arc<AtomicUsize>,
        poisoned: &Arc<AtomicBool>,
        ledger: &Arc<AccountingLedger>,
        generation_id: &str,
        ingress_sequence: u64,
        request_binding_sha256: &str,
        request_commitment_sha256: &str,
        bytes: usize,
    ) -> Option<Self> {
        if poisoned.load(Ordering::Acquire) {
            return None;
        }
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= SHADOW_QUEUE_BYTES)
            })
            .ok()?;
        Some(Self {
            counter: Arc::clone(counter),
            poisoned: Arc::clone(poisoned),
            ledger: Arc::clone(ledger),
            generation_id: generation_id.to_string(),
            ingress_sequence,
            request_binding_sha256: request_binding_sha256.to_string(),
            request_commitment_sha256:
                request_commitment_sha256.to_string(),
            bytes,
        })
    }
}

impl Drop for QueueByteReservation {
    fn drop(&mut self) {
        if self
            .counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(self.bytes)
            })
            .is_err()
        {
            self.poisoned.store(true, Ordering::Release);
            if !self.ledger.record(
                &self.generation_id,
                ShadowAccountingEvent::minimal(
                    self.ingress_sequence,
                    self.request_binding_sha256.clone(),
                    self.request_commitment_sha256.clone(),
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::AccountingLedgerContention,
                    ),
                ),
                false,
            ) {
                self.ledger.mark_hard_unready();
            }
        }
    }
}

// These slots describe only the four existing OUTER credential wrappers.
// Cache hits, singleflight sharing and nested refreshes are not individual
// provider-operation proofs and cannot discharge new plan requirements.
fn credential_outer_slot(kind: ActiveMutableEffectKind) -> Result<usize, String> {
    match kind {
        ActiveMutableEffectKind::CredentialGeneration => Ok(0),
        ActiveMutableEffectKind::OauthRotation => Ok(1),
        ActiveMutableEffectKind::CredentialLease => Ok(2),
        ActiveMutableEffectKind::CredentialDecrypt => Ok(3),
        _ => Err("unsupported outer credential prerequisite kind".to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct CredentialPrerequisiteParent {
    commitment: InlineSha256Digest,
    generation: InlineSha256Digest,
    request_binding: InlineSha256Digest,
    request_commitment: InlineSha256Digest,
    active_plan: InlineSha256Digest,
    scope: InlineSha256Digest,
    credential_slot: InlineSha256Digest,
    ingress_sequence: u64,
    decision_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct CredentialOuterResult {
    version: u64,
    metadata: InlineSha256Digest,
    secret_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct CredentialOuterSlot {
    effect_id: InlineSha256Digest,
    attempted: bool,
    barrier: Option<InlineSha256Digest>,
    receipt: Option<CompactActiveEffectCommitReceipt>,
    result: Option<CredentialOuterResult>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct CredentialPrerequisiteEvidence {
    parent: Option<CredentialPrerequisiteParent>,
    slots: [Option<CredentialOuterSlot>; 4],
    resolved: Option<CredentialOuterResult>,
    failed: bool,
}

const _: () = assert!(std::mem::size_of::<CredentialPrerequisiteEvidence>() <= 4096);
const _: () = assert!(std::mem::size_of::<Option<CredentialPrerequisiteEvidence>>() <= 4096);

impl CredentialPrerequisiteEvidence {
    fn commitment(&self) -> String {
        digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowOuterCredentialPrerequisites/v1",
            "evidence":self,
        }))
    }

    fn permits_binding(&self, plan: &str, time: u64) -> bool {
        self.parent.is_none_or(|parent| {
            InlineSha256Digest::from_str(plan).ok() == Some(parent.active_plan)
                && time == parent.decision_at_epoch_ms
        })
    }

    fn reserve(
        &mut self,
        parent: CredentialPrerequisiteParent,
        preparations: &[Option<ActiveEffectPreparation>; 2],
    ) -> Result<(), String> {
        validate_credential_preparation_group(preparations)?;
        if self.failed || self.parent.is_some_and(|bound| bound != parent) {
            return Err("credential prerequisite parent binding changed".to_string());
        }
        let mut reserved = self.slots;
        for preparation in preparations.iter().flatten() {
            let (generation, ingress) = preparation.reconciliation_identity();
            if InlineSha256Digest::from_digest(generation)? != parent.generation || ingress != parent.ingress_sequence {
                return Err("credential prerequisite preparation parent mismatch".to_string());
            }
            let index = credential_outer_slot(preparation.effect_kind())?;
            if reserved[index].is_some() {
                return Err("credential prerequisite outer slot already reserved".to_string());
            }
            reserved[index] = Some(CredentialOuterSlot {
                effect_id: InlineSha256Digest::from_digest(preparation.effect_id_sha256())?,
                attempted: false,
                barrier: None,
                receipt: None,
                result: None,
            });
        }
        self.parent = Some(parent);
        self.slots = reserved;
        Ok(())
    }

    fn retain(
        &mut self,
        parent: CredentialPrerequisiteParent,
        preparation: &ActiveEffectPreparation,
        receipt: CompactActiveEffectCommitReceipt,
        result: Option<CredentialOuterResult>,
    ) -> Result<(), String> {
        if self.parent != Some(parent) {
            return Err("credential prerequisite receipt parent mismatch".to_string());
        }
        let slot = self.slots[credential_outer_slot(preparation.effect_kind())?]
            .as_mut().ok_or("credential prerequisite receipt has no reservation")?;
        if slot.effect_id != InlineSha256Digest::from_digest(preparation.effect_id_sha256())?
            || slot.receipt.is_some() || !slot.attempted || slot.barrier.is_none()
            || (receipt.terminal_state() == ActiveEffectCommitState::Committed) != result.is_some()
        {
            return Err("credential prerequisite receipt slot mismatch".to_string());
        }
        if let Some(result) = result {
            let digest = Sha256Digest::parse(result.result_commitment()?).map_err(shadow_error)?;
            if !receipt.matches_result(&digest) {
                return Err("credential prerequisite signed result mismatch".to_string());
            }
        }
        if !receipt.matches_preparation_and_barrier(preparation.effect_id_sha256(),
            &slot.barrier.ok_or("credential prerequisite barrier missing")?.to_digest()?)
        {
            return Err("credential prerequisite recorded barrier mismatch".to_string());
        }
        slot.receipt = Some(receipt);
        slot.result = result;
        if receipt.terminal_state() != ActiveEffectCommitState::Committed {
            self.failed = true;
        }
        Ok(())
    }

    fn publish_resolution(
        &mut self,
        parent: CredentialPrerequisiteParent,
        preparations: &[Option<ActiveEffectPreparation>; 2],
        result: CredentialOuterResult,
    ) -> Result<(), String> {
        validate_credential_preparation_group(preparations)?;
        if self.failed || self.parent != Some(parent) || result.version == 0 {
            return Err("credential prerequisite group is not committed".to_string());
        }
        for preparation in preparations.iter().flatten() {
            let slot = self.slots[credential_outer_slot(preparation.effect_kind())?]
                .ok_or("credential prerequisite group reservation missing")?;
            if slot.effect_id != InlineSha256Digest::from_digest(preparation.effect_id_sha256())?
                || slot.receipt.is_none_or(|receipt| receipt.terminal_state() != ActiveEffectCommitState::Committed)
                || slot.result != Some(result)
            {
                return Err("credential prerequisite group lacks matching commits".to_string());
            }
        }
        if self.resolved.is_some_and(|prior| prior.version != result.version || prior.metadata != result.metadata) {
            self.failed = true;
            return Err("credential prerequisite generation changed between outer groups".to_string());
        }
        self.resolved = Some(result);
        Ok(())
    }

    fn validate_decision(&self, decision: &Value, dispatch: bool) -> Result<(), String> {
        let Some(parent) = self.parent else { return Ok(()); };
        let supplied_slot = decision.get("credential_ref").filter(|value| !value.is_null());
        let supplied_version = decision.get("credential_version").filter(|value| !value.is_null());
        let supplied_secret = decision.get("policy_effect_results")
            .and_then(|effects| effects.get("credential_secret_available"))
            .filter(|value| !value.is_null());
        let slot = decision.get("credential_ref").and_then(Value::as_str);
        let version = decision.get("credential_version").and_then(Value::as_u64);
        if supplied_slot.is_some_and(|value| !value.is_string())
            || supplied_version.is_some_and(|value| value.as_u64().is_none())
            || supplied_secret.is_some_and(|value| value.as_bool().is_none())
            || slot.is_some_and(|slot| InlineSha256Digest::compute(slot.as_bytes()) != parent.credential_slot)
            || version.is_some_and(|version| self.resolved.is_none_or(|result| result.version != version))
            || ((slot.is_some() || version.is_some()) && supplied_secret.is_some_and(|value|
                self.resolved.is_none_or(|result| Some(result.secret_available) != value.as_bool())))
            || (dispatch && (self.failed || slot.is_none() || version.is_none()
                || self.resolved.is_none_or(|result| !result.secret_available)
                || self.slots.iter().flatten().any(|slot| slot.receipt.is_none_or(|receipt|
                    receipt.terminal_state() != ActiveEffectCommitState::Committed))
                || [2, 3].into_iter().any(|index| self.slots[index].and_then(|slot| slot.receipt)
                    .is_none_or(|receipt| receipt.terminal_state() != ActiveEffectCommitState::Committed))))
        {
            return Err("active decision contradicts retained credential prerequisite result".to_string());
        }
        // A genuine later denial need not invent a slot/version. Any completed
        // prerequisites remain retained even when that denial omits resolution.
        Ok(())
    }
}

fn validate_credential_preparation_group(
    preparations: &[Option<ActiveEffectPreparation>; 2],
) -> Result<(), String> {
    let kinds = preparations.each_ref().map(|item| item.as_ref().map(ActiveEffectPreparation::effect_kind));
    if !matches!(kinds,
        [Some(ActiveMutableEffectKind::CredentialGeneration), None]
        | [Some(ActiveMutableEffectKind::CredentialGeneration), Some(ActiveMutableEffectKind::OauthRotation)]
        | [Some(ActiveMutableEffectKind::CredentialLease), Some(ActiveMutableEffectKind::CredentialDecrypt)])
    {
        return Err("invalid outer credential prerequisite group".to_string());
    }
    Ok(())
}

impl CredentialOuterResult {
    fn from_info(info: &CredentialLeaseInfo) -> Result<Self, String> {
        let metadata = credential_lease_metadata_sha256(&info.metadata);
        if info.version == 0 || metadata != info.metadata_sha256 {
            return Err("credential prerequisite result metadata or version is invalid".to_string());
        }
        Ok(Self {
            version: info.version,
            metadata: InlineSha256Digest::from_str(&metadata)?,
            secret_available: info.secret_available,
        })
    }

    fn result_commitment(&self) -> Result<String, String> {
        Ok(digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowCredentialEffectResult/v1",
            "version":self.version,
            "metadataSha256":self.metadata.to_digest()?.as_str(),
            "secretAvailable":self.secret_available,
        })))
    }
}

#[derive(Clone, Copy)]
struct PrerequisiteEffectRoot {
    prerequisite_commitment: InlineSha256Digest,
    effect_results: InlineSha256Digest,
}

const _: () = assert!(4 * (std::mem::size_of::<CredentialPrerequisiteEvidence>()
    + std::mem::size_of::<PrerequisiteEffectRoot>()) <= SHADOW_CREDENTIAL_PREREQUISITE_RETENTION_BYTES);

impl PrerequisiteEffectRoot {
    fn new(evidence: &CredentialPrerequisiteEvidence, effect_results: &Value) -> Result<Self, String> {
        let commitment = evidence.commitment();
        let explicit = effect_results.get("explicitCommitments").and_then(Value::as_array)
            .ok_or("prerequisite effect root lacks explicit commitments")?;
        if explicit.iter().filter(|item| item.as_str() == Some(commitment.as_str())).count() != 1 {
            return Err("prerequisite evidence is not bound exactly once in effect root".to_string());
        }
        Ok(Self {
            prerequisite_commitment: InlineSha256Digest::from_str(&commitment)?,
            effect_results: InlineSha256Digest::from_str(&digest_json_ensure_ascii(effect_results))?,
        })
    }
}

// Move-only bounded transient reservation. Strings here are canonical digests;
// only the inline evidence above survives in lifecycle/pending/terminal state.
pub(crate) struct CredentialPrerequisiteReservation {
    parent: CredentialPrerequisiteParent,
    preparations: [Option<ActiveEffectPreparation>; 2],
    intent_sha256: String,
    prepared_state_sha256: String,
}

impl CredentialPrerequisiteReservation {
    pub(crate) fn effect_count(&self) -> usize {
        self.preparations.iter().flatten().count()
    }

    pub(crate) fn result_commitment(&self, info: &CredentialLeaseInfo) -> Result<String, String> {
        CredentialOuterResult::from_info(info)?.result_commitment()
    }
}

// Non-authorizing and move-only: provenance for this wrapper result, not a
// child-plan capability. Only successful full-group publication constructs it.
pub(crate) struct CommittedCredentialPrerequisite {
    parent: CredentialPrerequisiteParent,
    result: CredentialOuterResult,
    evidence_commitment: InlineSha256Digest,
}

#[derive(Clone)]
struct FinalActiveDecision {
    decision_at_epoch_ms: u64,
    active_evaluation: PolicyEvaluation,
    effect_requirements: ActiveEffectRequirements,
    final_outcome: String,
    final_decision_sha256: String,
    effect_results_sha256: String,
    terminal_response_sha256: String,
    exact_response_facts_sha256: Option<String>,
    gmail_metadata_evidence_sha256: Option<String>,
    resolved_credential_slot: Option<String>,
    resolved_credential_version: Option<u64>,
    dispatch_authorized: bool,
    credential_prerequisites: CredentialPrerequisiteEvidence,
    prerequisite_effect_root: PrerequisiteEffectRoot,
}

// A retained reference to a genuinely appended terminal, never an execution
// permit or a new signed statement. There is no public constructor, mutable
// accessor, serialization, or conversion to an effect/dispatch capability.
struct ActiveTerminalRecord {
    decision: FinalActiveDecision,
    receipt: DurableShadowEventReceipt,
    request_binding_sha256: InlineSha256Digest,
    request_commitment_sha256: InlineSha256Digest,
    returned_http_status: u16,
    phase: ShadowSpoolPhase,
}

const _: () = assert!(
    std::mem::size_of::<ActiveTerminalRecord>()
        - std::mem::size_of::<FinalActiveDecision>()
        <= SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES
);
const _: () = assert!(
    std::mem::size_of::<Option<ActiveTerminalRecord>>()
        - std::mem::size_of::<Option<FinalActiveDecision>>()
        <= SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES
);

struct PreparedActiveTerminalRecord {
    decision: FinalActiveDecision,
    generation_id: InlineSha256Digest,
    ingress_sequence: u64,
    request_binding_sha256: InlineSha256Digest,
    request_commitment_sha256: InlineSha256Digest,
    event_sha256: InlineSha256Digest,
    returned_http_status: u16,
    phase: ShadowSpoolPhase,
}

// Receipt matching happens after append; all fallible local binding and
// canonicalization happens before it. Only the final successful state update
// converts this private intermediate into the retained terminal record.
struct MatchedActiveTerminalRecord {
    prepared: PreparedActiveTerminalRecord,
    receipt: DurableShadowEventReceipt,
}

fn final_active_outcome_digest(
    active_plan_sha256: &str,
    outcome: &str,
    returned_http_status: u16,
    dispatch_authorized: bool,
    effect_results_sha256: &str,
    terminal_response_sha256: &str,
) -> String {
    digest_json_ensure_ascii(&json!({
        "domain":"serverware.policyShadowFinalActiveOutcome/v2",
        "activePlanSha256":active_plan_sha256,
        "outcome":outcome,
        "returnedHttpStatus":returned_http_status,
        "dispatchAuthorized":dispatch_authorized,
        "effectResultsSha256":effect_results_sha256,
        "terminalResponseSha256":terminal_response_sha256,
    }))
}

impl FinalActiveDecision {
    fn terminal_event(
        &self,
        ingress_sequence: u64,
        request_binding_sha256: String,
        request_commitment_sha256: String,
        active_response_validation_sha256: Option<String>,
    ) -> ShadowAccountingEvent {
        let mut event = ShadowAccountingEvent::minimal(
            ingress_sequence,
            request_binding_sha256,
            request_commitment_sha256,
            if self.dispatch_authorized {
                ShadowRuntimeEvent::ResponseTerminalAppended
            } else {
                ShadowRuntimeEvent::ActivePreDispatchTerminal
            },
        );
        event.active_plan_sha256 = Some(self.active_evaluation.semantic_sha256.clone());
        event.final_active_decision_sha256 = Some(self.final_decision_sha256.clone());
        event.active_effect_results_sha256 = Some(self.effect_results_sha256.clone());
        event.active_disposition = Some(self.final_outcome.clone());
        event.response_facts_sha256 = self.exact_response_facts_sha256.clone();
        event.active_response_validation_sha256 = active_response_validation_sha256;
        event
    }
}

impl PreparedActiveTerminalRecord {
    #[allow(clippy::too_many_arguments)]
    fn new(
        generation_id: &str,
        ingress_sequence: u64,
        request_binding_sha256: &str,
        request_commitment_sha256: &str,
        decision: FinalActiveDecision,
        returned_http_status: u16,
        active_response_validation_sha256: Option<&str>,
        event: &ShadowAccountingEvent,
    ) -> Result<Self, String> {
        let generation_id = InlineSha256Digest::from_str(generation_id)?;
        let request_binding = InlineSha256Digest::from_str(request_binding_sha256)?;
        let request_commitment = InlineSha256Digest::from_str(request_commitment_sha256)?;
        if ingress_sequence == 0 || !(200..=599).contains(&returned_http_status)
            || !matches!(decision.final_outcome.as_str(), "allow" | "deny" | "conditional" | "error")
        {
            return Err("terminal record status or identity is invalid".to_string());
        }
        let plan = decision.active_evaluation.active_plan()
            .ok_or("terminal record lacks an active plan")?;
        if decision.prerequisite_effect_root.prerequisite_commitment
                != InlineSha256Digest::from_str(&decision.credential_prerequisites.commitment())?
            || decision.prerequisite_effect_root.effect_results
                != InlineSha256Digest::from_str(&decision.effect_results_sha256)?
            || decision.credential_prerequisites.parent.is_some_and(|parent|
                parent.generation != generation_id || parent.ingress_sequence != ingress_sequence
                || parent.request_binding != request_binding || parent.request_commitment != request_commitment
                || parent.decision_at_epoch_ms != decision.decision_at_epoch_ms
                || InlineSha256Digest::from_str(&decision.active_evaluation.semantic_sha256).ok() != Some(parent.active_plan))
        {
            return Err("terminal record credential prerequisite commitment mismatch".to_string());
        }
        decision.credential_prerequisites.validate_decision(&json!({
            "credential_ref":decision.resolved_credential_slot,
            "credential_version":decision.resolved_credential_version,
        }), decision.dispatch_authorized)?;
        if plan.semantic_commitment().map_err(shadow_error)?.as_str()
                != decision.active_evaluation.semantic_sha256
            || decision.effect_requirements != ActiveEffectRequirements::from_plan(plan)
            || decision.final_decision_sha256 != final_active_outcome_digest(
                &decision.active_evaluation.semantic_sha256,
                &decision.final_outcome,
                returned_http_status,
                decision.dispatch_authorized,
                &decision.effect_results_sha256,
                &decision.terminal_response_sha256,
            )
        {
            return Err("terminal record decision commitment mismatch".to_string());
        }
        for digest in [
            Some(decision.active_evaluation.semantic_sha256.as_str()),
            Some(decision.final_decision_sha256.as_str()),
            Some(decision.effect_results_sha256.as_str()),
            Some(decision.terminal_response_sha256.as_str()),
            decision.exact_response_facts_sha256.as_deref(),
            decision.gmail_metadata_evidence_sha256.as_deref(),
            active_response_validation_sha256,
        ].into_iter().flatten() {
            InlineSha256Digest::from_str(digest)?;
        }
        let expected_event = decision.terminal_event(
            ingress_sequence,
            request_binding_sha256.to_string(),
            request_commitment_sha256.to_string(),
            active_response_validation_sha256.map(str::to_string),
        );
        let event_bytes = event.canonical_bytes()?;
        if event_bytes != expected_event.canonical_bytes()? {
            return Err("terminal record event commitment mismatch".to_string());
        }
        Ok(Self {
            decision,
            generation_id,
            ingress_sequence,
            request_binding_sha256: request_binding,
            request_commitment_sha256: request_commitment,
            event_sha256: InlineSha256Digest::compute(&event_bytes),
            returned_http_status,
            phase: event.spool_phase(),
        })
    }

    fn match_receipt(
        self,
        receipt: DurableShadowEventReceipt,
    ) -> Result<MatchedActiveTerminalRecord, String> {
        if receipt.generation_id != self.generation_id
            || receipt.ingress_sequence != self.ingress_sequence
            || receipt.event_ordinal == 0
            || receipt.event_sha256 != self.event_sha256
        {
            return Err("terminal record durable receipt binding mismatch".to_string());
        }
        Ok(MatchedActiveTerminalRecord { prepared: self, receipt })
    }
}

impl MatchedActiveTerminalRecord {
    fn into_record(self) -> ActiveTerminalRecord {
        ActiveTerminalRecord {
            decision: self.prepared.decision,
            receipt: self.receipt,
            request_binding_sha256: self.prepared.request_binding_sha256,
            request_commitment_sha256: self.prepared.request_commitment_sha256,
            returned_http_status: self.prepared.returned_http_status,
            phase: self.prepared.phase,
        }
    }
}

#[derive(Clone)]
struct PendingActiveDecision {
    decision_at_epoch_ms: u64,
    active_plan_sha256: String,
    active_evaluation: PolicyEvaluation,
    final_outcome: String,
    effect_requirements: ActiveEffectRequirements,
    explicit_effect_commitments: Vec<String>,
    final_upstream_request_commitment_sha256: Option<String>,
    resolved_credential_slot: Option<String>,
    resolved_credential_version: Option<u64>,
    dispatch_authorized: bool,
    active_decision: Value,
    credential_prerequisites: CredentialPrerequisiteEvidence,
}

#[derive(Clone)]
struct DecisionTimeBinding {
    decision_at_epoch_ms: u64,
    active_plan_sha256: String,
    effect_requirements: ActiveEffectRequirements,
    active_evaluation: PolicyEvaluation,
}

#[derive(Default)]
struct LifecycleState {
    pending_active: Option<PendingActiveDecision>,
    final_active: Option<ActiveTerminalRecord>,
    candidate: Option<PolicyEvaluation>,
    decision_time_binding: Option<DecisionTimeBinding>,
    response_finished: bool,
    credential_prerequisites: CredentialPrerequisiteEvidence,
    credential_prerequisites_sealed: bool,
}

struct ShadowRequestLifecycle {
    generation: Arc<ShadowGeneration>,
    current_generation:
        Arc<RwLock<Option<Arc<PublishedShadowGeneration>>>>,
    facts: Arc<AdmittedRequestFacts>,
    ingress_sequence: u64,
    request_binding_sha256: String,
    request_commitment_sha256: String,
    sender: SyncSender<ShadowWork>,
    queued_bytes: Arc<AtomicUsize>,
    queue_poisoned: Arc<AtomicBool>,
    ledger: Arc<AccountingLedger>,
    state: Mutex<LifecycleState>,
    finalization_consumed: AtomicBool,
    response_terminal_recorded: AtomicBool,
}

impl ShadowRequestLifecycle {
    fn generation_is_current(&self) -> bool {
        self.current_generation.try_read().is_ok_and(|current| {
            current.as_ref().is_some_and(|published| {
                let installed = &published.generation;
                installed.generation_id()
                    == self.generation.generation_id()
                    && installed.signed_identity
                        == self.generation.signed_identity
                    && installed.identity.generation_epoch
                        == self.generation.identity.generation_epoch
                    && installed.identity.generation_tombstone_epoch
                        == self.generation.identity.generation_tombstone_epoch
                    && installed.identity.assignment_revision
                        == self.generation.identity.assignment_revision
                    && installed.identity.active_snapshot_sha256
                        == self.generation.identity.active_snapshot_sha256
                    && installed.identity.active_policy_sequence
                        == self.generation.identity.active_policy_sequence
                    && installed.identity.active_rollback_epoch
                        == self.generation.identity.active_rollback_epoch
            })
        }) && self.ledger.generation_is_live(
            self.generation.generation_id(),
            self.generation.identity.generation_epoch,
        )
    }

    fn generation_is_current_for(&self, snapshot: &Arc<Snapshot>) -> bool {
        self.generation.matches_active_snapshot(snapshot) && self.generation_is_current()
    }
}

#[derive(Clone)]
pub(crate) struct ShadowRequestHandle {
    inner: Arc<ShadowRequestLifecycle>,
}

pub(crate) enum ShadowActiveEffectPermit {
    Verified {
        permit: VerifiedActiveEffectPermit,
        generation_id: String,
        ingress_sequence: u64,
        effect_kind: ActiveMutableEffectKind,
    },
    #[cfg(test)]
    InactiveForwardingTest,
}

#[cfg(test)]
impl ShadowActiveEffectPermit {
    pub(crate) fn inactive_forwarding_test() -> Self {
        Self::InactiveForwardingTest
    }

    pub(crate) fn is_inactive_forwarding_test(&self) -> bool {
        matches!(self, Self::InactiveForwardingTest)
    }
}

impl ShadowRequestHandle {
    fn validate_credential_reservation(&self, reservation: &CredentialPrerequisiteReservation) -> Result<(), String> {
        let parent = reservation.parent;
        if parent.generation != InlineSha256Digest::from_str(self.inner.generation.generation_id())?
            || parent.ingress_sequence != self.inner.ingress_sequence
            || parent.request_binding != InlineSha256Digest::from_str(&self.inner.request_binding_sha256)?
            || parent.request_commitment != InlineSha256Digest::from_str(&self.inner.request_commitment_sha256)?
        {
            return Err("credential prerequisite reservation belongs to another lifecycle".to_string());
        }
        let state = self.inner.state.try_lock().map_err(|_| "credential prerequisite ownership state is unavailable")?;
        if state.credential_prerequisites.parent != Some(parent)
            || !state.credential_prerequisites.permits_binding(
                &state.decision_time_binding.as_ref().ok_or("credential prerequisite parent was removed")?.active_plan_sha256,
                state.decision_time_binding.as_ref().ok_or("credential prerequisite parent was removed")?.decision_at_epoch_ms,
            )
        {
            return Err("credential prerequisite reservation parent drift".to_string());
        }
        validate_credential_preparation_group(&reservation.preparations)?;
        for preparation in reservation.preparations.iter().flatten() {
            let slot = state.credential_prerequisites.slots[credential_outer_slot(preparation.effect_kind())?]
                .ok_or("credential prerequisite ownership slot missing")?;
            if slot.effect_id != InlineSha256Digest::from_digest(preparation.effect_id_sha256())? {
                return Err("credential prerequisite ownership slot drift".to_string());
            }
        }
        Ok(())
    }

    pub(crate) fn reserve_credential_prerequisites(
        &self,
        snapshot: &Arc<Snapshot>,
        scope: &CredentialLeaseScope,
        primary: ActiveMutableEffectKind,
        intent_sha256: &str,
        prepared_state_sha256: &str,
    ) -> Result<CredentialPrerequisiteReservation, String> {
        if !self.inner.generation_is_current_for(snapshot) {
            return Err("credential prerequisite generation is not current".to_string());
        }
        let mut state = self.inner.state.try_lock()
            .map_err(|_| "credential prerequisite reservation state is unavailable")?;
        let binding = state.decision_time_binding.as_ref()
            .ok_or("credential prerequisite lacks a decision-time parent")?;
        // Re-establish scope from immutable admitted identity/target facts,
        // not from the caller's proposed scope or a later enriched request.
        let facts = &self.inner.facts;
        let headers = lower_headers(&discard_declared_request_headers(&facts.headers, &[])?);
        let principal = if let Some(id) = facts.authenticated_principal_id.as_deref() {
            snapshot.principals.iter().find(|principal| principal.id == id)
        } else {
            snapshot.principals.iter().find(|principal| principal.matches_at(
                facts.client_ip.as_deref(), &headers, None,
                u128::from(binding.decision_at_epoch_ms),
            ))
        }.ok_or("credential prerequisite admitted principal is unavailable")?;
        let (_, url) = parse_validated_absolute_target(&facts.url)?;
        let matched = snapshot.match_route(&principal.id, &facts.method, &url)
            .ok_or("credential prerequisite admitted route is unavailable")?;
        if principal.id != scope.principal_id || matched.route.id != scope.route_id
            || matched.route.credential_ref.as_deref() != Some(scope.credential_id.as_str())
            || !snapshot.credentials.contains_key(&scope.credential_id)
        {
            return Err("credential prerequisite admitted scope mismatch".to_string());
        }
        let kinds = match primary {
            ActiveMutableEffectKind::CredentialGeneration => [Some(primary),
                snapshot.credentials.get(&scope.credential_id)
                    .filter(|credential| credential.kind() == "oauth2")
                    .map(|_| ActiveMutableEffectKind::OauthRotation)],
            ActiveMutableEffectKind::CredentialLease => [Some(primary), Some(ActiveMutableEffectKind::CredentialDecrypt)],
            _ => return Err("unsupported primary credential prerequisite kind".to_string()),
        };
        if state.credential_prerequisites_sealed || state.pending_active.is_some() || state.final_active.is_some()
            || self.inner.finalization_consumed.load(Ordering::Acquire)
        {
            return Err("credential prerequisite reservation follows finalization".to_string());
        }
        let scope_digest = digest_json_ensure_ascii(&credential_lease_scope_commitment(scope));
        let parent_digest = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowCredentialPrerequisiteParent/v1",
            "generation":self.inner.generation.generation_id(),
            "ingressSequence":self.inner.ingress_sequence,
            "requestBinding":self.inner.request_binding_sha256,
            "requestCommitment":self.inner.request_commitment_sha256,
            "policySha256":snapshot.hash,
            "snapshotEpoch":snapshot.epoch,
            "policySequence":snapshot.policy_sequence,
            "rollbackEpoch":snapshot.rollback_epoch,
            "activePlanSha256":binding.active_plan_sha256,
            "decisionAtEpochMs":binding.decision_at_epoch_ms,
            "scopeSha256":scope_digest,
        }));
        let parent = CredentialPrerequisiteParent {
            commitment: InlineSha256Digest::from_str(&parent_digest)?,
            generation: InlineSha256Digest::from_str(self.inner.generation.generation_id())?,
            request_binding: InlineSha256Digest::from_str(&self.inner.request_binding_sha256)?,
            request_commitment: InlineSha256Digest::from_str(&self.inner.request_commitment_sha256)?,
            active_plan: InlineSha256Digest::from_str(&binding.active_plan_sha256)?,
            scope: InlineSha256Digest::from_str(&scope_digest)?,
            credential_slot: InlineSha256Digest::compute(scope.credential_id.as_bytes()),
            ingress_sequence: self.inner.ingress_sequence,
            decision_at_epoch_ms: binding.decision_at_epoch_ms,
        };
        // Existing barrier wire signs these opaque digests; the closed parent
        // preimage adds no new wire/profile interpretation or permission.
        let intent = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowCredentialOuterIntent/v2",
            "parent":parent_digest,
            "intent":Sha256Digest::parse(intent_sha256.to_string()).map_err(shadow_error)?,
        }));
        let prepared = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowCredentialOuterPreparedState/v2",
            "parent":parent_digest,
            "preparedState":Sha256Digest::parse(prepared_state_sha256.to_string()).map_err(shadow_error)?,
        }));
        let mut preparations = [None, None];
        for (index, kind) in kinds.into_iter().enumerate() {
            if let Some(kind) = kind {
                preparations[index] = Some(ActiveEffectPreparation::new(
                    parent.generation.to_digest()?, parent.ingress_sequence, kind,
                    Sha256Digest::parse(intent.clone()).map_err(shadow_error)?,
                    Sha256Digest::parse(prepared.clone()).map_err(shadow_error)?,
                ).map_err(shadow_error)?);
            }
        }
        state.credential_prerequisites.reserve(parent, &preparations)?;
        Ok(CredentialPrerequisiteReservation {
            parent, preparations, intent_sha256: intent, prepared_state_sha256: prepared,
        })
    }

    pub(crate) fn fail_credential_prerequisites(&self) {
        if let Ok(mut state) = self.inner.state.try_lock() {
            if !state.credential_prerequisites_sealed {
                state.credential_prerequisites.failed = true;
            }
        }
        self.inner.ledger.mark_hard_unready();
    }

    pub(crate) fn prepare_credential_prerequisite(
        &self,
        snapshot: &Arc<Snapshot>,
        reservation: &CredentialPrerequisiteReservation,
        index: usize,
    ) -> Result<ShadowActiveEffectPermit, String> {
        self.validate_credential_reservation(reservation)?;
        let preparation = reservation.preparations.get(index).and_then(Option::as_ref)
            .ok_or("credential prerequisite index is invalid")?;
        {
            let mut state = self.inner.state.try_lock().map_err(|_| "credential prerequisite preparation state is unavailable")?;
            if state.credential_prerequisites_sealed || state.credential_prerequisites.failed {
                return Err("credential prerequisite preparation is sealed or failed".to_string());
            }
            let slot = state.credential_prerequisites.slots[credential_outer_slot(preparation.effect_kind())?]
                .as_mut().ok_or("credential prerequisite preparation slot missing")?;
            if slot.attempted {
                return Err("credential prerequisite preparation was already attempted".to_string());
            }
            slot.attempted = true;
        }
        let prepared = self.prepare_mutable_effect(snapshot, preparation.effect_kind(),
            &reservation.intent_sha256, &reservation.prepared_state_sha256);
        match prepared {
            Ok(ShadowActiveEffectPermit::Verified { permit, generation_id, ingress_sequence, effect_kind })
                if permit.preparation() == preparation => {
                    let retained = (|| {
                        let barrier = InlineSha256Digest::from_digest(permit.signed_receipt_sha256())?;
                        let mut state = self.inner.state.try_lock().map_err(|_| "credential prerequisite barrier retention state is unavailable")?;
                        if state.credential_prerequisites_sealed {
                            return Err("credential prerequisite barrier retention is sealed".to_string());
                        }
                        state.credential_prerequisites.slots[credential_outer_slot(effect_kind)?]
                            .as_mut().ok_or("credential prerequisite barrier slot missing")?.barrier = Some(barrier);
                        Ok(())
                    })();
                    if let Err(error) = retained {
                        self.reconcile_mutable_effect(preparation.effect_id_sha256());
                        self.fail_credential_prerequisites();
                        return Err(error);
                    }
                    Ok(ShadowActiveEffectPermit::Verified { permit, generation_id, ingress_sequence, effect_kind })
                },
            _ => {
                // The append may already be durable even when its reply or
                // supervisor deadline fails. Preserve and reconcile this exact
                // reserved ID as well as settling earlier known siblings.
                self.reconcile_mutable_effect(preparation.effect_id_sha256());
                self.fail_credential_prerequisites();
                Err("credential prerequisite barrier failed or was ambiguous".to_string())
            }
        }
    }

    pub(crate) fn settle_credential_prerequisite(
        &self,
        reservation: &CredentialPrerequisiteReservation,
        index: usize,
        permit: ShadowActiveEffectPermit,
        terminal: ActiveEffectCommitState,
        result_sha256: &str,
        info: Option<&CredentialLeaseInfo>,
    ) -> Result<(), String> {
        let actual_binding = match &permit {
            ShadowActiveEffectPermit::Verified { permit, .. } => {
                let (generation, ingress) = permit.preparation().reconciliation_identity();
                Some((generation.clone(), ingress, permit.preparation().effect_id_sha256().clone()))
            },
            #[cfg(test)]
            ShadowActiveEffectPermit::InactiveForwardingTest => None,
        };
        let preparation = reservation.preparations.get(index).and_then(Option::as_ref);
        let result = (|| {
            self.validate_credential_reservation(reservation)?;
            let preparation = preparation.ok_or("credential prerequisite settlement index is invalid")?;
            let barrier = match &permit {
                ShadowActiveEffectPermit::Verified { permit, .. } if permit.preparation() == preparation =>
                    permit.signed_receipt_sha256().clone(),
                _ => {
                    return Err("credential prerequisite permit changed".to_string());
                }
            };
            {
                let state = self.inner.state.try_lock().map_err(|_| "credential prerequisite barrier join state is unavailable")?;
                if state.credential_prerequisites.slots[credential_outer_slot(preparation.effect_kind())?]
                    .and_then(|slot| slot.barrier) != Some(InlineSha256Digest::from_digest(&barrier)?)
                {
                    return Err("credential prerequisite permit differs from retained barrier".to_string());
                }
            }
            let retained_result = info.map(CredentialOuterResult::from_info).transpose()?;
            if (terminal == ActiveEffectCommitState::Committed) != retained_result.is_some()
                || retained_result.map(|result| result.result_commitment()).transpose()?
                    .is_some_and(|expected| expected != result_sha256)
            {
                return Err("credential prerequisite result commitment mismatch".to_string());
            }
            let receipt = self.commit_mutable_effect(permit, terminal, result_sha256)?;
            let compact = receipt.compact_for(preparation, &barrier, terminal,
                &Sha256Digest::parse(result_sha256.to_string()).map_err(shadow_error)?)
                .map_err(shadow_error)?;
            let mut state = self.inner.state.try_lock()
                .map_err(|_| "credential prerequisite receipt retention state is unavailable")?;
            if state.credential_prerequisites_sealed {
                return Err("credential prerequisite receipt retention is sealed".to_string());
            }
            state.credential_prerequisites.retain(reservation.parent, preparation, compact, retained_result)
        })();
        if result.is_err() {
            if let Some((generation, ingress, actual)) = actual_binding.as_ref() {
                self.reconcile_bound_mutable_effect(generation, *ingress, actual);
            }
            if let Some(expected) = preparation {
                if actual_binding.as_ref().map(|(_, _, effect)| effect) != Some(expected.effect_id_sha256()) {
                    let (generation, ingress) = expected.reconciliation_identity();
                    self.reconcile_bound_mutable_effect(generation, ingress, expected.effect_id_sha256());
                }
            }
            self.fail_credential_prerequisites();
        }
        result
    }

    pub(crate) fn publish_credential_resolution(
        &self,
        reservation: CredentialPrerequisiteReservation,
        info: &CredentialLeaseInfo,
    ) -> Result<CommittedCredentialPrerequisite, String> {
        self.validate_credential_reservation(&reservation)?;
        if !self.inner.generation_is_current() {
            return Err("credential prerequisite publication generation is not current".to_string());
        }
        let result = CredentialOuterResult::from_info(info)?;
        let mut state = self.inner.state.try_lock()
            .map_err(|_| "credential prerequisite publication state is unavailable")?;
        if state.credential_prerequisites_sealed || self.inner.finalization_consumed.load(Ordering::Acquire) {
            return Err("credential prerequisite publication is sealed".to_string());
        }
        state.credential_prerequisites.publish_resolution(reservation.parent, &reservation.preparations, result)?;
        Ok(CommittedCredentialPrerequisite {
            parent: reservation.parent,
            result,
            evidence_commitment: InlineSha256Digest::from_str(&state.credential_prerequisites.commitment())?,
        })
    }

    fn reconcile_mutable_effect(
        &self,
        effect_id_sha256: &Sha256Digest,
    ) -> bool {
        let Ok(generation) = Sha256Digest::parse(self.inner.generation.generation_id().to_string()) else {
            self.inner.ledger.mark_hard_unready();
            return false;
        };
        self.reconcile_bound_mutable_effect(&generation, self.inner.ingress_sequence, effect_id_sha256)
    }

    // Binding comes only from this lifecycle or a genuine verified permit's
    // preparation; never reassign a crossed permit to the receiving handle.
    fn reconcile_bound_mutable_effect(
        &self,
        generation_id: &Sha256Digest,
        ingress_sequence: u64,
        effect_id_sha256: &Sha256Digest,
    ) -> bool {
        let Some(custody) = self.inner.ledger.custody.get() else {
            self.inner.ledger.mark_hard_unready();
            return false;
        };
        let context = match custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::ReconcileActiveEffect,
            "reconcile-active-effect",
            effect_id_sha256.as_str(),
        ) {
            Ok(context) => context,
            Err(_) => {
                self.inner.ledger.mark_hard_unready();
                return false;
            }
        };
        let receipt_result = custody.reconcile_active_effect(
            &context,
            generation_id,
            ingress_sequence,
            effect_id_sha256,
        );
        let completed = finish_custody_call(custody.as_ref(), context);
        let reconciled = completed
            && receipt_result.is_ok_and(|receipt| {
                receipt.effect_id_sha256() == effect_id_sha256
                    && matches!(
                        receipt.terminal_state(),
                        ActiveEffectCommitState::OutcomeUnknown
                            | ActiveEffectCommitState::ReconcileRequired
                    )
            });
        if !reconciled {
            self.inner.ledger.mark_hard_unready();
        }
        reconciled
    }

    pub(crate) fn prepare_mutable_effect(
        &self,
        snapshot: &Arc<Snapshot>,
        effect_kind: ActiveMutableEffectKind,
        effect_intent_sha256: &str,
        prepared_state_sha256: &str,
    ) -> Result<ShadowActiveEffectPermit, String> {
        if !self.inner.generation_is_current_for(snapshot) {
            return Err(
                "active effect generation is no longer current".to_string(),
            );
        }
        let state = self.inner.state.try_lock().map_err(|_| {
            "active effect decision-time state is unavailable".to_string()
        })?;
        if state.decision_time_binding.is_none() {
            return Err(
                "active effect lacks a typed decision-time plan".to_string(),
            );
        }
        drop(state);
        let generation_id = Sha256Digest::parse(
            self.inner.generation.generation_id().to_string(),
        )
        .map_err(shadow_error)?;
        let preparation = ActiveEffectPreparation::new(
            generation_id,
            self.inner.ingress_sequence,
            effect_kind,
            Sha256Digest::parse(effect_intent_sha256.to_string())
                .map_err(shadow_error)?,
            Sha256Digest::parse(prepared_state_sha256.to_string())
                .map_err(shadow_error)?,
        )
        .map_err(shadow_error)?;
        let custody = self
            .inner
            .ledger
            .custody
            .get()
            .ok_or_else(|| {
                "active effect custody supervisor is not installed".to_string()
            })?;
        let context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::AppendActiveEffectBarrier,
            "append-active-effect-barrier",
            preparation.effect_id_sha256().as_str(),
        )?;
        let permit_result =
            custody.append_active_effect_barrier(&context, &preparation);
        if !finish_custody_call(custody.as_ref(), context) {
            if let Ok(permit) = permit_result.as_ref() {
                let (generation, ingress) = permit.preparation().reconciliation_identity();
                self.reconcile_bound_mutable_effect(generation, ingress, permit.preparation().effect_id_sha256());
            }
            self.reconcile_mutable_effect(preparation.effect_id_sha256());
            self.inner.ledger.mark_hard_unready();
            return Err(
                "active effect barrier supervisor exceeded its deadline"
                    .to_string(),
            );
        }
        let permit = permit_result.map_err(|error| {
            self.reconcile_mutable_effect(preparation.effect_id_sha256());
            self.inner.ledger.mark_hard_unready();
            shadow_error(error)
        })?;
        if permit.preparation() != &preparation {
            let (generation, ingress) = permit.preparation().reconciliation_identity();
            self.reconcile_bound_mutable_effect(generation, ingress, permit.preparation().effect_id_sha256());
            self.reconcile_mutable_effect(preparation.effect_id_sha256());
            self.inner.ledger.mark_hard_unready();
            return Err(
                "active effect permit does not match its preparation"
                    .to_string(),
            );
        }
        Ok(ShadowActiveEffectPermit::Verified {
            permit,
            generation_id:
                self.inner.generation.generation_id().to_string(),
            ingress_sequence: self.inner.ingress_sequence,
            effect_kind,
        })
    }

    pub(crate) fn commit_mutable_effect(
        &self,
        permit: ShadowActiveEffectPermit,
        terminal_state: ActiveEffectCommitState,
        result_sha256: &str,
    ) -> Result<VerifiedActiveEffectCommitReceipt, String> {
        let (permit, generation_id, ingress_sequence, effect_kind) = match permit {
            ShadowActiveEffectPermit::Verified {
                permit,
                generation_id,
                ingress_sequence,
                effect_kind,
            } => (permit, generation_id, ingress_sequence, effect_kind),
            #[cfg(test)]
            ShadowActiveEffectPermit::InactiveForwardingTest => {
                return Err("inactive test effect permit reached production custody".to_string())
            }
        };
        if generation_id != self.inner.generation.generation_id()
            || ingress_sequence != self.inner.ingress_sequence
            || permit.preparation().effect_kind() != effect_kind
        {
            self.inner.ledger.mark_hard_unready();
            return Err("active effect permit binding drift".to_string());
        }
        let result_sha256 =
            Sha256Digest::parse(result_sha256.to_string())
                .map_err(shadow_error)?;
        let effect_id_sha256 = permit.preparation().effect_id_sha256().clone();
        let expected_preparation = permit.preparation().clone();
        let expected_barrier = permit.signed_receipt_sha256().clone();
        let custody = self
            .inner
            .ledger
            .custody
            .get()
            .ok_or_else(|| {
                "active effect custody supervisor is not installed".to_string()
            })?;
        let context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::CommitActiveEffect,
            "commit-active-effect",
            effect_id_sha256.as_str(),
        )?;
        let receipt_result = custody.commit_active_effect(
            &context,
            permit,
            terminal_state,
            &result_sha256,
        );
        if !finish_custody_call(custody.as_ref(), context) {
            let reconciled =
                self.reconcile_mutable_effect(&effect_id_sha256);
            self.inner.ledger.mark_hard_unready();
            return Err(
                if reconciled {
                    "active effect commit deadline was durably reconciled"
                } else {
                    "active effect commit supervisor exceeded its deadline without reconciliation"
                }
                .to_string(),
            );
        }
        let receipt = match receipt_result {
            Ok(receipt) => receipt,
            Err(error) => {
                let reconciled =
                    self.reconcile_mutable_effect(&effect_id_sha256);
                self.inner.ledger.mark_hard_unready();
                return Err(if reconciled {
                    format!(
                        "active effect commit failed and was durably reconciled: {}",
                        shadow_error(error)
                    )
                } else {
                    format!(
                        "active effect commit failed without reconciliation: {}",
                        shadow_error(error)
                    )
                });
            }
        };
        if receipt.compact_for(&expected_preparation, &expected_barrier, terminal_state, &result_sha256).is_err()
        {
            self.reconcile_mutable_effect(&effect_id_sha256);
            self.inner.ledger.mark_hard_unready();
            return Err(
                "active effect commit receipt binding mismatch".to_string(),
            );
        }
        if matches!(
            terminal_state,
            ActiveEffectCommitState::OutcomeUnknown
                | ActiveEffectCommitState::ReconcileRequired
        ) {
            self.inner.ledger.mark_hard_unready();
        }
        Ok(receipt)
    }

    fn final_outcome(decision: &Value, _dispatch_authorized: bool) -> &'static str {
        if decision.get("allowed").and_then(Value::as_bool) == Some(true) {
            "allow"
        } else if decision.get("action").and_then(Value::as_str) == Some("jit_required") {
            "conditional"
        } else if decision
            .get("status_code")
            .and_then(Value::as_u64)
            .is_some_and(|status| status >= 500)
        {
            "error"
        } else {
            "deny"
        }
    }

    fn explicit_pending_active(
        &self,
        snapshot: &Arc<Snapshot>,
        decision: &Value,
        decision_at_epoch_ms: u128,
        dispatch_authorized: bool,
    ) -> Result<PendingActiveDecision, String> {
        let decision_at_epoch_ms = checked_epoch_ms(decision_at_epoch_ms)?;
        if decision_at_epoch_ms < self.inner.facts.captured_at_epoch_ms {
            return Err("final policy decision precedes ingress capture".to_string());
        }
        if !self.inner.generation_is_current_for(snapshot)
            || decision.get("policy_hash").and_then(Value::as_str)
                != Some(
                    self.inner
                        .generation
                        .identity
                        .active_snapshot_sha256
                        .as_str(),
                )
        {
            return Err("active snapshot changed before shadow finalization".to_string());
        }
        let (decision_time_binding, credential_prerequisites) = {
            let mut state = self.inner.state.try_lock()
                .map_err(|_| "shadow lifecycle mutex poisoned".to_string())?;
            state.credential_prerequisites.validate_decision(decision, dispatch_authorized)?;
            if state.credential_prerequisites.slots.iter().flatten().any(|slot| slot.receipt.is_none())
                && !state.credential_prerequisites.failed
            {
                return Err("credential prerequisites are still in flight before terminal sealing".to_string());
            }
            state.credential_prerequisites_sealed = true;
            (state.decision_time_binding.clone()
                .ok_or("decision-time active evaluation is unavailable")?, state.credential_prerequisites)
        };
        credential_prerequisites.validate_decision(decision, dispatch_authorized)?;
        if decision_time_binding.decision_at_epoch_ms
            != decision_at_epoch_ms
        {
            return Err(
                "terminal decision time differs from bound active evaluation"
                    .to_string(),
            );
        }
        let effect_requirements =
            decision_time_binding.effect_requirements.clone();
        let effect_results = decision
            .get("policy_effect_results")
            .and_then(Value::as_object)
            .ok_or("authoritative active effect results are unavailable")?;
        let mut explicit_effect_commitments = Vec::new();
        let mut commit = |name: &'static str, value: Option<&Value>| -> Result<(), String> {
            let value = value.ok_or_else(|| format!("active effect result {name} is unavailable"))?;
            explicit_effect_commitments.push(digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowExplicitEffectResult/v1",
                "name":name,
                "value":value,
            })));
            Ok(())
        };
        commit("trust-freshness", effect_results.get("trust_root_fresh"))?;
        if effect_requirements.gmail_prior_search_proof() {
            commit(
                "gmail-prior-search-proof",
                effect_results.get("gmail_prior_search_proof_resolved"),
            )?;
        }
        if effect_requirements.jit_grant() {
            commit("jit-grant", effect_results.get("jit_resolved"))?;
        }
        if effect_requirements.quota_reservation() {
            commit(
                "quota-reservation",
                effect_results
                    .get("quota_results_sha256")
                    .or_else(|| effect_results.get("legacy_rate_limits_committed")),
            )?;
        }
        if effect_requirements.durable_budget_reservation() {
            commit(
                "durable-budget-reservation",
                effect_results.get("durable_budget_results_sha256"),
            )?;
        }
        if effect_requirements.credential_materialization() {
            commit(
                "credential-generation",
                effect_results.get("credential_generation_resolved"),
            )?;
            commit(
                "credential-availability",
                effect_results.get("credential_secret_available"),
            )?;
            commit("credential-injection", decision.get("injection"))?;
        }
        commit("final-request", decision.get("request_digest"))?;
        commit("final-operation", decision.get("operation_digest"))?;
        if dispatch_authorized {
            commit(
                "final-upstream-request",
                effect_results
                    .get("final_upstream_request_commitment_sha256"),
            )?;
        }
        commit(
            "dispatch-authorization",
            Some(&Value::Bool(dispatch_authorized)),
        )?;
        explicit_effect_commitments.push(credential_prerequisites.commitment());
        explicit_effect_commitments.sort();
        explicit_effect_commitments.dedup();
        if explicit_effect_commitments.is_empty() {
            return Err("active effect result commitment set is empty".to_string());
        }
        Ok(PendingActiveDecision {
            decision_at_epoch_ms,
            active_plan_sha256:
                decision_time_binding.active_plan_sha256,
            active_evaluation:
                decision_time_binding.active_evaluation,
            final_outcome: Self::final_outcome(decision, dispatch_authorized).to_string(),
            effect_requirements,
            explicit_effect_commitments,
            final_upstream_request_commitment_sha256: effect_results
                .get("final_upstream_request_commitment_sha256")
                .and_then(Value::as_str)
                .filter(|value| value.starts_with("sha256:"))
                .map(str::to_string),
            resolved_credential_slot: decision
                .get("credential_ref")
                .and_then(Value::as_str)
                .map(str::to_string),
            resolved_credential_version: decision
                .get("credential_version")
                .and_then(Value::as_u64)
                .filter(|version| *version != 0),
            dispatch_authorized,
            active_decision: decision.clone(),
            credential_prerequisites,
        })
    }

    fn record_failure(
        &self,
        reason: PolicyShadowTerminalReason,
    ) -> bool {
        let record = ShadowAccountingEvent::minimal(
            self.inner.ingress_sequence,
            self.inner.request_binding_sha256.clone(),
            self.inner.request_commitment_sha256.clone(),
            ShadowRuntimeEvent::Failure(reason),
        );
        let recorded = self.inner
            .ledger
            .record(self.inner.generation.generation_id(), record, false);
        if !recorded {
            self.inner.ledger.mark_hard_unready();
        }
        recorded
    }

    fn finalize_terminal(
        &self,
        snapshot: &Arc<Snapshot>,
        pending: PendingActiveDecision,
        terminal_outcome: &str,
        returned_http_status: u16,
        terminal_response_sha256: String,
        exact_response_facts_sha256: Option<String>,
        active_response_validation_sha256: Option<String>,
        gmail_metadata_evidence_sha256: Option<String>,
        terminal_effect_commitments: Vec<String>,
    ) -> Result<(), String> {
        if !self.inner.generation_is_current_for(snapshot) {
            self.record_failure(
                PolicyShadowTerminalReason::GenerationChangedBeforeTerminal,
            );
            return Err("shadow generation changed before terminal finalization".to_string());
        }
        if !(200..=599).contains(&returned_http_status) {
            self.record_failure(
                if pending.dispatch_authorized {
                    PolicyShadowTerminalReason::PostDispatchTerminalHttpStatusInvalid
                } else {
                    PolicyShadowTerminalReason::PreDispatchTerminalHttpStatusInvalid
                },
            );
            return Err("terminal active HTTP status is invalid".to_string());
        }
        if !matches!(
            terminal_outcome,
            "allow" | "deny" | "conditional" | "error"
        ) {
            self.record_failure(
                PolicyShadowTerminalReason::TerminalOutcomeInvalid,
            );
            return Err("terminal active outcome is invalid".to_string());
        }
        if terminal_outcome == "allow"
            && pending.effect_requirements.response_validation()
            && active_response_validation_sha256.is_none()
        {
            self.record_failure(
                PolicyShadowTerminalReason::RequiredActiveResponseValidationUnavailable,
            );
            return Err("required active response validation is unavailable".to_string());
        }
        if terminal_outcome == "allow"
            && pending.effect_requirements.gmail_metadata_fanout()
            && gmail_metadata_evidence_sha256.is_none()
        {
            self.record_failure(
                PolicyShadowTerminalReason::RequiredGmailMetadataEvidenceUnavailable,
            );
            return Err("required Gmail metadata evidence is unavailable".to_string());
        }
        let decision_time_plan = pending
            .active_evaluation
            .active_plan()
            .ok_or("decision-time typed active plan is unavailable")?;
        if pending.active_evaluation.semantic_sha256
                != pending.active_plan_sha256
            || pending.effect_requirements
                != ActiveEffectRequirements::from_plan(decision_time_plan)
        {
            self.record_failure(
                PolicyShadowTerminalReason::DecisionTimePlanBindingMismatch,
            );
            return Err(
                "decision-time typed active plan binding mismatch".to_string(),
            );
        }
        let effect_results_value = json!({
            "domain":"serverware.policyShadowFinalEffectResults/v2",
            "activePlanSha256":pending.active_plan_sha256.as_str(),
            "explicitCommitments":pending.explicit_effect_commitments.as_slice(),
            "terminalResponseSha256":terminal_response_sha256.as_str(),
            "exactResponseFactsSha256":exact_response_facts_sha256.as_deref(),
            "activeResponseValidationSha256":active_response_validation_sha256.as_deref(),
            "gmailMetadataEvidenceSha256":gmail_metadata_evidence_sha256.as_deref(),
            "terminalEffectCommitments":terminal_effect_commitments,
        });
        let prerequisite_effect_root = PrerequisiteEffectRoot::new(
            &pending.credential_prerequisites, &effect_results_value,
        )?;
        let effect_results_sha256 = digest_json_ensure_ascii(&effect_results_value);
        let final_decision_sha256 = final_active_outcome_digest(
            &pending.active_plan_sha256,
            terminal_outcome,
            returned_http_status,
            pending.dispatch_authorized,
            &effect_results_sha256,
            &terminal_response_sha256,
        );
        let final_active = FinalActiveDecision {
            decision_at_epoch_ms: pending.decision_at_epoch_ms,
            active_evaluation: pending.active_evaluation,
            effect_requirements: pending.effect_requirements,
            final_outcome: terminal_outcome.to_string(),
            final_decision_sha256,
            effect_results_sha256,
            terminal_response_sha256,
            exact_response_facts_sha256,
            gmail_metadata_evidence_sha256,
            resolved_credential_slot: pending.resolved_credential_slot,
            resolved_credential_version: pending.resolved_credential_version,
            dispatch_authorized: pending.dispatch_authorized,
            credential_prerequisites: pending.credential_prerequisites,
            prerequisite_effect_root,
        };
        let state = match self.inner.state.try_lock() {
            Ok(state) => state,
            Err(_) => {
                self.record_failure(
                    PolicyShadowTerminalReason::TerminalStateContention,
                );
                return Err("shadow lifecycle state is busy".to_string());
            }
        };
        if state.credential_prerequisites != final_active.credential_prerequisites {
            return Err("credential prerequisite evidence changed before terminal append".to_string());
        }
        if self.inner.finalization_consumed.load(Ordering::Acquire)
            || state.final_active.is_some()
        {
            self.record_failure(
                PolicyShadowTerminalReason::DuplicateTerminalFinalization,
            );
            return Err(
                "shadow active terminal evidence was already finalized"
                    .to_string(),
            );
        }
        drop(state);
        let terminal_event = final_active.terminal_event(
            self.inner.ingress_sequence,
            self.inner.request_binding_sha256.clone(),
            self.inner.request_commitment_sha256.clone(),
            active_response_validation_sha256.clone(),
        );
        let dispatch_authorized = final_active.dispatch_authorized;
        let prepared_record = PreparedActiveTerminalRecord::new(
            self.inner.generation.generation_id(),
            self.inner.ingress_sequence,
            &self.inner.request_binding_sha256,
            &self.inner.request_commitment_sha256,
            final_active,
            returned_http_status,
            active_response_validation_sha256.as_deref(),
            &terminal_event,
        ).map_err(|error| {
            self.record_failure(PolicyShadowTerminalReason::DecisionTimePlanBindingMismatch);
            error
        })?;
        let receipt = self.inner.ledger.record_with_receipt(
            self.inner.generation.generation_id(),
            terminal_event,
            false,
        ).ok_or("custody did not append terminal active evidence")?;
        let matched_record = prepared_record.match_receipt(receipt).map_err(|error| {
            self.inner.ledger.mark_hard_unready();
            error
        })?;
        if self
            .inner
            .finalization_consumed
            .compare_exchange(
                false,
                true,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.record_failure(
                PolicyShadowTerminalReason::DuplicateTerminalFinalization,
            );
            return Err(
                "terminal flag contention followed durable evidence append"
                    .to_string(),
            );
        }
        if dispatch_authorized
            && self
                .inner
                .response_terminal_recorded
                .compare_exchange(
                    false,
                    true,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            self.record_failure(
                PolicyShadowTerminalReason::DuplicateTerminalFinalization,
            );
            return Err(
                "response terminal flag contention followed durable terminal append"
                    .to_string(),
            );
        }
        let mut state = match self.inner.state.try_lock() {
            Ok(state) => state,
            Err(_) => {
                self.record_failure(
                    PolicyShadowTerminalReason::TerminalStateContention,
                );
                return Err(
                    "shadow lifecycle state is busy after durable terminal append"
                        .to_string(),
                );
            }
        };
        if !state.credential_prerequisites_sealed
            || state.credential_prerequisites != matched_record.prepared.decision.credential_prerequisites
        {
            self.inner.ledger.mark_hard_unready();
            return Err("credential prerequisite evidence changed after terminal append".to_string());
        }
        state.final_active = Some(matched_record.into_record());
        state.response_finished = true;
        drop(state);
        if let Err(error) = self.enqueue_request_evaluation() {
            self.record_failure(
                PolicyShadowTerminalReason::CandidateEnqueueFailed,
            );
            let _ = error;
        }
        Ok(())
    }

    pub(crate) fn record_unready_accounting(
        &self,
        reason: PolicyShadowTerminalReason,
    ) {
        self.inner.ledger.mark_hard_unready();
        let record = ShadowAccountingEvent::minimal(
            self.inner.ingress_sequence,
            self.inner.request_binding_sha256.clone(),
            self.inner.request_commitment_sha256.clone(),
            ShadowRuntimeEvent::CleanupQuarantined(reason),
        );
        if !self.inner.ledger.record(
            self.inner.generation.generation_id(),
            record,
            false,
        ) {
            self.inner.ledger.mark_hard_unready();
        }
    }

    pub(crate) fn finalize_pre_dispatch_local_response(
        &self,
        snapshot: &Arc<Snapshot>,
        decision: &Value,
        decision_at_epoch_ms: u128,
        returned_http_status: u16,
        local_response: &[u8],
    ) -> Result<(), String> {
        let staged_dispatch = self
            .inner
            .state
            .try_lock()
            .map_err(|_| "shadow lifecycle mutex poisoned".to_string())?
            .pending_active
            .clone();
        if staged_dispatch.is_some() {
            self.record_failure(
                PolicyShadowTerminalReason::PostDispatchTypedCompletionRequired,
            );
            return Err(
                "post-dispatch outcome requires typed terminal completion"
                    .to_string(),
            );
        }
        let pending =
            self.explicit_pending_active(snapshot, decision, decision_at_epoch_ms, false)?;
        let terminal_outcome = Self::final_outcome(decision, false);
        let terminal_response_sha256 = sha256_prefixed(local_response);
        let terminal_effects = match self.pre_dispatch_terminal_effects(
            &pending,
            decision,
            returned_http_status,
            &terminal_response_sha256,
        ) {
            Ok(effects) => effects,
            Err(error) => {
                self.record_failure(
                    PolicyShadowTerminalReason::EarlyLocalTerminalEvidenceUnavailable,
                );
                return Err(error);
            }
        };
        let terminal_effect_commitments =
            terminal_effects.validate_exact_and_commit(
                &pending.effect_requirements,
                None,
                &terminal_response_sha256,
                None,
            )?;
        self.finalize_terminal(
            snapshot,
            pending,
            terminal_outcome,
            returned_http_status,
            terminal_response_sha256,
            Some(digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowExactLocalResponse/v1",
                "status":returned_http_status,
                "wireResponseSha256":sha256_prefixed(local_response),
                "wireResponseBytes":local_response.len(),
            }))),
            None,
            None,
            terminal_effect_commitments,
        )
    }

    fn pre_dispatch_terminal_effects(
        &self,
        pending: &PendingActiveDecision,
        decision: &Value,
        returned_http_status: u16,
        terminal_response_sha256: &str,
    ) -> Result<ActiveTerminalEffectSet, String> {
        let effect_results = decision
            .get("policy_effect_results")
            .and_then(Value::as_object);
        let lookup = |requirement: ActiveEffectRequirement| -> Option<&Value> {
            if requirement == ActiveEffectRequirement::FinalRequest {
                return decision.get("request_digest");
            }
            if requirement == ActiveEffectRequirement::CredentialInjection {
                return decision.get("injection");
            }
            let name = match requirement {
                ActiveEffectRequirement::TrustFreshness => "trust_root_fresh",
                ActiveEffectRequirement::GmailPriorSearchProof => {
                    "gmail_prior_search_proof_resolved"
                }
                ActiveEffectRequirement::GmailMetadataFanout => {
                    "gmail_metadata_fanout_resolved"
                }
                ActiveEffectRequirement::JitGrant => "jit_resolved",
                ActiveEffectRequirement::QuotaReserve => {
                    "quota_reservation_sha256"
                }
                ActiveEffectRequirement::QuotaTerminal => {
                    "quota_completion_sha256"
                }
                ActiveEffectRequirement::DurableBudgetReserve => {
                    "durable_budget_reservation_sha256"
                }
                ActiveEffectRequirement::DurableBudgetTerminal => {
                    "durable_budget_completion_sha256"
                }
                ActiveEffectRequirement::CredentialVersion => {
                    "credential_generation_resolved"
                }
                ActiveEffectRequirement::CredentialLease => {
                    "credential_lease_sha256"
                }
                ActiveEffectRequirement::CredentialDecrypt => {
                    "credential_decrypt_sha256"
                }
                ActiveEffectRequirement::CredentialInjection => unreachable!(),
                ActiveEffectRequirement::OauthRefresh => {
                    "oauth_refresh_sha256"
                }
                ActiveEffectRequirement::OauthExchange => {
                    "oauth_exchange_sha256"
                }
                ActiveEffectRequirement::OauthMint => "oauth_mint_sha256",
                ActiveEffectRequirement::IdempotencyBinding => {
                    "idempotency_binding_sha256"
                }
                ActiveEffectRequirement::RecoveryResolution => {
                    "recovery_resolution_sha256"
                }
                ActiveEffectRequirement::FinalRequest => unreachable!(),
                ActiveEffectRequirement::DispatchAuthorization
                | ActiveEffectRequirement::DispatchTerminal
                | ActiveEffectRequirement::ResponseValidation
                | ActiveEffectRequirement::TerminalResponse => return None,
            };
            effect_results.and_then(|results| results.get(name))
        };
        let mut evidence = Vec::with_capacity(
            pending.effect_requirements.as_slice().len(),
        );
        for requirement in pending.effect_requirements.as_slice() {
            let (terminal_state, result_sha256) = match requirement {
                ActiveEffectRequirement::TerminalResponse => (
                    ActiveEffectTerminalState::Completed,
                    Sha256Digest::parse(terminal_response_sha256.to_string())
                        .map_err(shadow_error)?,
                ),
                ActiveEffectRequirement::DispatchAuthorization => (
                    ActiveEffectTerminalState::Denied,
                    canonical_digest(&json!({
                        "domain":"serverware.policyShadowDispatchAuthorization/v1",
                        "authorized":false,
                        "status":returned_http_status,
                    }))?,
                ),
                ActiveEffectRequirement::DispatchTerminal
                | ActiveEffectRequirement::ResponseValidation
                | ActiveEffectRequirement::GmailMetadataFanout => (
                    ActiveEffectTerminalState::NotReached,
                    canonical_digest(&json!({
                        "domain":"serverware.policyShadowEffectNotReached/v1",
                        "requirement":requirement,
                        "stage":"pre-dispatch-local-response",
                        "status":returned_http_status,
                    }))?,
                ),
                _ => match lookup(*requirement) {
                    Some(Value::Null) => (
                        ActiveEffectTerminalState::NotReached,
                        canonical_digest(&json!({
                            "domain":"serverware.policyShadowEffectNotReached/v1",
                            "requirement":requirement,
                            "stage":"pre-dispatch-local-response",
                            "status":returned_http_status,
                        }))?,
                    ),
                    Some(value) => (
                        if value == &Value::Bool(false) {
                            ActiveEffectTerminalState::Denied
                        } else {
                            ActiveEffectTerminalState::Completed
                        },
                        canonical_digest(&json!({
                            "domain":"serverware.policyShadowNamedEffectResult/v1",
                            "requirement":requirement,
                            "value":value,
                        }))?,
                    ),
                    None => (
                        ActiveEffectTerminalState::NotReached,
                        canonical_digest(&json!({
                            "domain":"serverware.policyShadowEffectNotReached/v1",
                            "requirement":requirement,
                            "stage":"pre-dispatch-local-response",
                            "status":returned_http_status,
                        }))?,
                    ),
                },
            };
            evidence.push(ActiveEffectTerminalEvidence::from_active_executor(
                *requirement,
                terminal_state,
                result_sha256,
            ));
        }
        ActiveTerminalEffectSet::from_active_executor(evidence)
    }

    pub(crate) fn finalize_post_dispatch_terminal(
        &self,
        snapshot: &Arc<Snapshot>,
        terminal_outcome: &str,
        returned_http_status: u16,
        returned_response: &[u8],
        exact_response_facts_sha256: Option<String>,
        active_response_validation_sha256: Option<String>,
        gmail_metadata_evidence_sha256: Option<String>,
        terminal_effects: ActiveTerminalEffectSet,
    ) -> Result<(), String> {
        let pending = self
            .inner
            .state
            .try_lock()
            .map_err(|_| "shadow lifecycle mutex poisoned".to_string())?
            .pending_active
            .clone()
            .ok_or("active dispatch barrier evidence is unavailable")?;
        let terminal_response_sha256 = sha256_prefixed(returned_response);
        let commitments = terminal_effects.validate_exact_and_commit(
            &pending.effect_requirements,
            active_response_validation_sha256.as_deref(),
            &terminal_response_sha256,
            gmail_metadata_evidence_sha256.as_deref(),
        )?;
        if terminal_outcome == "allow" {
            terminal_effects.require_all_completed()?;
        }
        self.finalize_terminal(
            snapshot,
            pending,
            terminal_outcome,
            returned_http_status,
            terminal_response_sha256,
            exact_response_facts_sha256,
            active_response_validation_sha256,
            gmail_metadata_evidence_sha256,
            commitments,
        )
    }

    pub(crate) fn finalize_post_dispatch_unknown(
        &self,
        snapshot: &Arc<Snapshot>,
        decision: &Value,
        returned_http_status: u16,
        returned_response: &[u8],
        reason: PolicyShadowTerminalReason,
    ) -> Result<(), String> {
        self.finalize_post_dispatch_state(
            snapshot,
            decision,
            returned_http_status,
            returned_response,
            reason,
            "error",
            false,
        )
    }

    fn finalize_post_dispatch_response_observed(
        &self,
        snapshot: &Arc<Snapshot>,
        returned_response: &[u8],
        reason: PolicyShadowTerminalReason,
    ) -> Result<(), String> {
        let pending = self
            .inner
            .state
            .try_lock()
            .map_err(|_| "shadow lifecycle state is busy".to_string())?
            .pending_active
            .clone()
            .ok_or("active dispatch barrier evidence is unavailable")?;
        let returned_http_status = parse_buffered_response(returned_response)
            .map(|response| response.status)
            .map_err(|_| "returned response is not exact buffered HTTP".to_string())?;
        let terminal_outcome = if reason.response_was_released() {
            "allow"
        } else if returned_http_status >= 500 {
            "error"
        } else {
            "deny"
        };
        self.finalize_post_dispatch_state(
            snapshot,
            &pending.active_decision,
            returned_http_status,
            returned_response,
            reason,
            terminal_outcome,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_post_dispatch_state(
        &self,
        snapshot: &Arc<Snapshot>,
        decision: &Value,
        returned_http_status: u16,
        returned_response: &[u8],
        reason: PolicyShadowTerminalReason,
        terminal_outcome: &str,
        provider_response_observed: bool,
    ) -> Result<(), String> {
        let pending = self
            .inner
            .state
            .try_lock()
            .map_err(|_| "shadow lifecycle mutex poisoned".to_string())?
            .pending_active
            .clone()
            .ok_or("active dispatch barrier evidence is unavailable")?;
        let effect_results = decision
            .get("policy_effect_results")
            .and_then(Value::as_object);
        let terminal_response_sha256 = sha256_prefixed(returned_response);
        // Parsed adapter output is not authoritative response-validation or
        // Gmail fanout evidence. Those results must come from the active
        // executor or the authenticated raw transport path.
        let parsed_response_validation_sha256: Option<String> = None;
        let observed_gmail_metadata_sha256: Option<String> = None;
        let mut evidence = Vec::with_capacity(
            pending.effect_requirements.as_slice().len(),
        );
        for requirement in pending.effect_requirements.as_slice() {
            let (state, digest) = match requirement {
                ActiveEffectRequirement::TrustFreshness => {
                    let value = effect_results
                        .and_then(|results| results.get("trust_root_fresh"))
                        .ok_or(
                            "post-dispatch trust freshness evidence is unavailable",
                        )?;
                    (
                        match value.as_bool() {
                            Some(true) => ActiveEffectTerminalState::Completed,
                            Some(false) => ActiveEffectTerminalState::Failed,
                            None => {
                                ActiveEffectTerminalState::ProviderOutcomeUnknown
                            }
                        },
                        canonical_digest(&json!({
                            "domain":"serverware.policyShadowNamedEffectResult/v1",
                            "requirement":requirement,
                            "value":value,
                        }))?,
                    )
                }
                ActiveEffectRequirement::FinalRequest => {
                    let value = decision
                        .get("request_digest")
                        .filter(|value| !value.is_null())
                        .ok_or(
                            "post-dispatch final request evidence is unavailable",
                        )?;
                    (
                        ActiveEffectTerminalState::Completed,
                        canonical_digest(&json!({
                            "domain":"serverware.policyShadowNamedEffectResult/v1",
                            "requirement":requirement,
                            "value":value,
                        }))?,
                    )
                }
                ActiveEffectRequirement::TerminalResponse => (
                    ActiveEffectTerminalState::Completed,
                    Sha256Digest::parse(terminal_response_sha256.clone())
                        .map_err(shadow_error)?,
                ),
                ActiveEffectRequirement::DispatchAuthorization => (
                    ActiveEffectTerminalState::Completed,
                    canonical_digest(&json!({
                        "domain":"serverware.policyShadowDispatchAuthorization/v1",
                        "authorized":true,
                    }))?,
                ),
                ActiveEffectRequirement::DispatchTerminal => (
                    if provider_response_observed {
                        ActiveEffectTerminalState::Completed
                    } else {
                        ActiveEffectTerminalState::ProviderOutcomeUnknown
                    },
                    canonical_digest(&json!({
                        "domain":"serverware.policyShadowDispatchTerminal/v1",
                        "failureClassSha256":sha256_prefixed(
                            reason.label().as_bytes()
                        ),
                        "providerResponseObserved":provider_response_observed,
                    }))?,
                ),
                ActiveEffectRequirement::QuotaTerminal
                | ActiveEffectRequirement::DurableBudgetTerminal => {
                    let key = if *requirement
                        == ActiveEffectRequirement::QuotaTerminal
                    {
                        "quota_completion_sha256"
                    } else {
                        "durable_budget_completion_sha256"
                    };
                    match effect_results.and_then(|results| results.get(key)) {
                        Some(value) if !value.is_null() => (
                            if value == &Value::Bool(false) {
                                ActiveEffectTerminalState::Denied
                            } else {
                                ActiveEffectTerminalState::Completed
                            },
                            canonical_digest(&json!({
                                "domain":"serverware.policyShadowNamedEffectResult/v1",
                                "requirement":requirement,
                                "value":value,
                            }))?,
                        ),
                        _ => (
                            ActiveEffectTerminalState::ProviderOutcomeUnknown,
                            canonical_digest(&json!({
                                "domain":"serverware.policyShadowProviderTruthUnknown/v1",
                                "requirement":requirement,
                                "failureClassSha256":sha256_prefixed(
                                    reason.label().as_bytes()
                                ),
                                "providerResponseObserved":provider_response_observed,
                            }))?,
                        ),
                    }
                }
                ActiveEffectRequirement::RecoveryResolution => {
                    match effect_results.and_then(|results| {
                        results.get("recovery_resolution_sha256")
                    }) {
                        Some(value) if !value.is_null() => (
                            ActiveEffectTerminalState::Completed,
                            canonical_digest(&json!({
                                "domain":"serverware.policyShadowNamedEffectResult/v1",
                                "requirement":requirement,
                                "value":value,
                            }))?,
                        ),
                        _ => (
                            ActiveEffectTerminalState::RecoveryRequired,
                            canonical_digest(&json!({
                                "domain":"serverware.policyShadowRecoveryRequired/v1",
                                "failureClassSha256":sha256_prefixed(
                                    reason.label().as_bytes()
                                ),
                                "providerResponseObserved":provider_response_observed,
                            }))?,
                        ),
                    }
                }
                ActiveEffectRequirement::ResponseValidation => (
                    if provider_response_observed {
                        ActiveEffectTerminalState::ProviderOutcomeUnknown
                    } else {
                        ActiveEffectTerminalState::NotReached
                    },
                    canonical_digest(&json!({
                        "domain":"serverware.policyShadowResponseValidationUnavailable/v1",
                        "requirement":requirement,
                        "providerResponseObserved":provider_response_observed,
                        "failureClassSha256":sha256_prefixed(
                            reason.label().as_bytes()
                        ),
                    }))?,
                ),
                ActiveEffectRequirement::GmailMetadataFanout => (
                    if provider_response_observed {
                        ActiveEffectTerminalState::ProviderOutcomeUnknown
                    } else {
                        ActiveEffectTerminalState::NotReached
                    },
                    canonical_digest(&json!({
                        "domain":"serverware.policyShadowGmailMetadataUnavailable/v1",
                        "requirement":requirement,
                        "providerResponseObserved":provider_response_observed,
                        "failureClassSha256":sha256_prefixed(
                            reason.label().as_bytes()
                        ),
                    }))?,
                ),
                _ => {
                    let key = match requirement {
                        ActiveEffectRequirement::GmailPriorSearchProof => {
                            "gmail_prior_search_proof_resolved"
                        }
                        ActiveEffectRequirement::JitGrant => "jit_resolved",
                        ActiveEffectRequirement::QuotaReserve => {
                            "quota_reservation_sha256"
                        }
                        ActiveEffectRequirement::DurableBudgetReserve => {
                            "durable_budget_reservation_sha256"
                        }
                        ActiveEffectRequirement::CredentialVersion => {
                            "credential_generation_resolved"
                        }
                        ActiveEffectRequirement::CredentialLease => {
                            "credential_lease_sha256"
                        }
                        ActiveEffectRequirement::CredentialDecrypt => {
                            "credential_decrypt_sha256"
                        }
                        ActiveEffectRequirement::CredentialInjection => {
                            "credential_injection_sha256"
                        }
                        ActiveEffectRequirement::OauthRefresh => {
                            "oauth_refresh_sha256"
                        }
                        ActiveEffectRequirement::OauthExchange => {
                            "oauth_exchange_sha256"
                        }
                        ActiveEffectRequirement::OauthMint => {
                            "oauth_mint_sha256"
                        }
                        ActiveEffectRequirement::IdempotencyBinding => {
                            "idempotency_binding_sha256"
                        }
                        _ => unreachable!(),
                    };
                    match effect_results.and_then(|results| results.get(key)) {
                        Some(value) if !value.is_null() => (
                            if value == &Value::Bool(false) {
                                ActiveEffectTerminalState::Denied
                            } else {
                                ActiveEffectTerminalState::Completed
                            },
                            canonical_digest(&json!({
                                "domain":"serverware.policyShadowNamedEffectResult/v1",
                                "requirement":requirement,
                                "value":value,
                            }))?,
                        ),
                        _ => (
                            ActiveEffectTerminalState::ProviderOutcomeUnknown,
                            canonical_digest(&json!({
                                "domain":"serverware.policyShadowEffectStateUnknown/v1",
                                "requirement":requirement,
                                "failureClassSha256":sha256_prefixed(
                                    reason.label().as_bytes()
                                ),
                            }))?,
                        ),
                    }
                }
            };
            evidence.push(ActiveEffectTerminalEvidence::from_active_executor(
                *requirement,
                state,
                digest,
            ));
        }
        let terminal_effects =
            ActiveTerminalEffectSet::from_active_executor(evidence)?;
        self.finalize_post_dispatch_terminal(
            snapshot,
            terminal_outcome,
            returned_http_status,
            returned_response,
            Some(digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowExactPostDispatchLocalResponse/v1",
                "status":returned_http_status,
                "responseSha256":terminal_response_sha256,
                "responseBytes":returned_response.len(),
                "failureClassSha256":sha256_prefixed(reason.label().as_bytes()),
                "providerResponseObserved":provider_response_observed,
            }))),
            parsed_response_validation_sha256,
            observed_gmail_metadata_sha256,
            terminal_effects,
        )
    }

    pub(crate) fn record_dispatch_barrier(
        &self,
        snapshot: &Arc<Snapshot>,
        decision: &Value,
        decision_at_epoch_ms: u128,
    ) -> Result<ShadowDispatchBarrierPermit, String> {
        if decision.get("allowed").and_then(Value::as_bool) != Some(true) {
            self.record_failure(
                PolicyShadowTerminalReason::DispatchBarrierNonAllow,
            );
            return Err("only an allowed decision can cross the dispatch barrier".to_string());
        }
        let pending = match self.explicit_pending_active(
            snapshot,
            decision,
            decision_at_epoch_ms,
            true,
        ) {
            Ok(pending) => pending,
            Err(error) => {
                self.record_failure(
                    PolicyShadowTerminalReason::DispatchBarrierEvidenceUnavailable,
                );
                return Err(error);
            }
        };
        let state = self
            .inner
            .state
            .try_lock()
            .map_err(|_| {
                self.record_failure(
                    PolicyShadowTerminalReason::DispatchBarrierStateContention,
                );
                "shadow lifecycle mutex poisoned".to_string()
            })?;
        if state.pending_active.is_some() || state.final_active.is_some() {
            drop(state);
            self.record_failure(
                PolicyShadowTerminalReason::DuplicateDispatchBarrier,
            );
            return Err("shadow dispatch barrier was already recorded".to_string());
        }
        drop(state);
        let final_upstream_request_commitment_sha256 = pending
            .final_upstream_request_commitment_sha256
            .clone()
            .ok_or_else(|| {
                self.inner.ledger.mark_hard_unready();
                "dispatch barrier lacks final upstream request commitment"
                    .to_string()
            })?;
        let effect_authority_commitments_sha256 =
            digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowDispatchAuthorities/v1",
                "activePlanSha256":pending.active_plan_sha256.as_str(),
                "explicitEffectCommitments":
                    pending.explicit_effect_commitments.as_slice(),
                "dispatchAuthorized":pending.dispatch_authorized,
            }));
        let decision_at_unix_nanos =
            checked_epoch_ms_to_unix_nanos(pending.decision_at_epoch_ms)
                .map_err(|error| {
                    self.record_failure(
                        PolicyShadowTerminalReason::DispatchBarrierEvidenceUnavailable,
                    );
                    error
                })?;
        let mut barrier_record = ShadowAccountingEvent::minimal(
            self.inner.ingress_sequence,
            self.inner.request_binding_sha256.clone(),
            self.inner.request_commitment_sha256.clone(),
            ShadowRuntimeEvent::DispatchBarrierAppended,
        );
        barrier_record.active_plan_sha256 =
            Some(pending.active_plan_sha256.clone());
        barrier_record.active_disposition =
            Some(pending.final_outcome.clone());
        barrier_record.active_effect_results_sha256 =
            Some(effect_authority_commitments_sha256.clone());
        barrier_record.decision_at_unix_nanos =
            Some(decision_at_unix_nanos);
        barrier_record.dispatch_final_request_sha256 =
            Some(final_upstream_request_commitment_sha256.clone());
        barrier_record.dispatch_effect_authority_sha256 =
            Some(effect_authority_commitments_sha256.clone());
        let receipt = self
            .inner
            .ledger
            .record_with_receipt(
                self.inner.generation.generation_id(),
                barrier_record,
                true,
            )
            .ok_or_else(|| {
                self.inner.ledger.mark_hard_unready();
                "custody did not append the dispatch barrier".to_string()
            })?;
        let permit_active_plan_sha256 =
            pending.active_plan_sha256.clone();
        let permit_decision_at_epoch_ms = pending.decision_at_epoch_ms;
        let mut state = self.inner.state.try_lock().map_err(|_| {
            self.record_failure(
                PolicyShadowTerminalReason::DispatchBarrierStateContention,
            );
            "shadow lifecycle state is busy after durable dispatch barrier"
                .to_string()
        })?;
        if state.pending_active.is_some() || state.final_active.is_some() {
            self.record_failure(
                PolicyShadowTerminalReason::DuplicateDispatchBarrier,
            );
            return Err(
                "shadow dispatch barrier state changed after durable append"
                    .to_string(),
            );
        }
        state.pending_active = Some(pending);
        drop(state);
        let provider_send_permit = self.prepare_mutable_effect(
            snapshot,
            ActiveMutableEffectKind::ProviderSend,
            &effect_authority_commitments_sha256,
            &final_upstream_request_commitment_sha256,
        )?;
        Ok(ShadowDispatchBarrierPermit {
            generation_id: receipt.generation_id,
            ingress_sequence: receipt.ingress_sequence,
            request_binding_sha256: InlineSha256Digest::from_str(
                &self.inner.request_binding_sha256,
            )?,
            request_commitment_sha256: InlineSha256Digest::from_str(
                &self.inner.request_commitment_sha256,
            )?,
            active_plan_sha256: InlineSha256Digest::from_str(
                &permit_active_plan_sha256,
            )?,
            decision_at_epoch_ms: permit_decision_at_epoch_ms,
            final_upstream_request_commitment_sha256:
                InlineSha256Digest::from_str(
                    &final_upstream_request_commitment_sha256,
                )?,
            effect_authority_commitments_sha256:
                InlineSha256Digest::from_str(
                    &effect_authority_commitments_sha256,
                )?,
            event_ordinal: receipt.event_ordinal,
            event_sha256: receipt.event_sha256,
            resulting_head_sha256: receipt.resulting_head_sha256,
            signed_receipt_sha256: receipt.signed_receipt_sha256,
            retrieval_id_sha256: receipt.retrieval_id_sha256,
            retrieval_proof_sha256: receipt.retrieval_proof_sha256,
            verified_payload_sha256: receipt.verified_payload_sha256,
            verified_trust_checkpoint_sha256:
                receipt.verified_trust_checkpoint_sha256,
            active_effect_owner: self.clone(),
            provider_send_permit: Some(provider_send_permit),
            secondary_effect_permit: None,
        })
    }

    pub(crate) fn record_effect_dispatch_barrier(
        &self,
        snapshot: &Arc<Snapshot>,
        effect_authority_commitment_sha256: String,
        final_upstream_request_commitment_sha256: String,
    ) -> Result<ShadowDispatchBarrierPermit, String> {
        if !self.inner.generation_is_current_for(snapshot)
            || !effect_authority_commitment_sha256.starts_with("sha256:")
            || !final_upstream_request_commitment_sha256
                .starts_with("sha256:")
        {
            self.record_failure(
                PolicyShadowTerminalReason::DispatchBarrierEvidenceUnavailable,
            );
            return Err(
                "effect dispatch barrier binding is unavailable".to_string(),
            );
        }
        let pending = self
            .inner
            .state
            .try_lock()
            .map_err(|_| {
                self.record_failure(
                    PolicyShadowTerminalReason::DispatchBarrierStateContention,
                );
                "shadow lifecycle state is busy".to_string()
            })?
            .pending_active
            .clone()
            .filter(|pending| pending.dispatch_authorized)
            .ok_or_else(|| {
                self.record_failure(
                    PolicyShadowTerminalReason::DispatchBarrierEvidenceUnavailable,
                );
                "effect dispatch requires an appended parent barrier".to_string()
            })?;
        let decision_at_unix_nanos =
            checked_epoch_ms_to_unix_nanos(pending.decision_at_epoch_ms)
                .map_err(|error| {
                    self.record_failure(
                        PolicyShadowTerminalReason::DispatchBarrierEvidenceUnavailable,
                    );
                    error
                })?;
        let mut barrier_record = ShadowAccountingEvent::minimal(
            self.inner.ingress_sequence,
            self.inner.request_binding_sha256.clone(),
            self.inner.request_commitment_sha256.clone(),
            ShadowRuntimeEvent::DispatchBarrierAppended,
        );
        barrier_record.active_plan_sha256 =
            Some(pending.active_plan_sha256.clone());
        barrier_record.active_disposition =
            Some(pending.final_outcome.clone());
        barrier_record.active_effect_results_sha256 =
            Some(effect_authority_commitment_sha256.clone());
        barrier_record.decision_at_unix_nanos =
            Some(decision_at_unix_nanos);
        barrier_record.dispatch_final_request_sha256 =
            Some(final_upstream_request_commitment_sha256.clone());
        barrier_record.dispatch_effect_authority_sha256 =
            Some(effect_authority_commitment_sha256.clone());
        let receipt = self
            .inner
            .ledger
            .record_with_receipt(
                self.inner.generation.generation_id(),
                barrier_record,
                true,
            )
            .ok_or_else(|| {
                self.inner.ledger.mark_hard_unready();
                "custody did not append the effect dispatch barrier"
                    .to_string()
            })?;
        let provider_send_permit = self.prepare_mutable_effect(
            snapshot,
            ActiveMutableEffectKind::ProviderSend,
            &effect_authority_commitment_sha256,
            &final_upstream_request_commitment_sha256,
        )?;
        let gmail_child_permit = self.prepare_mutable_effect(
            snapshot,
            ActiveMutableEffectKind::GmailChildDispatch,
            &effect_authority_commitment_sha256,
            &final_upstream_request_commitment_sha256,
        )?;
        Ok(ShadowDispatchBarrierPermit {
            generation_id: receipt.generation_id,
            ingress_sequence: receipt.ingress_sequence,
            request_binding_sha256: InlineSha256Digest::from_str(
                &self.inner.request_binding_sha256,
            )?,
            request_commitment_sha256: InlineSha256Digest::from_str(
                &self.inner.request_commitment_sha256,
            )?,
            active_plan_sha256: InlineSha256Digest::from_str(
                &pending.active_plan_sha256,
            )?,
            decision_at_epoch_ms: pending.decision_at_epoch_ms,
            final_upstream_request_commitment_sha256:
                InlineSha256Digest::from_str(
                    &final_upstream_request_commitment_sha256,
                )?,
            effect_authority_commitments_sha256:
                InlineSha256Digest::from_str(
                    &effect_authority_commitment_sha256,
                )?,
            event_ordinal: receipt.event_ordinal,
            event_sha256: receipt.event_sha256,
            resulting_head_sha256: receipt.resulting_head_sha256,
            signed_receipt_sha256: receipt.signed_receipt_sha256,
            retrieval_id_sha256: receipt.retrieval_id_sha256,
            retrieval_proof_sha256: receipt.retrieval_proof_sha256,
            verified_payload_sha256: receipt.verified_payload_sha256,
            verified_trust_checkpoint_sha256:
                receipt.verified_trust_checkpoint_sha256,
            active_effect_owner: self.clone(),
            provider_send_permit: Some(provider_send_permit),
            secondary_effect_permit: Some(gmail_child_permit),
        })
    }

    pub(crate) fn response_hook(&self) -> ShadowResponseHook {
        ShadowResponseHook {
            inner: Arc::clone(&self.inner),
        }
    }

    fn enqueue_request_evaluation(&self) -> Result<(), String> {
        let estimated_bytes = shadow_job_bytes_with_terminal_retention(self
            .inner
            .facts
            .estimated_bytes()
            .saturating_add(self.inner.request_binding_sha256.len()));
        if estimated_bytes > SHADOW_MAX_JOB_BYTES {
            if !self.inner.ledger.record(
                self.inner.generation.generation_id(),
                ShadowAccountingEvent::minimal(
                    self.inner.ingress_sequence,
                    self.inner.request_binding_sha256.clone(),
                    self.inner.request_commitment_sha256.clone(),
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::AccountingOversize,
                    ),
                ),
                false,
            ) {
                self.inner.ledger.mark_hard_unready();
            }
            return Err("shadow request job exceeds bound".to_string());
        }
        let Some(reservation) = QueueByteReservation::reserve(
            &self.inner.queued_bytes,
            &self.inner.queue_poisoned,
            &self.inner.ledger,
            self.inner.generation.generation_id(),
            self.inner.ingress_sequence,
            &self.inner.request_binding_sha256,
            &self.inner.request_commitment_sha256,
            estimated_bytes,
        ) else {
            if !self.inner.ledger.record(
                self.inner.generation.generation_id(),
                ShadowAccountingEvent::minimal(
                    self.inner.ingress_sequence,
                    self.inner.request_binding_sha256.clone(),
                    self.inner.request_commitment_sha256.clone(),
                    if self.inner.queue_poisoned.load(Ordering::Acquire) {
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::AccountingLedgerContention,
                        )
                    } else {
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::AccountingQueueFull,
                        )
                    },
                ),
                false,
            ) {
                self.inner.ledger.mark_hard_unready();
            }
            return Err("shadow request queue has no capacity".to_string());
        };
        let work = ShadowWork::Request(ShadowRequestJob {
            lifecycle: Arc::clone(&self.inner),
            _reservation: reservation,
        });
        match self.inner.sender.try_send(work) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                if !self.inner.ledger.record(
                    self.inner.generation.generation_id(),
                    ShadowAccountingEvent::minimal(
                        self.inner.ingress_sequence,
                        self.inner.request_binding_sha256.clone(),
                        self.inner.request_commitment_sha256.clone(),
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::AccountingQueueFull,
                        ),
                    ),
                    false,
                ) {
                    self.inner.ledger.mark_hard_unready();
                }
                Err("shadow request queue is full".to_string())
            }
            Err(TrySendError::Disconnected(_)) => {
                if !self.inner.ledger.record(
                    self.inner.generation.generation_id(),
                    ShadowAccountingEvent::minimal(
                        self.inner.ingress_sequence,
                        self.inner.request_binding_sha256.clone(),
                        self.inner.request_commitment_sha256.clone(),
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::AccountingQueueDisconnected,
                        ),
                    ),
                    false,
                ) {
                    self.inner.ledger.mark_hard_unready();
                }
                Err("shadow request worker is unavailable".to_string())
            }
        }
    }
}

impl Drop for ShadowRequestHandle {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1
            && !self.inner.finalization_consumed.load(Ordering::Acquire)
        {
            if !self.inner.ledger.record(
                self.inner.generation.generation_id(),
                ShadowAccountingEvent::minimal(
                    self.inner.ingress_sequence,
                    self.inner.request_binding_sha256.clone(),
                    self.inner.request_commitment_sha256.clone(),
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::CandidateEvaluationError,
                    ),
                ),
                false,
            ) {
                self.inner.ledger.mark_hard_unready();
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct ShadowResponseHook {
    inner: Arc<ShadowRequestLifecycle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TransportResponseFraming {
    NoBody,
    ContentLength,
    Chunked,
    CloseDelimited,
}

pub(crate) struct TransportCaptureReceiptWire {
    runtime_boot_sha256: String,
    generation_id: String,
    request_binding_sha256: String,
    peer_identity_sha256: String,
    raw_response_head: Arc<[u8]>,
    raw_response_body: Arc<[u8]>,
    raw_response_head_sha256: String,
    raw_response_body_sha256: String,
    framing: TransportResponseFraming,
    complete: bool,
    receipt_payload_sha256: String,
    signer_key_sha256: String,
    runtime_attestation_sha256: String,
    signature: Arc<[u8]>,
}

impl TransportCaptureReceiptWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_transport_adapter(
        runtime_boot_sha256: String,
        generation_id: String,
        request_binding_sha256: String,
        peer_identity_sha256: String,
        raw_response_head: Arc<[u8]>,
        raw_response_body: Arc<[u8]>,
        raw_response_head_sha256: String,
        raw_response_body_sha256: String,
        framing: TransportResponseFraming,
        complete: bool,
        receipt_payload_sha256: String,
        signer_key_sha256: String,
        runtime_attestation_sha256: String,
        signature: Arc<[u8]>,
    ) -> Self {
        Self {
            runtime_boot_sha256,
            generation_id,
            request_binding_sha256,
            peer_identity_sha256,
            raw_response_head,
            raw_response_body,
            raw_response_head_sha256,
            raw_response_body_sha256,
            framing,
            complete,
            receipt_payload_sha256,
            signer_key_sha256,
            runtime_attestation_sha256,
            signature,
        }
    }

    pub(crate) fn receipt_payload_sha256(&self) -> &str {
        &self.receipt_payload_sha256
    }

    pub(crate) fn signer_key_sha256(&self) -> &str {
        &self.signer_key_sha256
    }

    pub(crate) fn runtime_attestation_sha256(&self) -> &str {
        &self.runtime_attestation_sha256
    }

    pub(crate) fn signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

pub(crate) trait RawResponseCaptureAuthority {
    fn verify_transport_receipt(
        &self,
        receipt: &TransportCaptureReceiptWire,
        expected_runtime_boot_sha256: &str,
        expected_generation_id: &str,
        expected_request_binding_sha256: &str,
        expected_peer_identity_sha256: &str,
        expected_payload_sha256: &str,
        expected_receipt_sha256: &str,
    ) -> Result<(), String>;
}

pub(crate) struct AuthenticatedTransportCaptureReceipt {
    runtime_boot_sha256: String,
    generation_id: String,
    request_binding_sha256: String,
    peer_identity_sha256: String,
    raw_response_head: Arc<[u8]>,
    raw_response_body: Arc<[u8]>,
    framing: TransportResponseFraming,
    receipt_sha256: String,
    runtime_attestation_sha256: String,
}

impl AuthenticatedTransportCaptureReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate(
        wire: TransportCaptureReceiptWire,
        expected_runtime_boot_sha256: &str,
        expected_generation_id: &str,
        expected_request_binding_sha256: &str,
        expected_peer_identity_sha256: &str,
        authority: &dyn RawResponseCaptureAuthority,
    ) -> Result<Self, String> {
        let expected_payload_sha256 = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowTransportCapturePayload/v1",
            "runtimeBootSha256":wire.runtime_boot_sha256.as_str(),
            "generationId":wire.generation_id.as_str(),
            "requestBindingSha256":wire.request_binding_sha256.as_str(),
            "peerIdentitySha256":wire.peer_identity_sha256.as_str(),
            "rawResponseHeadSha256":wire.raw_response_head_sha256.as_str(),
            "rawResponseHeadBytes":wire.raw_response_head.len(),
            "rawResponseBodySha256":wire.raw_response_body_sha256.as_str(),
            "rawResponseBodyBytes":wire.raw_response_body.len(),
            "framing":wire.framing,
            "complete":wire.complete,
            "signerKeySha256":wire.signer_key_sha256.as_str(),
            "runtimeAttestationSha256":
                wire.runtime_attestation_sha256.as_str(),
        }));
        let expected_receipt_sha256 = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowTransportCaptureReceipt/v1",
            "payloadSha256":expected_payload_sha256.as_str(),
            "signerKeySha256":wire.signer_key_sha256.as_str(),
            "runtimeAttestationSha256":
                wire.runtime_attestation_sha256.as_str(),
            "signatureSha256":sha256_prefixed(wire.signature.as_ref()),
        }));
        if wire.runtime_boot_sha256 != expected_runtime_boot_sha256
            || wire.generation_id != expected_generation_id
            || wire.request_binding_sha256
                != expected_request_binding_sha256
            || wire.peer_identity_sha256 != expected_peer_identity_sha256
            || !wire.complete
            || wire.raw_response_head.is_empty()
            || wire.raw_response_head.len() > SHADOW_MAX_RESPONSE_HEADER_BYTES
            || wire.raw_response_body.len() > SHADOW_MAX_RESPONSE_BODY_BYTES
            || wire.raw_response_head_sha256
                != sha256_prefixed(&wire.raw_response_head)
            || wire.raw_response_body_sha256
                != sha256_prefixed(&wire.raw_response_body)
            || wire.receipt_payload_sha256 != expected_payload_sha256
            || !wire.signer_key_sha256.starts_with("sha256:")
            || !wire.runtime_attestation_sha256.starts_with("sha256:")
            || wire.signature.is_empty()
        {
            return Err(
                "authenticated transport capture receipt is invalid".to_string(),
            );
        }
        authority.verify_transport_receipt(
            &wire,
            expected_runtime_boot_sha256,
            expected_generation_id,
            expected_request_binding_sha256,
            expected_peer_identity_sha256,
            &expected_payload_sha256,
            &expected_receipt_sha256,
        )?;
        Ok(Self {
            runtime_boot_sha256: wire.runtime_boot_sha256,
            generation_id: wire.generation_id,
            request_binding_sha256: wire.request_binding_sha256,
            peer_identity_sha256: wire.peer_identity_sha256,
            raw_response_head: wire.raw_response_head,
            raw_response_body: wire.raw_response_body,
            framing: wire.framing,
            receipt_sha256: expected_receipt_sha256,
            runtime_attestation_sha256: wire.runtime_attestation_sha256,
        })
    }
}

pub(crate) struct VerifiedRawResponseCapture {
    status: u16,
    parsed_headers: HeaderMap,
    raw_response_head: Arc<[u8]>,
    raw_response_body: Arc<[u8]>,
    physical_header_count: usize,
    body: Arc<[u8]>,
    gmail_metadata_evidence: Option<ActiveGmailMetadataEvidence>,
    transport_capture_receipt_sha256: String,
    runtime_attestation_sha256: String,
    peer_identity_sha256: String,
    framing: TransportResponseFraming,
}

pub(crate) struct ActiveTerminalEffectSet {
    terminal_evidence: Vec<ActiveEffectTerminalEvidence>,
}

impl ActiveTerminalEffectSet {
    pub(crate) fn from_active_executor(
        terminal_evidence: Vec<ActiveEffectTerminalEvidence>,
    ) -> Result<Self, String> {
        if terminal_evidence.is_empty()
            || terminal_evidence.windows(2).any(|pair| {
                pair[0].requirement() >= pair[1].requirement()
            })
        {
            return Err("active terminal effect set is not canonical".to_string());
        }
        Ok(Self { terminal_evidence })
    }

    fn validate_exact_and_commit(
        &self,
        requirements: &ActiveEffectRequirements,
        expected_response_validation_sha256: Option<&str>,
        expected_terminal_response_sha256: &str,
        expected_gmail_metadata_sha256: Option<&str>,
    ) -> Result<Vec<String>, String> {
        let observed = self
            .terminal_evidence
            .iter()
            .map(ActiveEffectTerminalEvidence::requirement)
            .collect::<Vec<_>>();
        if observed != requirements.as_slice()
        {
            return Err("active terminal effect coverage is incomplete".to_string());
        }
        for required_terminal in [
            ActiveEffectRequirement::TrustFreshness,
            ActiveEffectRequirement::FinalRequest,
            ActiveEffectRequirement::TerminalResponse,
        ] {
            if self.terminal_evidence.iter().any(|evidence| {
                evidence.requirement() == required_terminal
                    && evidence.terminal_state()
                        == ActiveEffectTerminalState::NotReached
            }) {
                return Err(
                    "mandatory active terminal evidence was not reached"
                        .to_string(),
                );
            }
        }
        let expected = [
            (
                ActiveEffectRequirement::ResponseValidation,
                expected_response_validation_sha256,
            ),
            (
                ActiveEffectRequirement::TerminalResponse,
                Some(expected_terminal_response_sha256),
            ),
            (
                ActiveEffectRequirement::GmailMetadataFanout,
                expected_gmail_metadata_sha256,
            ),
        ];
        for (requirement, digest) in expected {
            if requirements.requires(requirement) {
                let evidence = self
                    .terminal_evidence
                    .iter()
                    .find(|evidence| evidence.requirement() == requirement)
                    .ok_or_else(|| {
                        "active terminal effect evidence is missing".to_string()
                    })?;
                if evidence.terminal_state()
                    == ActiveEffectTerminalState::Completed
                {
                    let digest = digest.ok_or_else(|| {
                        "completed active terminal effect lacks authoritative result"
                            .to_string()
                    })?;
                    if evidence.result_sha256().as_str() != digest {
                        return Err(
                            "active terminal effect result binding mismatch"
                                .to_string(),
                        );
                    }
                } else if digest.is_some() {
                    return Err(
                        "non-completed active terminal effect carried a completion result"
                            .to_string(),
                    );
                }
            }
        }
        let commitments = self
            .terminal_evidence
            .iter()
            .map(|evidence| {
                digest_json_ensure_ascii(&json!({
                    "domain":"serverware.policyShadowTypedTerminalEffect/v1",
                    "requirement":evidence.requirement(),
                    "terminalState":evidence.terminal_state(),
                    "resultSha256":evidence.result_sha256().as_str(),
                }))
            })
            .collect();
        Ok(commitments)
    }

    fn require_completed(
        &self,
        requirement: ActiveEffectRequirement,
    ) -> Result<(), String> {
        if self.terminal_evidence.iter().any(|evidence| {
            evidence.requirement() == requirement
                && evidence.terminal_state()
                    == ActiveEffectTerminalState::Completed
        }) {
            Ok(())
        } else {
            Err("required active effect did not complete".to_string())
        }
    }

    fn require_all_completed(&self) -> Result<(), String> {
        if self.terminal_evidence.iter().all(|evidence| {
            evidence.terminal_state() == ActiveEffectTerminalState::Completed
        }) {
            Ok(())
        } else {
            Err(
                "allowed active outcome has non-completed required effects"
                    .to_string(),
            )
        }
    }
}

impl VerifiedRawResponseCapture {
    pub(crate) fn from_authenticated_transport_receipt(
        receipt: AuthenticatedTransportCaptureReceipt,
        expected_runtime_boot_sha256: &str,
        expected_generation_id: &str,
        expected_request_binding_sha256: &str,
        expected_peer_identity_sha256: &str,
        gmail_metadata_evidence: Option<ActiveGmailMetadataEvidence>,
    ) -> Result<Self, String> {
        if receipt.runtime_boot_sha256 != expected_runtime_boot_sha256
            || receipt.generation_id != expected_generation_id
            || receipt.request_binding_sha256
                != expected_request_binding_sha256
            || receipt.peer_identity_sha256 != expected_peer_identity_sha256
        {
            return Err(
                "authenticated transport capture receipt binding mismatch"
                    .to_string(),
            );
        }
        let (status, parsed_headers, physical_header_count) =
            parse_raw_response_head(&receipt.raw_response_head)?;
        let body = reconstruct_raw_response_body(
            status,
            &parsed_headers,
            &receipt.raw_response_body,
            receipt.framing,
        )?;
        if gmail_metadata_evidence.as_ref().is_some_and(|evidence| {
            evidence.generation_id != expected_generation_id
                || evidence.request_binding_sha256
                    != expected_request_binding_sha256
                || evidence.source_list_response_sha256
                    != sha256_prefixed(&body)
        }) {
            return Err(
                "active Gmail metadata evidence binding mismatch".to_string(),
            );
        }
        Ok(Self {
            status,
            parsed_headers,
            raw_response_head: receipt.raw_response_head,
            raw_response_body: receipt.raw_response_body,
            physical_header_count,
            body,
            gmail_metadata_evidence,
            transport_capture_receipt_sha256: receipt.receipt_sha256,
            runtime_attestation_sha256:
                receipt.runtime_attestation_sha256,
            peer_identity_sha256: receipt.peer_identity_sha256,
            framing: receipt.framing,
        })
    }
}

fn parse_raw_response_head(
    raw: &[u8],
) -> Result<(u16, HeaderMap, usize), String> {
    if raw.len() > SHADOW_MAX_RESPONSE_HEADER_BYTES
        || !raw.ends_with(b"\r\n\r\n")
    {
        return Err("raw response head is incomplete".to_string());
    }
    let mut lines = raw[..raw.len() - 2].split(|byte| *byte == b'\n');
    let status_line = lines
        .next()
        .ok_or_else(|| "raw response status line is missing".to_string())?;
    let status_line = status_line
        .strip_suffix(b"\r")
        .ok_or_else(|| "raw response status line is not CRLF terminated".to_string())?;
    let status_text = std::str::from_utf8(status_line)
        .map_err(|_| "raw response status line is not ASCII".to_string())?;
    let mut status_parts = status_text.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .ok_or_else(|| "raw response status is missing".to_string())?
        .parse::<u16>()
        .map_err(|_| "raw response status is invalid".to_string())?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !(200..=599).contains(&status)
    {
        return Err("raw response protocol/status is invalid".to_string());
    }
    let mut headers = HeaderMap::new();
    let mut physical_header_count = 0_usize;
    for line in lines {
        let line = line
            .strip_suffix(b"\r")
            .ok_or_else(|| "raw response header is not CRLF terminated".to_string())?;
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err("folded raw response headers are forbidden".to_string());
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| "raw response header separator is missing".to_string())?;
        let name = HeaderName::from_bytes(&line[..separator])
            .map_err(|_| "raw response header name is invalid".to_string())?;
        let mut value = &line[separator + 1..];
        while value.first().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            value = &value[1..];
        }
        while value.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            value = &value[..value.len() - 1];
        }
        let value = HeaderValue::from_bytes(value)
            .map_err(|_| "raw response header value is invalid".to_string())?;
        headers.append(name, value);
        physical_header_count = physical_header_count
            .checked_add(1)
            .ok_or_else(|| "raw response header count overflow".to_string())?;
        if physical_header_count > SHADOW_MAX_RESPONSE_HEADERS {
            return Err("raw response header count exceeds bound".to_string());
        }
    }
    Ok((status, headers, physical_header_count))
}

fn reconstruct_raw_response_body(
    status: u16,
    headers: &HeaderMap,
    raw_body: &Arc<[u8]>,
    declared_framing: TransportResponseFraming,
) -> Result<Arc<[u8]>, String> {
    let body_forbidden = (100..200).contains(&status)
        || matches!(status, 204 | 304);
    let transfer_encoding = headers
        .get_all("transfer-encoding")
        .iter()
        .map(|value| value.to_str().ok())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "transfer encoding is not ASCII".to_string())?;
    let content_lengths = headers
        .get_all("content-length")
        .iter()
        .map(|value| value.to_str().ok()?.trim().parse::<usize>().ok())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "content length is invalid".to_string())?;
    let derived_framing = if body_forbidden {
        TransportResponseFraming::NoBody
    } else if !transfer_encoding.is_empty() {
        if transfer_encoding.len() != 1
            || !transfer_encoding[0].eq_ignore_ascii_case("chunked")
            || !content_lengths.is_empty()
        {
            return Err("ambiguous response framing is forbidden".to_string());
        }
        TransportResponseFraming::Chunked
    } else if !content_lengths.is_empty() {
        if content_lengths
            .iter()
            .any(|length| *length != content_lengths[0])
        {
            return Err("conflicting content lengths are forbidden".to_string());
        }
        TransportResponseFraming::ContentLength
    } else {
        TransportResponseFraming::CloseDelimited
    };
    if derived_framing != declared_framing {
        return Err("transport receipt framing mismatch".to_string());
    }
    match derived_framing {
        TransportResponseFraming::NoBody => {
            if !raw_body.is_empty() {
                return Err("body-forbidden response carried bytes".to_string());
            }
            Ok(Arc::from([]))
        }
        TransportResponseFraming::ContentLength => {
            if raw_body.len() != content_lengths[0] {
                return Err("content-length response is incomplete".to_string());
            }
            Ok(Arc::clone(raw_body))
        }
        TransportResponseFraming::Chunked => decode_complete_chunked_body(raw_body),
        TransportResponseFraming::CloseDelimited => Ok(Arc::clone(raw_body)),
    }
}

fn decode_complete_chunked_body(raw: &[u8]) -> Result<Arc<[u8]>, String> {
    let mut cursor = 0_usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = raw[cursor..]
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .map(|offset| cursor + offset)
            .ok_or_else(|| "chunk size line is incomplete".to_string())?;
        let size_field = raw[cursor..line_end]
            .split(|byte| *byte == b';')
            .next()
            .ok_or_else(|| "chunk size is missing".to_string())?;
        let size_text = std::str::from_utf8(size_field)
            .map_err(|_| "chunk size is not ASCII".to_string())?;
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| "chunk size is invalid".to_string())?;
        cursor = line_end
            .checked_add(2)
            .ok_or_else(|| "chunk cursor overflow".to_string())?;
        if size == 0 {
            if raw.get(cursor..) != Some(b"\r\n") {
                return Err(
                    "chunk trailers are unsupported for exact capture".to_string(),
                );
            }
            break;
        }
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| "chunk body overflow".to_string())?;
        if raw.get(end..end.saturating_add(2)) != Some(b"\r\n") {
            return Err("chunk body is incomplete".to_string());
        }
        decoded.extend_from_slice(
            raw.get(cursor..end)
                .ok_or_else(|| "chunk body is truncated".to_string())?,
        );
        if decoded.len() > SHADOW_MAX_RESPONSE_BODY_BYTES {
            return Err("decoded response exceeds bound".to_string());
        }
        cursor = end + 2;
    }
    Ok(Arc::from(decoded))
}

#[derive(Clone)]
pub(crate) struct ActiveGmailMetadataEvidence {
    generation_id: String,
    request_binding_sha256: String,
    route_sha256: String,
    source_list_response_sha256: String,
    hydrated_response_body: Arc<[u8]>,
    active_fanout_proof_sha256: String,
    ordered_child_evidence_root_sha256: String,
    hydrated_message_count: u64,
}

impl ActiveGmailMetadataEvidence {
    pub(crate) fn from_active_executor(
        generation_id: String,
        request_binding_sha256: String,
        route_sha256: String,
        source_list_response_sha256: String,
        hydrated_response_body: Arc<[u8]>,
        active_fanout_proof_sha256: String,
        ordered_child_evidence_root_sha256: String,
        hydrated_message_count: u64,
    ) -> Result<Self, String> {
        if hydrated_response_body.len() > SHADOW_MAX_RESPONSE_BODY_BYTES
            || !generation_id.starts_with("sha256:")
            || !request_binding_sha256.starts_with("sha256:")
            || !route_sha256.starts_with("sha256:")
            || !source_list_response_sha256.starts_with("sha256:")
            || !active_fanout_proof_sha256.starts_with("sha256:")
            || !ordered_child_evidence_root_sha256.starts_with("sha256:")
        {
            return Err("active Gmail metadata evidence is invalid".to_string());
        }
        Ok(Self {
            generation_id,
            request_binding_sha256,
            route_sha256,
            source_list_response_sha256,
            hydrated_response_body,
            active_fanout_proof_sha256,
            ordered_child_evidence_root_sha256,
            hydrated_message_count,
        })
    }

    fn commitment(&self) -> String {
        digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowActiveGmailMetadataEvidence/v1",
            "generationId":self.generation_id.as_str(),
            "requestBindingSha256":self.request_binding_sha256.as_str(),
            "routeSha256":self.route_sha256.as_str(),
            "sourceListResponseSha256":
                self.source_list_response_sha256.as_str(),
            "hydratedResponseBodySha256":sha256_prefixed(&self.hydrated_response_body),
            "hydratedResponseBodyBytes":self.hydrated_response_body.len(),
            "activeFanoutProofSha256":self.active_fanout_proof_sha256.as_str(),
            "orderedChildEvidenceRootSha256":self.ordered_child_evidence_root_sha256.as_str(),
            "hydratedMessageCount":self.hydrated_message_count,
        }))
    }
}

pub(crate) struct ShadowResponseAttempt {
    hook: ShadowResponseHook,
    status: u16,
    parsed_headers: HeaderMap,
    completed: bool,
}

impl ShadowResponseHook {
    pub(crate) fn begin(
        &self,
        snapshot: &Arc<Snapshot>,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<ShadowResponseAttempt, String> {
        if !self.inner.generation_is_current_for(snapshot) {
            return Err("active snapshot changed before response capture".to_string());
        }
        Ok(ShadowResponseAttempt {
            hook: self.clone(),
            status: status.as_u16(),
            parsed_headers: headers.clone(),
            completed: false,
        })
    }

    pub(crate) fn record_unavailable(
        &self,
        reason: PolicyShadowTerminalReason,
    ) -> bool {
        self.record_unavailable_detail(reason, None)
    }

    fn record_unavailable_detail(
        &self,
        reason: PolicyShadowTerminalReason,
        returned_response: Option<&[u8]>,
    ) -> bool {
        if self.inner.response_terminal_recorded.load(Ordering::Acquire) {
            return true;
        }
        let (pending_active, final_active) =
            match self.inner.state.try_lock() {
                Ok(state) => (
                    state.pending_active.clone(),
                    state.final_active.as_ref().map(|record| record.decision.clone()),
                ),
                Err(_) => {
                    ShadowRequestHandle {
                        inner: Arc::clone(&self.inner),
                    }
                    .record_failure(
                        PolicyShadowTerminalReason::TerminalStateContention,
                    );
                    return false;
                }
            };
        if pending_active
            .as_ref()
            .is_none_or(|active| !active.dispatch_authorized)
            && final_active
                .as_ref()
                .is_none_or(|active| !active.dispatch_authorized)
        {
            return false;
        }
        let mut record = ShadowAccountingEvent::minimal(
            self.inner.ingress_sequence,
            self.inner.request_binding_sha256.clone(),
            self.inner.request_commitment_sha256.clone(),
            ShadowRuntimeEvent::Failure(reason),
        );
        record.active_disposition = final_active
            .as_ref()
            .map(|active| active.final_outcome.clone());
        if record.active_disposition.is_none() {
            record.active_disposition = pending_active
                .as_ref()
                .map(|active| active.final_outcome.clone());
        }
        record.response_facts_sha256 = Some(digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowUnavailableResponse/v1",
            "terminalReason":reason,
            "returnedResponseSha256":returned_response.map(sha256_prefixed),
            "returnedResponseBytes":returned_response.map(|response| response.len()),
        })));
        if !self.inner
            .ledger
            .record(self.inner.generation.generation_id(), record, false)
        {
            return false;
        }
        if self
            .inner
            .response_terminal_recorded
            .compare_exchange(
                false,
                true,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            ShadowRequestHandle {
                inner: Arc::clone(&self.inner),
            }
            .record_failure(
                PolicyShadowTerminalReason::AccountingLedgerContention,
            );
            return false;
        }
        true
    }

    fn record_unavailable_with_terminal(
        &self,
        returned_response: &[u8],
        reason: PolicyShadowTerminalReason,
    ) {
        if self.record_unavailable_detail(reason, Some(returned_response)) {
            self.mark_terminal_unavailable();
        } else {
            self.inner.ledger.mark_hard_unready();
        }
    }

    fn mark_terminal_unavailable(&self) {
        match self.inner.state.try_lock() {
            Ok(mut state) => state.response_finished = true,
            Err(_) => {
                ShadowRequestHandle {
                    inner: Arc::clone(&self.inner),
                }
                .record_failure(
                    PolicyShadowTerminalReason::TerminalStateContention,
                );
            }
        }
    }
}

impl ShadowResponseAttempt {
    pub(crate) fn finish_exact(
        mut self,
        snapshot: &Arc<Snapshot>,
        capture: VerifiedRawResponseCapture,
        active_validation: &Value,
        parsed_upstream_body: &[u8],
        returned_response: &[u8],
        terminal_effects: ActiveTerminalEffectSet,
    ) {
        let result = self.try_finish_exact(
            snapshot,
            capture,
            active_validation,
            parsed_upstream_body,
            returned_response,
            terminal_effects,
        );
        if result.is_err() {
            if !self.hook.record_unavailable(
                PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
            ) {
                self.hook.inner.ledger.mark_hard_unready();
            }
        }
        self.completed = true;
    }

    fn try_finish_exact(
        &self,
        snapshot: &Arc<Snapshot>,
        capture: VerifiedRawResponseCapture,
        active_validation: &Value,
        parsed_upstream_body: &[u8],
        returned_response: &[u8],
        terminal_effects: ActiveTerminalEffectSet,
    ) -> Result<(), String> {
        if !self.hook.inner.generation_is_current_for(snapshot) {
            return Err("active snapshot changed before exact response finalization".to_string());
        }
        if capture.status != self.status
            || capture.parsed_headers != self.parsed_headers
            || capture.body.as_ref() != parsed_upstream_body
        {
            return Err("raw transport capture does not match parsed response".to_string());
        }
        let captured_at_epoch_ms = checked_epoch_ms(now_epoch_ms())
            .map_err(|_| "shadow response timestamp is outside the supported range".to_string())?;
        let response_facts_sha256 = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowExactResponseFacts/v1",
            "capturedAtEpochMs":captured_at_epoch_ms,
            "status":self.status,
            "physicalHeaderCount":capture.physical_header_count,
            "physicalHeadersSha256":sha256_prefixed(&capture.raw_response_head),
            "rawResponseHeadBytes":capture.raw_response_head.len(),
            "rawResponseBodySha256":sha256_prefixed(&capture.raw_response_body),
            "rawResponseBodyBytes":capture.raw_response_body.len(),
            "bodySha256":sha256_prefixed(&capture.body),
            "bodyLength":capture.body.len(),
            "transportCaptureReceiptSha256":capture.transport_capture_receipt_sha256,
            "runtimeAttestationSha256":capture.runtime_attestation_sha256,
            "peerIdentitySha256":capture.peer_identity_sha256,
            "framing":capture.framing,
            "mode":"bounded-exact",
        }));
        let active_response_validation_sha256 = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowBoundActiveResponseValidation/v1",
            "activePolicySnapshotSha256":self.hook.inner.generation.identity.active_snapshot_sha256.as_str(),
            "responseObligationRootSha256":self.hook.inner.generation.identity.response_obligation_root_sha256.as_str(),
            "responseFactsSha256":response_facts_sha256.as_str(),
            "activeValidationSha256":digest_json_ensure_ascii(active_validation),
        }));
        let gmail_metadata_evidence_sha256 = capture
            .gmail_metadata_evidence
            .as_ref()
            .map(ActiveGmailMetadataEvidence::commitment);
        let pending = self
            .hook
            .inner
            .state
            .try_lock()
            .map_err(|_| "shadow lifecycle mutex poisoned".to_string())?
            .pending_active
            .clone()
            .ok_or("active dispatch barrier evidence is unavailable")?;
        let terminal_response_sha256 = sha256_prefixed(returned_response);
        let terminal_effect_commitments = terminal_effects.validate_exact_and_commit(
            &pending.effect_requirements,
            Some(&active_response_validation_sha256),
            &terminal_response_sha256,
            gmail_metadata_evidence_sha256.as_deref(),
        )?;
        terminal_effects
            .require_completed(ActiveEffectRequirement::DispatchTerminal)?;
        if pending.effect_requirements.response_validation() {
            terminal_effects.require_completed(
                ActiveEffectRequirement::ResponseValidation,
            )?;
        }
        if pending.effect_requirements.gmail_metadata_fanout() {
            terminal_effects.require_completed(
                ActiveEffectRequirement::GmailMetadataFanout,
            )?;
        }
        let returned_http_status = parse_buffered_response(returned_response)
            .map(|parsed| parsed.status)
            .map_err(|_| "terminal returned response is not exact buffered HTTP".to_string())?;
        let terminal_outcome = match active_validation
            .get("outcome")
            .and_then(Value::as_str)
        {
            Some("released") | Some("accepted") => "allow",
            Some("blocked") | Some("rejected") => "deny",
            _ => "error",
        };
        ShadowRequestHandle {
            inner: Arc::clone(&self.hook.inner),
        }
        .finalize_terminal(
            snapshot,
            pending,
            terminal_outcome,
            returned_http_status,
            terminal_response_sha256,
            Some(response_facts_sha256.clone()),
            Some(active_response_validation_sha256.clone()),
            gmail_metadata_evidence_sha256,
            terminal_effect_commitments,
        )?;
        let estimated_bytes = shadow_job_bytes_with_terminal_retention(capture
            .body
            .len()
            .saturating_add(capture.raw_response_head.len())
            .saturating_add(capture.raw_response_body.len()));
        if estimated_bytes > SHADOW_MAX_JOB_BYTES {
            return Err("shadow response job exceeds bound".to_string());
        }
        let Some(reservation) = QueueByteReservation::reserve(
            &self.hook.inner.queued_bytes,
            &self.hook.inner.queue_poisoned,
            &self.hook.inner.ledger,
            self.hook.inner.generation.generation_id(),
            self.hook.inner.ingress_sequence,
            &self.hook.inner.request_binding_sha256,
            &self.hook.inner.request_commitment_sha256,
            estimated_bytes,
        ) else {
            return Err("shadow response queue has no capacity".to_string());
        };
        let enqueued_response_facts_sha256 =
            response_facts_sha256.clone();
        let enqueued_active_response_validation_sha256 =
            active_response_validation_sha256.clone();
        let enqueue_gate = Arc::new((Mutex::new(None), Condvar::new()));
        let work = ShadowWork::Response(ShadowResponseJob {
            lifecycle: Arc::clone(&self.hook.inner),
            status: self.status,
            headers: capture.parsed_headers,
            body: capture.body,
            physical_headers_sha256: sha256_prefixed(&capture.raw_response_head),
            gmail_metadata_evidence: capture.gmail_metadata_evidence,
            captured_at_epoch_ms,
            response_facts_sha256,
            active_response_validation_sha256,
            enqueue_gate: Arc::clone(&enqueue_gate),
            comparison_terminal_appended: false,
            _reservation: reservation,
        });
        match self.hook.inner.sender.try_send(work) {
            Ok(()) => {
                let mut record = ShadowAccountingEvent::minimal(
                    self.hook.inner.ingress_sequence,
                    self.hook.inner.request_binding_sha256.clone(),
                    self.hook.inner.request_commitment_sha256.clone(),
                    ShadowRuntimeEvent::ResponseCaptureEnqueued,
                );
                record.response_facts_sha256 =
                    Some(enqueued_response_facts_sha256);
                record.active_response_validation_sha256 =
                    Some(enqueued_active_response_validation_sha256);
                if !self.hook.inner.ledger.record(
                    self.hook.inner.generation.generation_id(),
                    record,
                    false,
                ) {
                    if let Ok(mut released) = enqueue_gate.0.try_lock() {
                        *released = Some(false);
                        enqueue_gate.1.notify_one();
                    }
                    return Err(
                        "response capture enqueue evidence was not durably appended"
                            .to_string(),
                    );
                }
                let mut released = enqueue_gate.0.try_lock().map_err(|_| {
                    "response worker enqueue gate is busy".to_string()
                })?;
                *released = Some(true);
                enqueue_gate.1.notify_one();
                Ok(())
            }
            Err(TrySendError::Full(ShadowWork::Response(mut job))) => {
                job.comparison_terminal_appended =
                    self.hook.inner.ledger.record(
                        self.hook.inner.generation.generation_id(),
                        ShadowAccountingEvent::minimal(
                            self.hook.inner.ingress_sequence,
                            self.hook.inner.request_binding_sha256.clone(),
                            self.hook.inner.request_commitment_sha256.clone(),
                            ShadowRuntimeEvent::Failure(
                                PolicyShadowTerminalReason::ResponseQueueFull,
                            ),
                        ),
                        false,
                    );
                if !job.comparison_terminal_appended {
                    self.hook.inner.ledger.mark_hard_unready();
                }
                Err("response queue failure was durably accounted".to_string())
            }
            Err(TrySendError::Disconnected(ShadowWork::Response(mut job))) => {
                job.comparison_terminal_appended =
                    self.hook.inner.ledger.record(
                        self.hook.inner.generation.generation_id(),
                        ShadowAccountingEvent::minimal(
                            self.hook.inner.ingress_sequence,
                            self.hook.inner.request_binding_sha256.clone(),
                            self.hook.inner.request_commitment_sha256.clone(),
                            ShadowRuntimeEvent::Failure(
                                PolicyShadowTerminalReason::ResponseWorkerUnavailable,
                            ),
                        ),
                        false,
                    );
                if !job.comparison_terminal_appended {
                    self.hook.inner.ledger.mark_hard_unready();
                }
                Err(
                    "response worker failure was durably accounted"
                        .to_string(),
                )
            }
            Err(_) => Err(
                "response queue returned an impossible work variant"
                    .to_string(),
            ),
        }
    }

    pub(crate) fn finish_parsed_unavailable(
        mut self,
        snapshot: &Arc<Snapshot>,
        returned_response: &[u8],
        reason: PolicyShadowTerminalReason,
    ) {
        if (ShadowRequestHandle {
            inner: Arc::clone(&self.hook.inner),
        })
        .finalize_post_dispatch_response_observed(
            snapshot,
            returned_response,
            reason,
        )
        .is_err()
        {
            if !self.hook.record_unavailable_detail(
                PolicyShadowTerminalReason::PostDispatchFinalizationFailed,
                Some(returned_response),
            ) {
                self.hook.inner.ledger.mark_hard_unready();
            }
        }
        if !self.hook
            .record_unavailable_detail(reason, Some(returned_response))
        {
            self.hook.inner.ledger.mark_hard_unready();
        }
        self.completed = true;
    }

    pub(crate) fn finish_streaming_unavailable(mut self) {
        if self.hook.record_unavailable(
            PolicyShadowTerminalReason::StreamingResponseNotBoundedExact,
        ) {
            self.hook.mark_terminal_unavailable();
        } else {
            self.hook.inner.ledger.mark_hard_unready();
        }
        self.completed = true;
    }

    pub(crate) fn finish_unavailable(
        mut self,
        reason: PolicyShadowTerminalReason,
    ) {
        if self.hook.record_unavailable(reason) {
            self.hook.mark_terminal_unavailable();
        } else {
            self.hook.inner.ledger.mark_hard_unready();
        }
        self.completed = true;
    }
}

impl Drop for ShadowResponseAttempt {
    fn drop(&mut self) {
        if !self.completed {
            if self.hook
                .record_unavailable(
                    PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
                )
            {
                self.hook.mark_terminal_unavailable();
            } else {
                self.hook.inner.ledger.mark_hard_unready();
            }
        }
    }
}

impl Drop for ShadowResponseHook {
    fn drop(&mut self) {
        let dispatch_started = self
            .inner
            .state
            .try_lock()
            .is_ok_and(|state| state.pending_active.is_some());
        if dispatch_started
            && !self
                .inner
                .response_terminal_recorded
                .load(Ordering::Acquire)
        {
            if !self.record_unavailable(
                PolicyShadowTerminalReason::UpstreamResponseNotObserved,
            ) {
                self.inner.ledger.mark_hard_unready();
            }
        }
    }
}

struct ShadowRequestJob {
    lifecycle: Arc<ShadowRequestLifecycle>,
    _reservation: QueueByteReservation,
}

struct ShadowResponseJob {
    lifecycle: Arc<ShadowRequestLifecycle>,
    status: u16,
    headers: HeaderMap,
    body: Arc<[u8]>,
    physical_headers_sha256: String,
    gmail_metadata_evidence: Option<ActiveGmailMetadataEvidence>,
    captured_at_epoch_ms: u64,
    response_facts_sha256: String,
    active_response_validation_sha256: String,
    enqueue_gate: Arc<(Mutex<Option<bool>>, Condvar)>,
    comparison_terminal_appended: bool,
    _reservation: QueueByteReservation,
}

impl Drop for ShadowResponseJob {
    fn drop(&mut self) {
        if self.comparison_terminal_appended {
            return;
        }
        let appended = self.lifecycle.ledger.record(
            self.lifecycle.generation.generation_id(),
            ShadowAccountingEvent::minimal(
                self.lifecycle.ingress_sequence,
                self.lifecycle.request_binding_sha256.clone(),
                self.lifecycle.request_commitment_sha256.clone(),
                ShadowRuntimeEvent::Failure(
                    PolicyShadowTerminalReason::WorkerLost,
                ),
            ),
            false,
        );
        if !appended {
            self.lifecycle.ledger.mark_hard_unready();
        }
    }
}

enum ShadowWork {
    Request(ShadowRequestJob),
    Response(ShadowResponseJob),
    CompactionWake,
}

pub(crate) struct ShadowRuntime {
    generation:
        Arc<RwLock<Option<Arc<PublishedShadowGeneration>>>>,
    custody: Arc<OnceLock<Arc<dyn PolicyShadowCustodyRpcSupervisor>>>,
    prepared_generation:
        Mutex<Option<Arc<PublicationReconcileCell>>>,
    sender: SyncSender<ShadowWork>,
    queued_bytes: Arc<AtomicUsize>,
    queue_poisoned: Arc<AtomicBool>,
    ledger: Arc<AccountingLedger>,
    installation_in_progress: AtomicBool,
    publication_reconciliation_required: AtomicBool,
    authoritative_publication_revision: AtomicU64,
    activation_publication_gate:
        RwLock<Option<ShadowActivationPublicationGate>>,
    #[cfg(test)]
    inactive_for_forwarding_tests: bool,
}

struct ShadowInstallationGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for ShadowInstallationGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

impl ShadowRuntime {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(SHADOW_QUEUE_ITEMS);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queue_poisoned = Arc::new(AtomicBool::new(false));
        let custody = Arc::new(OnceLock::new());
        let ledger = Arc::new(AccountingLedger::new(Arc::clone(&custody)));
        let worker_ledger = Arc::clone(&ledger);
        let _worker = thread::Builder::new()
            .name("policy-shadow-evaluator".to_string())
            .spawn(move || shadow_worker(receiver, worker_ledger));
        Self {
            generation: Arc::new(RwLock::new(None)),
            custody,
            prepared_generation: Mutex::new(None),
            sender,
            queued_bytes,
            queue_poisoned,
            ledger,
            installation_in_progress: AtomicBool::new(false),
            publication_reconciliation_required: AtomicBool::new(true),
            authoritative_publication_revision: AtomicU64::new(0),
            activation_publication_gate: RwLock::new(None),
            #[cfg(test)]
            inactive_for_forwarding_tests: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_inactive_for_forwarding_tests() -> Self {
        let mut runtime = Self::new();
        runtime.inactive_for_forwarding_tests = true;
        runtime
    }

    pub(crate) fn quarantine_for_cleanup_failure(&self) {
        self.ledger.mark_hard_unready();
    }

    pub(crate) fn recover_exact_publication(
        &self,
        expected: &ShadowGenerationIdentity,
        active_snapshot: &Snapshot,
    ) -> Result<
        Option<(ShadowActivePublicationPermit, ShadowGenerationIdentity)>,
        String,
    > {
        let current = self
            .generation
            .try_read()
            .map_err(|_| "shadow generation lock is busy".to_string())?
            .as_ref()
            .cloned();
        let Some(current) = current else {
            return Ok(None);
        };
        if &current.generation.signed_identity != expected {
            return Err(
                "published shadow generation differs from the prepared handoff"
                    .to_string(),
            );
        }
        if !current.generation.matches_active_snapshot(active_snapshot)
            || !same_exact_snapshot_identity(
                &current.active_projection.snapshot,
                active_snapshot,
            )
        {
            return Err(
                "published shadow generation active snapshot changed"
                    .to_string(),
            );
        }
        let publication_receipt_sha256 = current
            .publication_receipt_sha256
            .get()
            .cloned()
            .ok_or_else(|| {
                "published shadow generation omits its final custody receipt"
                    .to_string()
            })?;
        Ok(Some((
            ShadowActivePublicationPermit {
                active_snapshot_epoch: active_snapshot.epoch,
                active_snapshot_sha256: active_snapshot.hash.clone(),
                active_policy_sequence: active_snapshot.policy_sequence,
                active_rollback_epoch: active_snapshot.rollback_epoch,
                active_trust_generation: active_snapshot.trust_generation,
                active_compiled_behavior_sha256:
                    active_snapshot.compiled_behavior_sha256.clone(),
                active_policy_signing_key_id:
                    active_snapshot.policy_signing_key_id.clone(),
                active_response_verifying_key: active_snapshot
                    .response_verifying_key
                    .as_ref()
                    .map(|key| key.to_bytes()),
                active_response_signing_key_id:
                    active_snapshot.response_signing_key_id.clone(),
                active_attested_response_context:
                    active_snapshot.attested_response_context.clone(),
                custody_receipt_sha256:
                    current.preparation_receipt_sha256.clone(),
                publication_revision: current.publication_revision,
                publication_receipt_sha256,
            },
            current.generation.signed_identity.clone(),
        )))
    }

    pub(crate) fn retain_activation_publication(
        &self,
        expected_generation: &ShadowGenerationIdentity,
        receipt: &VerifiedActivationPublicationReceipt,
    ) -> Result<(), String> {
        let current = self
            .generation
            .try_read()
            .map_err(|_| "shadow generation lock is busy".to_string())?
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                "activation publication has no installed shadow generation"
                    .to_string()
            })?;
        let wire = receipt.wire();
        let generation = &current.generation;
        if &generation.signed_identity != expected_generation
            || wire.assignment_sha256
                != *generation.signed_identity.assignment_sha256()
            || wire.assignment_payload_sha256
                != *generation
                    .signed_identity
                    .assignment_payload_sha256()
            || wire.assignment_revision
                != generation.signed_identity.assignment_revision()
            || wire.replaced_policy_sha256
                != generation.identity.active_snapshot_sha256
            || wire.replaced_policy_sequence
                != generation.identity.active_policy_sequence
            || wire.replaced_rollback_epoch
                != generation.identity.active_rollback_epoch
            || wire.published_policy_sha256
                != generation.identity.candidate_snapshot_sha256
            || wire.published_policy_sequence
                != generation.identity.candidate_policy_sequence
            || wire.published_rollback_epoch
                != generation.identity.candidate_rollback_epoch
            || wire.replaced_publication_revision
                != current.publication_revision
            || wire.published_publication_revision
                != current
                    .publication_revision
                    .checked_add(1)
                    .ok_or_else(|| {
                        "activation publication revision overflow"
                            .to_string()
                    })?
        {
            return Err(
                "activation receipt does not authorize the exact installed candidate"
                    .to_string(),
            );
        }
        let proposed = ShadowActivationPublicationGate {
            generation_id: generation
                .signed_identity
                .generation_id()
                .clone(),
            transaction_sha256: wire.transaction_sha256.clone(),
            signed_receipt_sha256:
                receipt.signed_receipt_sha256().clone(),
            published_publication_revision:
                wire.published_publication_revision,
            candidate: Arc::clone(
                &generation.candidate_serving_snapshot,
            ),
        };
        let mut gate = self
            .activation_publication_gate
            .try_write()
            .map_err(|_| {
                "shadow activation publication gate is busy".to_string()
            })?;
        if let Some(existing) = gate.as_ref() {
            if existing.generation_id == proposed.generation_id
                && existing.transaction_sha256
                    == proposed.transaction_sha256
                && existing.signed_receipt_sha256
                    == proposed.signed_receipt_sha256
                && existing.published_publication_revision
                    == proposed.published_publication_revision
            {
                return Ok(());
            }
            return Err(
                "a different activation receipt already occupies the serving gate"
                    .to_string(),
            );
        }
        *gate = Some(proposed);
        Ok(())
    }

    pub(crate) fn authorizes_new_active_snapshot(
        &self,
        snapshot: &Snapshot,
    ) -> bool {
        let Ok(generation) = self.generation.try_read() else {
            return false;
        };
        let Some(generation) = generation.as_ref() else {
            return false;
        };
        let Ok(gate) = self.activation_publication_gate.try_read() else {
            return false;
        };
        gate.as_ref().is_some_and(|gate| {
            gate.authorizes(&generation.generation, snapshot)
        })
    }

    pub(crate) fn install_verified_artifacts(
        &self,
        assignment: &VerifiedAssignment,
        load_receipt: &VerifiedLoadReceipt,
        active_snapshot: &Arc<Snapshot>,
        candidate_snapshot: &Arc<Snapshot>,
        custody: Arc<dyn PolicyShadowCustodyRpcSupervisor>,
    ) -> Result<
        (ShadowActivePublicationPermit, ShadowGenerationIdentity),
        String,
    > {
        let signed_identity =
            ShadowGenerationIdentity::derive(assignment, load_receipt)
                .map_err(shadow_error)?;
        let (starts_at_unix_nanos, ends_at_unix_nanos) =
            signed_identity.assignment_window_unix_nanos();
        let exact_epoch_ms = |value: i64, label: &str| {
            u64::try_from(value)
                .ok()
                .filter(|nanos| nanos % 1_000_000 == 0)
                .map(|nanos| nanos / 1_000_000)
                .ok_or_else(|| {
                    format!(
                        "{label} must be a non-negative exact epoch millisecond"
                    )
                })
        };
        let (request_commitment_key_id, request_commitment_key_epoch) =
            signed_identity.request_commitment_key_binding();
        let bounds = ShadowRuntimeGenerationBounds {
            generation_epoch: signed_identity.generation_epoch(),
            generation_tombstone_epoch:
                signed_identity.generation_tombstone_epoch(),
            assignment_sha256:
                signed_identity.assignment_sha256().clone(),
            assignment_payload_sha256:
                signed_identity.assignment_payload_sha256().clone(),
            assignment_revision: signed_identity.assignment_revision(),
            load_receipt_sha256:
                signed_identity.load_receipt_sha256().clone(),
            load_receipt_payload_sha256:
                signed_identity.load_receipt_payload_sha256().clone(),
            active_snapshot_sha256:
                signed_identity.active_policy_sha256().clone(),
            active_policy_sequence:
                signed_identity.active_policy_sequence(),
            active_rollback_epoch:
                signed_identity.active_rollback_epoch(),
            active_compiled_snapshot_sha256: signed_identity
                .active_compiled_snapshot_sha256()
                .clone(),
            candidate_snapshot_sha256:
                signed_identity.candidate_policy_sha256().clone(),
            candidate_policy_sequence:
                signed_identity.candidate_policy_sequence(),
            candidate_rollback_epoch:
                signed_identity.candidate_rollback_epoch(),
            candidate_compiled_snapshot_sha256: signed_identity
                .candidate_compiled_snapshot_sha256()
                .clone(),
            runtime_boot_sha256:
                signed_identity.runtime_boot_id_sha256().clone(),
            assignment_starts_at_epoch_ms: exact_epoch_ms(
                starts_at_unix_nanos,
                "assignment start",
            )?,
            assignment_ends_at_epoch_ms: exact_epoch_ms(
                ends_at_unix_nanos,
                "assignment end",
            )?,
            sampling_basis_points:
                signed_identity.sampling_basis_points(),
            request_commitment_key_id:
                request_commitment_key_id.clone(),
            request_commitment_key_epoch,
            request_facts_schema_sha256: signed_identity
                .request_facts_schema_sha256()
                .clone(),
            ingress_range_start_sequence:
                signed_identity.ingress_range_start_sequence(),
            ingress_range_predecessor_head_sha256: signed_identity
                .ingress_range_predecessor_head_sha256()
                .clone(),
            observation_interval_sha256: signed_identity
                .observation_interval_sha256()
                .clone(),
            response_obligation_root_sha256: signed_identity
                .response_validation_obligations_root_sha256()
                .clone(),
        };
        let generation = ShadowGeneration::new(
            signed_identity.clone(),
            bounds,
            signed_identity.sampling_basis_points(),
            active_snapshot,
            candidate_snapshot,
        )?;
        let permit = self.install_verified_generation(generation, custody)?;
        Ok((permit, signed_identity))
    }

    pub(crate) fn install_verified_generation(
        &self,
        generation: ShadowGeneration,
        custody: Arc<dyn PolicyShadowCustodyRpcSupervisor>,
    ) -> Result<ShadowActivePublicationPermit, String> {
        self.installation_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                "shadow generation installation is already in progress"
                    .to_string()
            })?;
        let _installation_guard = ShadowInstallationGuard {
            flag: &self.installation_in_progress,
        };
        self.ledger.bind_custody(Arc::clone(&custody))?;
        self.publication_reconciliation_required
            .store(true, Ordering::Release);
        let recovery_context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::RecoverCurrentState,
            "recover-publication",
            generation.generation_id(),
        )?;
        let recovered_result =
            custody.recover_current_state(&recovery_context);
        if !finish_custody_call(custody.as_ref(), recovery_context) {
            return Err(
                "custody publication recovery exceeded its hard deadline"
                    .to_string(),
            );
        }
        let recovered = recovered_result.map_err(shadow_error)?;
        if !generation
            .signed_identity
            .matches_recovered_custody_state(&recovered)
        {
            return Err(
                "signed load receipt does not match authoritative custody recovery"
                    .to_string(),
            );
        }
        let recovered_revision = recovered.publication_revision();
        let recovered_generation = recovered
            .published_generation_sha256()
            .or_else(|| recovered.committed_generation_sha256());
        let recovering_same_successor = recovered_generation
            .is_some_and(|current| {
                current.as_str() == generation.generation_id()
            });
        let previous_publication = self
            .generation
            .try_read()
            .map_err(|_| "shadow generation lock is busy".to_string())?
            .as_ref()
            .cloned();
        let previous = previous_publication
            .as_ref()
            .map(|published| Arc::clone(&published.generation));
        if let Some(recovered_generation) = recovered_generation {
            let local_matches = previous.as_ref().is_some_and(|current| {
                current.generation_id() == recovered_generation.as_str()
            });
            let successor_matches =
                generation.generation_id() == recovered_generation.as_str();
            if !local_matches && !successor_matches {
                return Err(
                    "custody recovery names an unavailable committed generation"
                        .to_string(),
                );
            }
        } else if recovered.state()
            != PublicationReconciliationState::Uninstalled
        {
            return Err(
                "custody recovery state omits its authoritative generation"
                    .to_string(),
            );
        }
        if let Some(current) = previous.as_ref() {
            if generation.identity.generation_epoch <= current.identity.generation_epoch
                || generation.identity.generation_tombstone_epoch
                    < current.identity.generation_tombstone_epoch
                || generation.identity.assignment_revision
                    <= current.identity.assignment_revision
            {
                return Err("shadow generation replacement is not monotonic".to_string());
            }
        }
        let prepare_context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::PrepareGenerationPublication,
            "prepare-publication",
            generation.generation_id(),
        )?;
        let custody_prepare_result = custody.prepare_generation_publication(
                &prepare_context,
                &recovered,
                previous
                    .as_ref()
                    .map(|current| &current.signed_identity),
                &generation.signed_identity,
            );
        if !finish_custody_call(custody.as_ref(), prepare_context) {
            return Err(
                "custody publication preparation exceeded its hard deadline"
                    .to_string(),
            );
        }
        let custody_prepare = custody_prepare_result.map_err(shadow_error)?;
        let preparation_matches = if recovering_same_successor {
            custody_prepare.matches_recovered(
                recovered.predecessor_generation_sha256(),
                &generation.signed_identity,
            )
        } else {
            custody_prepare.matches(
                previous
                    .as_ref()
                    .map(|current| &current.signed_identity),
                &generation.signed_identity,
            )
        };
        if !preparation_matches {
            abort_generation_publication_supervised(
                custody.as_ref(),
                custody_prepare,
            )?;
            return Err(
                "shadow generation custody preparation mismatch".to_string(),
            );
        }
        let (
            recovered_ledger_event_ordinal,
            recovered_ledger_head_sha256,
            recovered_spool_root_sha256,
        ) = recovered.ledger_head();
        let (
            prepared_predecessor_event_ordinal,
            prepared_predecessor_head_sha256,
        ) = custody_prepare.spill_predecessor();
        if prepared_predecessor_event_ordinal
                != recovered_ledger_event_ordinal
            || prepared_predecessor_head_sha256
                != recovered_ledger_head_sha256
            || custody_prepare.durable_spool_sha256()
                != recovered_spool_root_sha256
        {
            abort_generation_publication_supervised(
                custody.as_ref(),
                custody_prepare,
            )?;
            return Err(
                "generation preparation diverges from recovered custody heads"
                    .to_string(),
            );
        }
        let (first_ingress_sequence, last_ingress_sequence) =
            custody_prepare.sequence_bounds();
        let generation_id = generation.generation_id().to_string();
        let active_projection_value = Arc::clone(&generation.active);
        let active_snapshot_sha256 =
            active_projection_value.snapshot.hash.clone();
        let active_policy_sequence = generation.identity.active_policy_sequence;
        let active_rollback_epoch = generation.identity.active_rollback_epoch;
        let custody_receipt_sha256 = custody_prepare
            .preparation_receipt_sha256()
            .as_str()
            .to_string();
        let generation = Arc::new(generation);
        let publication = Arc::new(PublishedShadowGeneration {
            generation: Arc::clone(&generation),
            active_projection: Arc::clone(&active_projection_value),
            first_ingress_sequence,
            last_ingress_sequence,
            persisted_sequence_range_sha256: custody_prepare
                .persisted_sequence_range_sha256()
                .as_str()
                .to_string(),
            durable_spool_sha256: custody_prepare
                .durable_spool_sha256()
                .as_str()
                .to_string(),
            preparation_receipt_sha256: custody_receipt_sha256.clone(),
            publication_revision: if recovering_same_successor {
                recovered_revision
            } else {
                recovered_revision.checked_add(1).ok_or_else(|| {
                    "publication revision overflow".to_string()
                })?
            },
            publication_receipt_sha256: OnceLock::new(),
            custody: Arc::clone(&custody),
        });
        let prepared = Arc::new(PublicationReconcileCell {
            generation: Arc::clone(&generation),
            publication: Arc::clone(&publication),
            custody_prepare: custody_prepare.clone(),
            allow_blank_recovery:
                recovering_same_successor && previous.is_none(),
            custody_publication: OnceLock::new(),
            state: AtomicU8::new(PUBLICATION_PREPARED),
        });
        let mut permit = ShadowActivePublicationPermit {
            active_snapshot_epoch:
                active_projection_value.snapshot.epoch,
            active_snapshot_sha256,
            active_policy_sequence,
            active_rollback_epoch,
            active_trust_generation:
                active_projection_value.snapshot.trust_generation,
            active_compiled_behavior_sha256:
                active_projection_value
                    .snapshot
                    .compiled_behavior_sha256
                    .clone(),
            active_policy_signing_key_id:
                active_projection_value
                    .snapshot
                    .policy_signing_key_id
                    .clone(),
            active_response_verifying_key:
                active_projection_value
                    .snapshot
                    .response_verifying_key
                    .as_ref()
                    .map(|key| key.to_bytes()),
            active_response_signing_key_id:
                active_projection_value
                    .snapshot
                    .response_signing_key_id
                    .clone(),
            active_attested_response_context:
                active_projection_value
                    .snapshot
                    .attested_response_context
                    .clone(),
            custody_receipt_sha256,
            publication_revision: 0,
            publication_receipt_sha256: String::new(),
        };
        let commit_context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::CommitGenerationPublication,
            "commit-publication",
            generation.generation_id(),
        )?;
        let mut hidden_guard = match self.prepared_generation.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                abort_generation_publication_supervised(
                    custody.as_ref(),
                    custody_prepare,
                )?;
                return Err(
                    "shadow prepared-generation slot is unavailable"
                        .to_string(),
                );
            }
        };
        if hidden_guard.is_some() {
            drop(hidden_guard);
            abort_generation_publication_supervised(
                custody.as_ref(),
                custody_prepare,
            )?;
            return Err("shadow prepared-generation slot is occupied".to_string());
        }
        let mut ledger_guard = match self.ledger.state.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                drop(hidden_guard);
                abort_generation_publication_supervised(
                    custody.as_ref(),
                    custody_prepare,
                )?;
                return Err(
                    "shadow accounting state is unavailable".to_string(),
                );
            }
        };
        let prepared_index =
            match AccountingLedger::prepare_generation_locked(
                &mut ledger_guard,
                &generation,
                &custody_prepare,
            ) {
                Ok(index) => index,
                Err(error) => {
                    drop(ledger_guard);
                    drop(hidden_guard);
                    abort_generation_publication_supervised(
                        custody.as_ref(),
                        custody_prepare,
                    )?;
                    return Err(error);
                }
            };
        *hidden_guard = Some(Arc::clone(&prepared));
        drop(ledger_guard);
        drop(hidden_guard);
        let committed_result = custody.commit_generation_publication(
            &commit_context,
            &custody_prepare,
        );
        let commit_completed_before_deadline =
            finish_custody_call(custody.as_ref(), commit_context);
        let committed = match committed_result {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Ok(mut hidden_guard) =
                    self.prepared_generation.try_lock()
                {
                    if hidden_guard.as_ref().is_some_and(|cell| {
                        Arc::ptr_eq(cell, &prepared)
                    }) {
                        hidden_guard.take();
                    }
                }
                if let Ok(mut ledger_guard) = self.ledger.state.try_lock() {
                    AccountingLedger::abort_prepared_generation_locked(
                        &mut ledger_guard,
                        prepared_index,
                        &generation_id,
                    );
                } else {
                    self.ledger.mark_hard_unready();
                }
                if abort_generation_publication_supervised(
                    custody.as_ref(),
                    custody_prepare,
                )
                .is_err()
                {
                    self.ledger.mark_hard_unready();
                }
                return Err(shadow_error(error));
            }
        };
        if committed.state() != PublicationReconciliationState::Published
            || committed.published_generation_sha256()
                != Some(generation.signed_identity.generation_id())
            || committed.predecessor_generation_sha256()
                != if recovering_same_successor {
                    recovered.predecessor_generation_sha256()
                } else {
                    previous
                        .as_ref()
                        .map(|current| {
                            current.signed_identity.generation_id()
                        })
                }
            || committed.sequence_bounds()
                != Some((first_ingress_sequence, last_ingress_sequence))
            || committed.prepared_publication_sha256()
                != Some(custody_prepare.preparation_receipt_sha256())
            || committed.publication_revision()
                != publication.publication_revision
        {
            prepared
                .state
                .store(PUBLICATION_COMMITTED, Ordering::Release);
            self.ledger.mark_hard_unready();
            return Err(
                "custody committed publication receipt is not the exact successor"
                    .to_string(),
            );
        }
        permit.publication_revision = committed.publication_revision();
        permit.publication_receipt_sha256 =
            committed.signed_receipt_sha256().as_str().to_string();
        if publication
            .publication_receipt_sha256
            .set(permit.publication_receipt_sha256.clone())
            .is_err()
        {
            prepared
                .state
                .store(PUBLICATION_COMMITTED, Ordering::Release);
            self.ledger.mark_hard_unready();
            return Err(
                "published generation receipt identity was already set"
                    .to_string(),
            );
        }
        if prepared.custody_publication.set(committed).is_err() {
            prepared
                .state
                .store(PUBLICATION_COMMITTED, Ordering::Release);
            self.ledger.mark_hard_unready();
            return Err(
                "committed publication reconciliation cell was already occupied"
                    .to_string(),
            );
        }
        prepared
            .state
            .store(PUBLICATION_COMMITTED, Ordering::Release);
        if !commit_completed_before_deadline {
            self.ledger.mark_hard_unready();
            return Err(
                "custody committed the successor after the publication deadline; restart reconciliation is required"
                    .to_string(),
            );
        }
        if !self.reconcile_committed_publication(
            &prepared,
            prepared_index,
        ) {
            self.ledger.mark_hard_unready();
            return Err(
                "custody committed successor awaits bounded local reconciliation"
                    .to_string(),
            );
        }
        self.authoritative_publication_revision.store(
            publication.publication_revision,
            Ordering::Release,
        );
        self.publication_reconciliation_required
            .store(false, Ordering::Release);
        Ok(permit)
    }

    fn reconcile_committed_publication(
        &self,
        prepared: &Arc<PublicationReconcileCell>,
        prepared_index: usize,
    ) -> bool {
        let Some(custody_publication) =
            prepared.custody_publication.get()
        else {
            return false;
        };
        if prepared.state.load(Ordering::Acquire) != PUBLICATION_COMMITTED {
            return false;
        }
        let Ok(mut current_guard) = self.generation.try_write() else {
            return false;
        };
        let current_unchanged = match (
            current_guard.as_ref(),
            custody_publication.predecessor_generation_sha256(),
        ) {
            (None, None) => true,
            (None, Some(_)) if prepared.allow_blank_recovery => true,
            (Some(current), Some(previous)) => {
                current.generation.generation_id() == previous.as_str()
            }
            _ => false,
        };
        if !current_unchanged {
            return false;
        }
        let Ok(mut hidden_guard) = self.prepared_generation.try_lock() else {
            return false;
        };
        if hidden_guard.as_ref().is_none_or(|cell| {
            !Arc::ptr_eq(cell, prepared)
        }) {
            return false;
        }
        let Ok(mut ledger_guard) = self.ledger.state.try_lock() else {
            return false;
        };
        if ledger_guard
            .generations
            .get(prepared_index)
            .is_none_or(|entry| {
                entry.generation_id
                    != prepared.generation.generation_id()
                    || !entry.prepared
            })
        {
            return false;
        }
        let Ok(mut activation_gate) =
            self.activation_publication_gate.try_write()
        else {
            return false;
        };
        for entry in ledger_guard.generations.iter_mut() {
            entry.live = false;
        }
        let prepared_entry = &mut ledger_guard.generations[prepared_index];
        prepared_entry.prepared = false;
        prepared_entry.live = true;
        ledger_guard.highest_generation_epoch =
            prepared.generation.identity.generation_epoch;
        ledger_guard.highest_generation_tombstone_epoch =
            prepared.generation.identity.generation_tombstone_epoch;
        ledger_guard.highest_assignment_revision =
            prepared.generation.identity.assignment_revision;
        activation_gate.take();
        *current_guard = Some(Arc::clone(&prepared.publication));
        hidden_guard.take();
        prepared
            .state
            .store(PUBLICATION_PUBLISHED, Ordering::Release);
        true
    }

    pub(crate) fn capture(
        &self,
        snapshot: &Arc<Snapshot>,
        request: &DecisionRequest,
        authenticated_principal_id: Option<&str>,
        ingress: ShadowIngressKind,
        _captured_at_epoch_ms: u128,
        raw_body: Option<&[u8]>,
    ) -> ShadowAdmission {
        #[cfg(test)]
        if self.inactive_for_forwarding_tests {
            return ShadowAdmission::inactive(snapshot, ingress);
        }
        if !ingress.is_shadow_coverage() {
            return ShadowAdmission::inactive(snapshot, ingress);
        }
        let binding = request_binding(snapshot, request, authenticated_principal_id);
        let custody_admission = match self.begin_persisted_ingress(&binding) {
            Ok(admission) => admission,
            Err(reason) => {
                return ShadowAdmission::custody_fail_closed(
                    snapshot,
                    binding,
                    ingress,
                    reason,
                )
            }
        };
        let ingress_sequence = custody_admission.ingress_sequence();
        let captured_at_epoch_ms =
            match checked_custody_observed_epoch_ms(&custody_admission) {
                Ok(value) => value,
                Err(error) => {
                    let accounted = self.record_ingress_event(
                        &custody_admission,
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::FactsCaptureError,
                        ),
                        Some(sha256_prefixed(error.as_bytes())),
                    );
                    return if accounted {
                        ShadowAdmission::failed(
                            snapshot, binding, ingress, 0, &error,
                        )
                    } else {
                        ShadowAdmission::custody_fail_closed(
                            snapshot,
                            binding,
                            ingress,
                            PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                        )
                    };
                }
            };
        let published =
            match self.publication_for_admission(&custody_admission) {
                Ok(published) => published,
                Err(error) => {
                    let accounted = self.record_ingress_event(
                        &custody_admission,
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::AccountingGenerationTombstoned,
                        ),
                        Some(sha256_prefixed(error.as_bytes())),
                    );
                    return if accounted {
                        ShadowAdmission::failed(
                            snapshot,
                            binding,
                            ingress,
                            captured_at_epoch_ms,
                            &error,
                        )
                    } else {
                        ShadowAdmission::custody_fail_closed(
                            snapshot,
                            binding,
                            ingress,
                            PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                        )
                    };
                }
            };
        let generation = Arc::clone(&published.generation);
        if !generation.matches_active_snapshot(snapshot) {
            let accounted = self.record_ingress_event(
                &custody_admission,
                ShadowRuntimeEvent::Failure(
                    PolicyShadowTerminalReason::AccountingGenerationTombstoned,
                ),
                Some(sha256_prefixed(
                    b"active snapshot does not match custody generation",
                )),
            );
            return if accounted {
                ShadowAdmission::failed(
                    snapshot,
                    binding,
                    ingress,
                    captured_at_epoch_ms,
                    "installed shadow generation does not match the current active snapshot",
                )
            } else {
                ShadowAdmission::custody_fail_closed(
                    snapshot,
                    binding,
                    ingress,
                    PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                )
            };
        }
        let body = raw_body.unwrap_or_else(|| request.body.as_bytes());
        if body.len() > SHADOW_MAX_FACT_BODY_BYTES
            || request
                .body_sha256
                .as_ref()
                .is_some_and(|digest| digest != &sha256_prefixed(body))
            || request.forwarded_body_length.is_some_and(|length| {
                usize::try_from(length).ok() != Some(body.len())
            })
            || request.forwarded_body_utf8_valid.is_some_and(|declared| {
                declared != std::str::from_utf8(body).is_ok()
            })
        {
            let accounted = self.record_ingress_event(
                &custody_admission,
                ShadowRuntimeEvent::Failure(
                    PolicyShadowTerminalReason::FactsCaptureError,
                ),
                Some(sha256_prefixed(b"invalid raw request body binding")),
            );
            return if accounted {
                ShadowAdmission::failed(
                    snapshot,
                    binding,
                    ingress,
                    captured_at_epoch_ms,
                    "shadow raw request body binding is invalid",
                )
            } else {
                ShadowAdmission::custody_fail_closed(
                    snapshot,
                    binding,
                    ingress,
                    PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                )
            };
        }
        match custody_admission.sampling().decision() {
            SamplingDecision::ExcludedByAssignment => {
                let accounted = self.record_ingress_event(
                    &custody_admission,
                    ShadowRuntimeEvent::SampledOut,
                    Some(
                        custody_admission
                            .sampling()
                            .request_commitment_sha256()
                            .as_str()
                            .to_string(),
                    ),
                );
                return if accounted {
                    ShadowAdmission::inactive(snapshot, ingress)
                } else {
                    ShadowAdmission::custody_fail_closed(
                        snapshot,
                        binding,
                        ingress,
                        PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                    )
                };
            }
            SamplingDecision::Included => {}
        }
        let active_projection = if published.active_projection.snapshot.epoch
                == snapshot.epoch
            && published.active_projection.snapshot.hash == snapshot.hash
            && published.active_projection.snapshot.policy_sequence
                == snapshot.policy_sequence
            && published.active_projection.snapshot.rollback_epoch
                == snapshot.rollback_epoch
        {
            Arc::clone(&published.active_projection)
        } else {
            let error =
                "installed shadow active projection is unavailable".to_string();
            let accounted = self.record_ingress_event(
                &custody_admission,
                ShadowRuntimeEvent::Failure(
                    PolicyShadowTerminalReason::FactsCaptureError,
                ),
                Some(sha256_prefixed(error.as_bytes())),
            );
            return if accounted {
                ShadowAdmission::failed(
                    snapshot,
                    binding,
                    ingress,
                    captured_at_epoch_ms,
                    &error,
                )
            } else {
                ShadowAdmission::custody_fail_closed(
                    snapshot,
                    binding,
                    ingress,
                    PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                )
            };
        };
        let active = match evaluate_policy_plan_borrowed(
            &active_projection,
            request,
            authenticated_principal_id,
            ingress,
            captured_at_epoch_ms,
            PolicyEvaluationContext::active(
                captured_at_epoch_ms,
                captured_at_epoch_ms,
                None,
            ),
        ) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                let accounted = self.record_ingress_event(
                    &custody_admission,
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::ActiveEvaluationError,
                    ),
                    Some(sha256_prefixed(error.as_bytes())),
                );
                return if accounted {
                    ShadowAdmission::failed(
                        snapshot,
                        binding,
                        ingress,
                        captured_at_epoch_ms,
                        &error,
                    )
                } else {
                    ShadowAdmission::custody_fail_closed(
                        snapshot,
                        binding,
                        ingress,
                        PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                    )
                }
            }
        };
        let mut admission = ShadowAdmission::captured(
            snapshot.hash.clone(),
            snapshot.policy_sequence,
            snapshot.rollback_epoch,
            binding.clone(),
            ingress,
            captured_at_epoch_ms,
            Arc::clone(&active_projection),
            active.clone(),
        );
        let facts = match AdmittedRequestFacts::capture(
            request,
            authenticated_principal_id,
            ingress,
            captured_at_epoch_ms,
            raw_body,
        ) {
            Ok(facts) => Arc::new(facts),
            Err(error) => {
                let accounted = self.record_ingress_event(
                    &custody_admission,
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::FactsCaptureError,
                    ),
                    Some(sha256_prefixed(error.as_bytes())),
                );
                return if accounted {
                    ShadowAdmission::failed(
                        snapshot,
                        binding,
                        ingress,
                        captured_at_epoch_ms,
                        &error,
                    )
                } else {
                    ShadowAdmission::custody_fail_closed(
                        snapshot,
                        binding,
                        ingress,
                        PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                    )
                };
            }
        };
        let lifecycle = Arc::new(ShadowRequestLifecycle {
            generation,
            current_generation: Arc::clone(&self.generation),
            facts,
            ingress_sequence,
            request_binding_sha256: binding,
            request_commitment_sha256: custody_admission
                .request_commitment_sha256()
                .as_str()
                .to_string(),
            sender: self.sender.clone(),
            queued_bytes: Arc::clone(&self.queued_bytes),
            queue_poisoned: Arc::clone(&self.queue_poisoned),
            ledger: Arc::clone(&self.ledger),
            state: Mutex::new(LifecycleState::default()),
            finalization_consumed: AtomicBool::new(false),
            response_terminal_recorded: AtomicBool::new(false),
        });
        admission.finalization = Some(ShadowRequestHandle { inner: lifecycle });
        admission
    }

    fn begin_persisted_ingress(
        &self,
        binding: &str,
    ) -> Result<PersistedIngressAdmission, PolicyShadowTerminalReason> {
        let mut reconciliation_capacity = self
            .ledger
            .reserve_reconciliation_capacity(None)
            .ok_or(
                PolicyShadowTerminalReason::AccountingQueueFull,
            )?;
        let binding = match Sha256Digest::parse(binding.to_string()) {
            Ok(binding) => binding,
            Err(_) => {
                self.ledger.mark_hard_unready();
                return Err(
                    PolicyShadowTerminalReason::AccountingSerializationFailed,
                );
            }
        };
        let Some(custody) = self.custody.get() else {
            self.ledger.mark_hard_unready();
            return Err(
                PolicyShadowTerminalReason::AccountingCustodyUnavailable,
            );
        };
        let context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::BeginIngress,
            "begin-ingress",
            binding.as_str(),
        )
        .map_err(|_| {
            self.ledger.mark_hard_unready();
            PolicyShadowTerminalReason::AccountingCustodyUnavailable
        })?;
        let admission = custody.begin_ingress(&context, &binding);
        if !finish_custody_call(custody.as_ref(), context) {
            match admission {
                Ok(
                IngressCustodyAdmission::Unavailable(receipt)
                ) if receipt.request_binding_sha256() == &binding =>
                {
                    if !self.ledger.record_unavailable(receipt) {
                        self.ledger.mark_hard_unready();
                    }
                }
                Ok(IngressCustodyAdmission::Assigned(admission)) => {
                    let opening_recorded = reconciliation_capacity
                        .authorizes_event_payload(
                            admission
                                .opening_spill_receipt()
                                .canonical_event_bytes()
                                .len(),
                        )
                        && reconciliation_capacity.rebind_to_generation(
                            admission.generation_id().as_str(),
                        )
                        && self.ledger.record_admission(&admission);
                    drop(reconciliation_capacity);
                    let deadline_failure_recorded = opening_recorded
                        && self.ledger.record(
                            admission.generation_id().as_str(),
                            ShadowAccountingEvent::minimal(
                                admission.ingress_sequence(),
                                binding.as_str().to_string(),
                                admission
                                    .request_commitment_sha256()
                                    .as_str()
                                    .to_string(),
                                ShadowRuntimeEvent::Failure(
                                    PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                                ),
                            ),
                            false,
                        );
                    if !deadline_failure_recorded {
                        self.ledger.mark_hard_unready();
                    }
                }
                _ => self.ledger.mark_hard_unready(),
            }
            return Err(
                PolicyShadowTerminalReason::AccountingCustodyUnavailable,
            );
        }
        let admission = admission.map_err(|_| {
            self.ledger.mark_hard_unready();
            PolicyShadowTerminalReason::AccountingCustodyUnavailable
        })?;
        match admission {
            IngressCustodyAdmission::Assigned(admission)
                if admission.request_binding_sha256() == &binding =>
            {
                let admitted = reconciliation_capacity
                    .authorizes_event_payload(
                        admission
                            .opening_spill_receipt()
                            .canonical_event_bytes()
                            .len(),
                    )
                    && reconciliation_capacity.rebind_to_generation(
                        admission.generation_id().as_str(),
                    )
                    && self.ledger.record_admission(&admission);
                if admitted {
                    Ok(admission)
                } else {
                    let mut event = ShadowAccountingEvent::minimal(
                        admission.ingress_sequence(),
                        binding.as_str().to_string(),
                        admission
                            .request_commitment_sha256()
                            .as_str()
                            .to_string(),
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::AccountingLedgerContention,
                        ),
                    );
                    event.response_facts_sha256 = Some(sha256_prefixed(
                        b"bounded local admission ledger unavailable",
                    ));
                    let failure_appended = self.ledger.record(
                        admission.generation_id().as_str(),
                        event,
                        false,
                    );
                    if !failure_appended {
                        self.ledger.mark_hard_unready();
                    }
                    Err(
                        PolicyShadowTerminalReason::AccountingLedgerContention,
                    )
                }
            }
            IngressCustodyAdmission::Unavailable(receipt)
                if receipt.request_binding_sha256() == &binding =>
            {
                if !self.ledger.record_unavailable(receipt) {
                    self.ledger.mark_hard_unready();
                }
                Err(
                    PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                )
            }
            _ => {
                self.ledger.mark_hard_unready();
                Err(
                    PolicyShadowTerminalReason::AccountingCustodyUnavailable,
                )
            }
        }
    }

    fn publication_for_admission(
        &self,
        admission: &PersistedIngressAdmission,
    ) -> Result<Arc<PublishedShadowGeneration>, String> {
        if self
            .publication_reconciliation_required
            .load(Ordering::Acquire)
        {
            let prepared = self
                .prepared_generation
                .try_lock()
                .ok()
                .and_then(|slot| slot.as_ref().cloned());
            let prepared_index = prepared.as_ref().and_then(|cell| {
                self.ledger.state.try_lock().ok().and_then(|state| {
                    state.generations.iter().position(|entry| {
                        entry.generation_id == cell.generation.generation_id()
                    })
                })
            });
            if prepared
                .as_ref()
                .zip(prepared_index)
                .is_some_and(|(cell, index)| {
                    self.reconcile_committed_publication(cell, index)
                })
            {
                if let Some(publication) = prepared.as_ref() {
                    self.authoritative_publication_revision.store(
                        publication.publication.publication_revision,
                        Ordering::Release,
                    );
                }
                self.publication_reconciliation_required
                    .store(false, Ordering::Release);
            } else {
                return Err(
                    "shadow generation publication requires durable reconciliation"
                        .to_string(),
                );
            }
        }
        if self.installation_in_progress.load(Ordering::Acquire) {
            return Err(
                "shadow generation publication is reconciling".to_string(),
            );
        }
        let published = self
            .generation
            .try_read()
            .map_err(|_| "shadow generation publication slot is busy".to_string())?
            .as_ref()
            .cloned()
            .ok_or_else(|| "shadow generation is not locally published".to_string())?;
        let custody = self
            .custody
            .get()
            .ok_or_else(|| "shadow custody authority is not bound".to_string())?;
        if published.generation.generation_id()
                != admission.generation_id().as_str()
            || admission.ingress_sequence()
                < published.first_ingress_sequence
            || admission.ingress_sequence()
                > published.last_ingress_sequence
            || published.publication_revision
                != self
                    .authoritative_publication_revision
                    .load(Ordering::Acquire)
            || !Arc::ptr_eq(&published.custody, custody)
        {
            return Err(
                "custody admission does not match the atomic local publication"
                    .to_string(),
            );
        }
        Ok(published)
    }

    fn record_ingress_event(
        &self,
        admission: &PersistedIngressAdmission,
        runtime_event: ShadowRuntimeEvent,
        evidence_sha256: Option<String>,
    ) -> bool {
        let mut event = ShadowAccountingEvent::minimal(
            admission.ingress_sequence(),
            admission.request_binding_sha256().as_str().to_string(),
            admission
                .request_commitment_sha256()
                .as_str()
                .to_string(),
            runtime_event,
        );
        event.response_facts_sha256 = evidence_sha256;
        let recorded = self.ledger.record(
            admission.generation_id().as_str(),
            event,
            false,
        );
        if recorded {
            let _ = self.sender.try_send(ShadowWork::CompactionWake);
        }
        recorded
    }

    pub(crate) fn account_malformed_target(
        &self,
        snapshot: &Arc<Snapshot>,
        method: &str,
        target: &str,
        captured_at_epoch_ms: u128,
    ) {
        let binding = sha256_prefixed(
            format!(
                "serverware.shadowMalformedTarget/v1\0{}\0{}\0{}\0{}",
                snapshot.hash, method, target, captured_at_epoch_ms
            )
            .as_bytes(),
        );
        if let Ok(admission) = self.begin_persisted_ingress(&binding) {
            self.record_ingress_event(
                &admission,
                ShadowRuntimeEvent::Failure(
                    PolicyShadowTerminalReason::FactsCaptureError,
                ),
                Some(sha256_prefixed(b"malformed request target")),
            );
        }
    }

    pub(crate) fn account_unsupported(
        &self,
        snapshot: &Arc<Snapshot>,
        ingress: ShadowIngressKind,
        method: &str,
        target: &str,
    ) -> bool {
        let binding = sha256_prefixed(
            format!(
                "serverware.shadowIngressAccounting/v2\0{}\0{}\0{}\0{:?}",
                snapshot.hash, method, target, ingress
            )
            .as_bytes(),
        );
        let Ok(admission) = self.begin_persisted_ingress(&binding) else {
            return false;
        };
        let published = match self.publication_for_admission(&admission) {
            Ok(published)
                if published.generation.matches_active_snapshot(snapshot) =>
            {
                published
            }
            _ => {
                return self.record_ingress_event(
                    &admission,
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::AccountingGenerationTombstoned,
                    ),
                    Some(sha256_prefixed(
                        b"unsupported ingress generation mismatch",
                    )),
                );
            }
        };
        let captured_at_epoch_ms =
            match checked_custody_observed_epoch_ms(&admission) {
                Ok(value) => value,
                Err(error) => {
                    return self.record_ingress_event(
                        &admission,
                        ShadowRuntimeEvent::Failure(
                            PolicyShadowTerminalReason::FactsCaptureError,
                        ),
                        Some(sha256_prefixed(error.as_bytes())),
                    );
                }
            };
        if admission.sampling().decision()
            == SamplingDecision::ExcludedByAssignment
        {
            let recorded = self.record_ingress_event(
                &admission,
                ShadowRuntimeEvent::SampledOut,
                Some(
                    admission
                        .sampling()
                        .request_commitment_sha256()
                        .as_str()
                        .to_string(),
                ),
            );
            return recorded;
        }
        self.record_ingress_event(
            &admission,
            if ingress == ShadowIngressKind::OuterConnect {
                ShadowRuntimeEvent::TransportExcluded
            } else {
                ShadowRuntimeEvent::UnsupportedRequiredIngress
            },
            Some(digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowTransportAccounting/v2",
                "capturedAtEpochMs":captured_at_epoch_ms,
                "requestCommitmentSha256":admission
                    .sampling()
                    .request_commitment_sha256()
                    .as_str(),
                "ingress":format!("{ingress:?}"),
                "generationId":published.generation.generation_id(),
            }))),
        )
    }

    #[allow(dead_code)]
    fn compact_accounting_spool(
        &self,
        request: &AuthenticatedSpoolCompactionRequest,
    ) -> Result<VerifiedSpoolCompactionReceipt, String> {
        let custody = self
            .custody
            .get()
            .ok_or_else(|| "production shadow custody is not bound".to_string())?;
        // Custody performs durable compaction without a runtime ledger lock.
        // The local bounded receipt cache advances only after its authenticated
        // compaction receipt is checked against the exact retained spill head.
        let context = custody_call_context(
            custody.as_ref(),
            PolicyShadowCustodyOperation::CompactSpool,
            "compact-spool",
            request.old_spool_head_sha256().as_str(),
        )?;
        let receipt_result = custody.compact_spool(&context, request);
        if !finish_custody_call(custody.as_ref(), context) {
            self.ledger.mark_hard_unready();
            return Err(
                "custody compaction exceeded its hard deadline".to_string(),
            );
        }
        let receipt = receipt_result.map_err(shadow_error)?;
        if !receipt.matches_request(request) {
            self.ledger.mark_hard_unready();
            return Err(
                "custody compaction receipt does not match the authenticated request"
                    .to_string(),
            );
        }
        self.ledger
            .apply_authenticated_compaction(request, &receipt)?;
        Ok(receipt)
    }

    pub(crate) fn status(&self) -> Value {
        let generation =
            if self.installation_in_progress.load(Ordering::Acquire) {
                None
            } else {
                self.generation.try_read().ok().and_then(|generation| {
                generation.as_ref().map(|published| {
                    let generation = &published.generation;
                    let (candidate_hash, candidate_sequence, rollback_epoch) =
                        generation.candidate.identity();
                    json!({
                        "generation_id":generation.generation_id(),
                        "generation_epoch":generation.identity.generation_epoch,
                        "generation_tombstone_epoch":generation.identity.generation_tombstone_epoch,
                        "assignment_sha256":generation.identity.assignment_sha256.as_str(),
                        "assignment_revision":generation.identity.assignment_revision,
                        "load_receipt_sha256":generation.identity.load_receipt_sha256.as_str(),
                        "runtime_boot_sha256":generation.identity.runtime_boot_sha256.as_str(),
                        "response_obligation_root_sha256":generation.identity.response_obligation_root_sha256.as_str(),
                        "assignment_starts_at_epoch_ms":generation.identity.assignment_starts_at_epoch_ms,
                        "assignment_ends_at_epoch_ms":generation.identity.assignment_ends_at_epoch_ms,
                        "sampling_basis_points":generation.sampling_basis_points,
                        "active_policy_sha256":generation.identity.active_snapshot_sha256.as_str(),
                        "active_policy_sequence":generation.identity.active_policy_sequence,
                        "active_rollback_epoch":generation.identity.active_rollback_epoch,
                        "candidate_policy_sha256":candidate_hash,
                        "candidate_policy_sequence":candidate_sequence,
                        "candidate_rollback_epoch":rollback_epoch,
                        "first_ingress_sequence":published.first_ingress_sequence,
                        "last_ingress_sequence":published.last_ingress_sequence,
                        "persisted_sequence_range_sha256":published.persisted_sequence_range_sha256,
                        "durable_spool_sha256":published.durable_spool_sha256,
                        "preparation_receipt_sha256":published.preparation_receipt_sha256,
                        "publication_revision":published.publication_revision,
                    })
                })
            })
            };
        let mut status = self.ledger.status();
        if let Some(object) = status.as_object_mut() {
            object.insert("active_generation".to_string(), generation.unwrap_or(Value::Null));
            object.insert(
                "production_custody_bound".to_string(),
                Value::Bool(self.custody.get().is_some()),
            );
            object.insert(
                "publication_reconciliation_required".to_string(),
                Value::Bool(
                    self.publication_reconciliation_required
                        .load(Ordering::Acquire),
                ),
            );
            object.insert(
                "authoritative_publication_revision".to_string(),
                Value::from(
                    self.authoritative_publication_revision
                        .load(Ordering::Acquire),
                ),
            );
            object.insert(
                "queue".to_string(),
                json!({
                    "item_capacity":SHADOW_QUEUE_ITEMS,
                    "byte_capacity":SHADOW_QUEUE_BYTES,
                    "reserved_bytes":self.queued_bytes.load(Ordering::Acquire),
                    "accounting_poisoned":self.queue_poisoned.load(Ordering::Acquire),
                    "send_mode":"try-send-no-retry",
                    "reservation":"raii",
                }),
            );
        }
        status
    }
}

struct CandidateResponseBehavior {
    released_body_sha256: String,
    released_body_bytes: u64,
    released_content_type: Option<String>,
    release_mode: String,
}

fn evaluate_candidate_response_behavior(
    route: &Route,
    status: StatusCode,
    content_type: Option<&str>,
    body: &[u8],
    operation: Option<&Value>,
    response_observed_at_epoch_ms: u64,
) -> Result<CandidateResponseBehavior, Value> {
    // This is the immutable response-observation time committed by the caller,
    // not request decision time or a fresh candidate-worker wall-clock read.
    let base_response_config = route
        .adapter_config
        .get("response")
        .unwrap_or(&Value::Null);
    let response_config = response_config_for_status(base_response_config, status)?;
    let credential_bearing = route
        .credential_ref
        .as_deref()
        .is_some_and(|credential_ref| !credential_ref.is_empty());
    if let Some(error) = credential_response_projection_error(
        credential_bearing,
        &response_config,
        &route.adapter_type,
    ) {
        return Err(error);
    }
    let maximum_body_bytes = response_config
        .get("maxBodyBytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| json!({"error":"response_body_limit_missing"}))?;
    let exact_body_bytes = u64::try_from(body.len())
        .map_err(|_| json!({"error":"candidate_response_length_overflow"}))?;
    if exact_body_bytes > maximum_body_bytes {
        return Err(json!({
            "error":"response_body_too_large",
            "maxBodyBytes":maximum_body_bytes,
        }));
    }
    let mode = effective_response_mode(&route.adapter_type, Some(&response_config))
        .unwrap_or("any");
    if !matches!(mode, "any" | "headersOnly" | "json") {
        return Err(json!({"error":"response_mode_unsupported","mode":mode}));
    }
    if mode == "headersOnly" {
        return Ok(CandidateResponseBehavior {
            released_body_sha256: sha256_prefixed(b""),
            released_body_bytes: 0,
            released_content_type: None,
            release_mode: "headers-only".to_string(),
        });
    }

    let paths = allowed_field_paths(&response_config);
    if route.adapter_type != "gmail.v1" && mode == "json" && paths.is_empty() {
        return Err(json!({
            "error":"response_allowed_fields_missing",
            "adapter":route.adapter_type,
        }));
    }
    if route.adapter_type == "gmail.v1" && status.is_success() {
        let validate_internal_date = response_config
            .get("validateInternalDate")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !validate_internal_date && paths.is_empty() {
            validate_response_constraints_for_type_at_ms(
                route,
                body,
                operation,
                Some("responseDateWindow"),
                i128::from(response_observed_at_epoch_ms),
            )?;
            return Ok(CandidateResponseBehavior {
                released_body_sha256: sha256_prefixed(body),
                released_body_bytes: exact_body_bytes,
                released_content_type: content_type.map(str::to_string),
                release_mode: "gmail-validation-disabled".to_string(),
            });
        }
    }
    let requires_json = mode == "json" || !paths.is_empty() || route.adapter_type == "gmail.v1";
    if !requires_json {
        if status.is_success() {
            validate_response_constraints_at_ms(
                route, body, operation, i128::from(response_observed_at_epoch_ms),
            )?;
        }
        return Ok(CandidateResponseBehavior {
            released_body_sha256: sha256_prefixed(body),
            released_body_bytes: exact_body_bytes,
            released_content_type: content_type.map(str::to_string),
            release_mode: "passthrough".to_string(),
        });
    }

    let mut payload = sensitive_json_value_from_slice(body)
        .map_err(|_| json!({"error":"response_invalid_json","adapter":route.adapter_type}))?;
    if route.adapter_type == "gmail.v1" && status.is_success() {
        let days = config_u64(&route.adapter_config, "maxAgeDays", 30);
        let is_list_response = operation
            .and_then(|value| value.get("operation"))
            .and_then(Value::as_str)
            == Some("gmail.messages.list");
        let validate_internal_date = response_config
            .get("validateInternalDate")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if validate_internal_date {
            let cutoff_ms = gmail_cutoff_ms_at(u128::from(response_observed_at_epoch_ms), days);
            if is_list_response {
                let messages = payload
                    .get_mut("messages")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| json!({"error":"gmail_response_messages_missing"}))?;
                for item in messages {
                    let object = item
                        .as_object_mut()
                        .ok_or_else(|| json!({"error":"gmail_response_message_invalid"}))?;
                    if object
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| canonical_gmail_message_id(id))
                        .is_none()
                    {
                        return Err(json!({"error":"gmail_response_message_id_invalid"}));
                    }
                    validate_gmail_internal_date_value_at_cutoff(
                        object.get("internalDate"),
                        days,
                        cutoff_ms,
                    )?;
                    object.insert(
                        "serverwareAgeProof".to_string(),
                        Value::String("validated".to_string()),
                    );
                }
            } else {
                validate_gmail_internal_date_value_at_cutoff(
                    payload.get("internalDate"),
                    days,
                    cutoff_ms,
                )?;
            }
        }
        let constraint_body = Zeroizing::new(
            serde_json::to_vec(&*payload)
                .map_err(|_| json!({"error":"gmail_response_serialization_failed"}))?,
        );
        for constraint_type in ["responseBinding", "responseJson", "responseDateWindow"] {
            validate_response_constraints_for_type_at_ms(
                route,
                &constraint_body,
                operation,
                Some(constraint_type),
                i128::from(response_observed_at_epoch_ms),
            )?;
        }
        apply_gmail_allowed_fields(&mut payload, &response_config, is_list_response);
    } else if status.is_success() {
        validate_response_constraints_at_ms(
            route, body, operation, i128::from(response_observed_at_epoch_ms),
        )?;
        if !paths.is_empty() {
            let projected = SensitiveJsonValue::new(redact_json_value(&payload, &paths));
            replace_sensitive_json_value(&mut payload, projected.into_value());
        }
    } else if !paths.is_empty() {
        let projected = SensitiveJsonValue::new(redact_json_value(&payload, &paths));
        replace_sensitive_json_value(&mut payload, projected.into_value());
    }
    let released_body = Zeroizing::new(
        serde_json::to_vec(&*payload)
            .map_err(|_| json!({"error":"response_serialization_failed","adapter":route.adapter_type}))?,
    );
    Ok(CandidateResponseBehavior {
        released_body_sha256: sha256_prefixed(&released_body),
        released_body_bytes: u64::try_from(released_body.len())
            .map_err(|_| json!({"error":"candidate_response_length_overflow"}))?,
        released_content_type: Some("application/json".to_string()),
        release_mode: "json-projection".to_string(),
    })
}

fn evaluate_candidate_response(
    candidate_snapshot: &PolicyPlanSnapshot,
    candidate: &PolicyEvaluation,
    response_obligation_root_sha256: &Sha256Digest,
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
    physical_headers_sha256: &str,
    gmail_metadata_evidence: Option<&ActiveGmailMetadataEvidence>,
    captured_at_epoch_ms: u64,
) -> Result<String, String> {
    let status = StatusCode::from_u16(status)
        .map_err(|_| "candidate response status is invalid".to_string())?;
    let route_id = candidate
        .route_id
        .as_deref()
        .ok_or("candidate response route is unavailable")?;
    let route = candidate_snapshot
        .snapshot
        .routes
        .iter()
        .find(|route| route.id == route_id)
        .ok_or("candidate response route is missing")?;
    let operation = candidate.operation.as_ref();
    let requires_gmail_metadata = route.adapter_type == "gmail.v1"
        && operation
            .and_then(|value| value.get("operation"))
            .and_then(Value::as_str)
            == Some("gmail.messages.list")
        && gmail_metadata_fetch_for_route(route).is_some();
    let comparison_body = if requires_gmail_metadata {
        let evidence = gmail_metadata_evidence
            .ok_or("candidate Gmail list validation requires active metadata evidence")?;
        let (intent_route_sha256, maximum_age_days, maximum_messages) = candidate
            .candidate_plan()
            .and_then(|plan| {
                plan.effect_intents().iter().find_map(|intent| match intent {
                    CandidateEffectIntent::WouldUseActiveGmailMetadataEvidence {
                        route_sha256,
                        maximum_age_days,
                        maximum_messages,
                        ..
                    } => Some((
                        route_sha256.as_str(),
                        *maximum_age_days,
                        *maximum_messages,
                    )),
                    _ => None,
                })
            })
            .ok_or("candidate Gmail metadata effect intent is unavailable")?;
        if evidence.route_sha256 != intent_route_sha256
            || evidence.route_sha256 != sha256_prefixed(route.id.as_bytes())
            || maximum_age_days
                != config_u64(&route.adapter_config, "maxAgeDays", 30)
            || evidence.hydrated_message_count > maximum_messages
        {
            return Err(
                "active Gmail metadata evidence does not match candidate bounds"
                    .to_string(),
            );
        }
        evidence.hydrated_response_body.as_ref()
    } else {
        body
    };
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| canonical_response_content_type(Some(value)));
    let validation = (|| -> Result<CandidateResponseBehavior, Value> {
        validate_response_envelopes(
            route,
            status,
            headers,
            Some(u64::try_from(comparison_body.len()).map_err(|_| {
                json!({"error":"candidate_response_length_overflow"})
            })?),
            operation,
        )?;
        if status.is_success() {
            let operation_context = operation.unwrap_or(&Value::Null);
            validate_public_npm_publish_receipt(
                route,
                status,
                content_type.as_deref(),
                comparison_body,
                operation_context,
            )?;
            validate_response_binding_envelope(
                route,
                status,
                content_type.as_deref(),
                operation_context,
            )?;
        }
        evaluate_candidate_response_behavior(
            route,
            status,
            content_type.as_deref(),
            comparison_body,
            operation,
            captured_at_epoch_ms,
        )
    })();
    let response_behavior = validation.as_ref().ok();
    let rejection_sha256 = validation
        .as_ref()
        .err()
        .map(|payload| digest_json_ensure_ascii(payload));
    let response_obligations_sha256 = candidate
        .candidate_plan()
        .map(|plan| {
            digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowCandidateResponseObligations/v1",
                "commitments":plan.response_validation_commitments(),
            }))
        })
        .ok_or("candidate response plan is unavailable")?;
    let response_policy = response_policy_for_route(route);
    Ok(digest_json_ensure_ascii(&json!({
        "domain":"serverware.policyShadowCandidateResponseValidation/v1",
        "outcome":if validation.is_ok() {"accepted"} else {"rejected"},
        "routeIdSha256":sha256_prefixed(route.id.as_bytes()),
        "capturedAtEpochMs":captured_at_epoch_ms,
        "status":status.as_u16(),
        "bodySha256":sha256_prefixed(comparison_body),
        "physicalHeadersSha256":physical_headers_sha256,
        "activeGmailMetadataEvidenceSha256":gmail_metadata_evidence.map(ActiveGmailMetadataEvidence::commitment),
        "generationResponseObligationRootSha256":response_obligation_root_sha256.as_str(),
        "responseObligationsSha256":response_obligations_sha256,
        "responsePolicySha256":digest_json_ensure_ascii(&json!({
            "adapterType":route.adapter_type,
            "responseConfig":route.adapter_config.get("response"),
            "hasResponseConstraints":response_policy.has_response_constraints,
            "hasResponseBinding":response_policy.has_response_binding,
            "credentialBearing":response_policy.credential_bearing,
        })),
        "candidateReleasedBodySha256":response_behavior.as_ref().map(|behavior| &behavior.released_body_sha256),
        "candidateReleasedBodyBytes":response_behavior.as_ref().map(|behavior| behavior.released_body_bytes),
        "candidateReleasedContentType":response_behavior.as_ref().and_then(|behavior| behavior.released_content_type.as_deref()),
        "candidateReleaseMode":response_behavior.as_ref().map(|behavior| behavior.release_mode.as_str()),
        "rejectionSha256":rejection_sha256,
    })))
}

fn shadow_worker(receiver: Receiver<ShadowWork>, ledger: Arc<AccountingLedger>) {
    while let Ok(work) = receiver.recv() {
        match work {
            ShadowWork::CompactionWake => {}
            ShadowWork::Request(job) => {
                let lifecycle = &job.lifecycle;
                if !lifecycle.generation_is_current() {
                    if !ledger.record(
                        lifecycle.generation.generation_id(),
                        ShadowAccountingEvent::minimal(
                            lifecycle.ingress_sequence,
                            lifecycle.request_binding_sha256.clone(),
                            lifecycle.request_commitment_sha256.clone(),
                            ShadowRuntimeEvent::Failure(
                                PolicyShadowTerminalReason::AccountingGenerationTombstoned,
                            ),
                        ),
                        false,
                    ) {
                        ledger.mark_hard_unready();
                    }
                    continue;
                }
                let (final_active, decision_time_binding) = lifecycle
                    .state
                    .try_lock()
                    .ok()
                    .map(|state| {
                        (
                            state.final_active.as_ref().map(|record| record.decision.clone()),
                            state.decision_time_binding.clone(),
                        )
                    })
                    .unwrap_or((None, None));
                let Some(final_active) = final_active else {
                    if !ledger.record(
                        lifecycle.generation.generation_id(),
                        ShadowAccountingEvent::minimal(
                            lifecycle.ingress_sequence,
                            lifecycle.request_binding_sha256.clone(),
                            lifecycle.request_commitment_sha256.clone(),
                            ShadowRuntimeEvent::Failure(
                                PolicyShadowTerminalReason::CandidateEvaluationError,
                            ),
                        ),
                        false,
                    ) {
                        ledger.mark_hard_unready();
                    }
                    continue;
                };
                let evaluated = evaluate_policy_plan(
                    &lifecycle.generation.candidate,
                    &lifecycle.facts,
                    PolicyEvaluationContext::candidate(
                        lifecycle.facts.captured_at_epoch_ms,
                        final_active.decision_at_epoch_ms,
                        final_active.resolved_credential_slot.clone(),
                        final_active.resolved_credential_version,
                    ),
                );
                let mut record = ShadowAccountingEvent::minimal(
                    lifecycle.ingress_sequence,
                    lifecycle.request_binding_sha256.clone(),
                    lifecycle.request_commitment_sha256.clone(),
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::CandidateEvaluationError,
                    ),
                );
                record.active_plan_sha256 = Some(
                    final_active
                        .active_evaluation
                        .semantic_sha256
                        .clone(),
                );
                record.final_active_decision_sha256 =
                    Some(final_active.final_decision_sha256.clone());
                record.active_effect_results_sha256 =
                    Some(final_active.effect_results_sha256.clone());
                record.active_disposition = Some(final_active.final_outcome.clone());
                let mut accepted_candidate = None;
                match evaluated {
                    Ok(candidate)
                        if candidate
                            .candidate_plan()
                            .is_some_and(|plan| plan.validate().is_ok()) =>
                    {
                        let binding_is_exact = final_active
                            .active_evaluation
                            .active_plan()
                            .map(|plan| {
                                final_active.effect_requirements
                                    == ActiveEffectRequirements::from_plan(plan)
                                    && decision_time_binding
                                        .as_ref()
                                        .is_some_and(|binding| {
                                            binding.active_plan_sha256
                                                == final_active
                                                    .active_evaluation
                                                    .semantic_sha256
                                                && binding.effect_requirements
                                                    == final_active
                                                        .effect_requirements
                                                && binding
                                                    .active_evaluation
                                                    .semantic_sha256
                                                    == final_active
                                                        .active_evaluation
                                                        .semantic_sha256
                                        })
                            })
                            == Some(true);
                        if !binding_is_exact {
                            record.set_event(
                                ShadowRuntimeEvent::Failure(
                                    PolicyShadowTerminalReason::CandidateEvaluationError,
                                ),
                            );
                            if !ledger.record(
                                lifecycle.generation.generation_id(),
                                record,
                                true,
                            ) {
                                ledger.mark_hard_unready();
                            }
                            continue;
                        }
                        record.set_event(
                            ShadowRuntimeEvent::CandidateEvaluated,
                        );
                        record.candidate_plan_sha256 =
                            Some(candidate.semantic_sha256.clone());
                        record.candidate_disposition =
                            Some(candidate.disposition_label().to_string());
                        accepted_candidate = Some(candidate);
                    }
                    Ok(candidate) => {
                        record.candidate_plan_sha256 =
                            Some(candidate.semantic_sha256.clone());
                        record.candidate_disposition =
                            Some(candidate.disposition_label().to_string());
                    }
                    Err(_) => {}
                }
                let durably_recorded = ledger.record(
                    lifecycle.generation.generation_id(),
                    record,
                    true,
                );
                if durably_recorded {
                    if let (Some(candidate), Ok(mut state)) =
                        (accepted_candidate, lifecycle.state.try_lock())
                    {
                        state.candidate = Some(candidate);
                    }
                } else {
                    ledger.mark_hard_unready();
                }
            }
            ShadowWork::Response(mut job) => {
                let enqueue_authorized = {
                    let (gate, ready) = &*job.enqueue_gate;
                    match gate.lock() {
                        Ok(guard) => {
                            if guard.is_none() {
                                ready.wait_timeout(
                                    guard,
                                    Duration::from_millis(250),
                                )
                                .ok()
                                .and_then(|(guard, _)| *guard)
                            } else {
                                *guard
                            }
                        }
                        Err(_) => None,
                    }
                };
                if enqueue_authorized != Some(true) {
                    continue;
                }
                let lifecycle = &job.lifecycle;
                if !lifecycle.generation_is_current() {
                    job.comparison_terminal_appended = ledger.record(
                        lifecycle.generation.generation_id(),
                        ShadowAccountingEvent::minimal(
                            lifecycle.ingress_sequence,
                            lifecycle.request_binding_sha256.clone(),
                            lifecycle.request_commitment_sha256.clone(),
                            ShadowRuntimeEvent::Failure(
                                PolicyShadowTerminalReason::AccountingGenerationTombstoned,
                            ),
                        ),
                        false,
                    );
                    if !job.comparison_terminal_appended {
                        ledger.mark_hard_unready();
                    }
                    continue;
                }
                let (final_active, mut candidate) = lifecycle
                    .state
                    .try_lock()
                    .ok()
                    .map(|state| (
                        state.final_active.as_ref().map(|record| record.decision.clone()),
                        state.candidate.clone(),
                    ))
                    .unwrap_or((None, None));
                if candidate.is_none() {
                    if let Some(active) = final_active.as_ref() {
                        candidate = evaluate_policy_plan(
                            &lifecycle.generation.candidate,
                            &lifecycle.facts,
                            PolicyEvaluationContext::candidate(
                                lifecycle.facts.captured_at_epoch_ms,
                                active.decision_at_epoch_ms,
                                active.resolved_credential_slot.clone(),
                                active.resolved_credential_version,
                            ),
                        )
                        .ok();
                    }
                }
                let mut record = ShadowAccountingEvent::minimal(
                    lifecycle.ingress_sequence,
                    lifecycle.request_binding_sha256.clone(),
                    lifecycle.request_commitment_sha256.clone(),
                    ShadowRuntimeEvent::Failure(
                        PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
                    ),
                );
                record.response_facts_sha256 =
                    Some(job.response_facts_sha256.clone());
                record.active_response_validation_sha256 =
                    Some(job.active_response_validation_sha256.clone());
                if let Some(active) = final_active {
                    record.final_active_decision_sha256 =
                        Some(active.final_decision_sha256);
                    record.active_effect_results_sha256 =
                        Some(active.effect_results_sha256);
                    record.active_disposition = Some(active.final_outcome);
                    if !active.dispatch_authorized {
                        record.candidate_disposition =
                            Some("not-applicable-active-not-dispatched".to_string());
                    }
                }
                if let Some(candidate) = candidate {
                    record.candidate_plan_sha256 =
                        Some(candidate.semantic_sha256.clone());
                    record.candidate_disposition =
                        Some(candidate.disposition_label().to_string());
                    match evaluate_candidate_response(
                        &lifecycle.generation.candidate,
                        &candidate,
                        &lifecycle.generation.identity.response_obligation_root_sha256,
                        job.status,
                        &job.headers,
                        &job.body,
                        &job.physical_headers_sha256,
                        job.gmail_metadata_evidence.as_ref(),
                        job.captured_at_epoch_ms,
                    ) {
                        Ok(commitment) => {
                            record.set_event(
                                ShadowRuntimeEvent::ResponseEvaluated,
                            );
                            record.candidate_response_validation_sha256 = Some(commitment);
                        }
                        Err(error) => {
                            record.candidate_response_validation_sha256 =
                                Some(sha256_prefixed(error.as_bytes()));
                        }
                    }
                }
                job.comparison_terminal_appended = ledger.record(
                    lifecycle.generation.generation_id(),
                    record,
                    false,
                );
                if !job.comparison_terminal_appended {
                    ledger.mark_hard_unready();
                }
            }
        }
        ledger.compact_one_requested();
    }
}

#[cfg(test)]
mod active_terminal_record_tests {
    use super::*;
    use super::super::policy_shadow::terminal_receipt_fixture::{self, Fault};
    use super::super::policy_shadow::credential_effect_receipt_fixture as effect_fixture;

    // These are exact local receipt/retention component tests, not a running
    // authority, successful effect execution, or production custody RPC proof.
    fn decision(dispatch: bool) -> FinalActiveDecision {
        let outcome = if dispatch {
            PolicyOutcome::Permit
        } else {
            PolicyOutcome::Deny { reason: Identifier::parse("fixture-denial").unwrap() }
        };
        let plan = ActivePolicyPlan::new(outcome, vec![], vec![], vec![]).unwrap();
        let semantic_sha256 = plan.semantic_commitment().unwrap().as_str().to_string();
        let effect_requirements = ActiveEffectRequirements::from_plan(&plan);
        let final_outcome = if dispatch { "allow" } else { "deny" }.to_string();
        let credential_prerequisites = CredentialPrerequisiteEvidence::default();
        let component_effects = json!({"explicitCommitments":[credential_prerequisites.commitment()]});
        let prerequisite_effect_root = PrerequisiteEffectRoot::new(&credential_prerequisites, &component_effects).unwrap();
        let effect_results_sha256 = digest_json_ensure_ascii(&component_effects);
        let terminal_response_sha256 = sha256_prefixed(b"component response bytes");
        let final_decision_sha256 = final_active_outcome_digest(
            &semantic_sha256,
            &final_outcome,
            if dispatch { 200 } else { 403 },
            dispatch,
            &effect_results_sha256,
            &terminal_response_sha256,
        );
        FinalActiveDecision {
            decision_at_epoch_ms: 1,
            active_evaluation: PolicyEvaluation {
                snapshot_hash: sha256_prefixed(b"component policy"),
                route_id: None,
                disposition: if dispatch { PureDisposition::Permit } else {
                    PureDisposition::Deny {
                        status: 403,
                        reason: "fixture-denial".to_string(),
                        payload: json!({"error":"fixture-denial"}),
                    }
                },
                plan: SeparatedPolicyPlan::Active(plan),
                operation: None,
                rewrite: None,
                conditions: vec![],
                semantic_sha256,
            },
            effect_requirements,
            final_outcome,
            final_decision_sha256,
            effect_results_sha256,
            terminal_response_sha256,
            exact_response_facts_sha256: Some(sha256_prefixed(b"component response facts")),
            gmail_metadata_evidence_sha256: None,
            resolved_credential_slot: None,
            resolved_credential_version: None,
            dispatch_authorized: dispatch,
            credential_prerequisites,
            prerequisite_effect_root,
        }
    }

    fn event(decision: &FinalActiveDecision) -> ShadowAccountingEvent {
        decision.terminal_event(
            1,
            sha256_prefixed(b"component request binding"),
            sha256_prefixed(b"component request commitment"),
            None,
        )
    }

    fn prepare(
        decision: FinalActiveDecision,
        event: &ShadowAccountingEvent,
        status: u16,
    ) -> Result<PreparedActiveTerminalRecord, String> {
        PreparedActiveTerminalRecord::new(
            &sha256_prefixed(b"component generation"),
            1,
            &sha256_prefixed(b"component request binding"),
            &sha256_prefixed(b"component request commitment"),
            decision,
            status,
            None,
            event,
        )
    }

    fn spool(event: &ShadowAccountingEvent, generation: &str) -> ShadowSpoolEvent {
        let bytes = event.canonical_bytes().unwrap();
        ShadowSpoolEvent::new(
            Sha256Digest::parse(generation.to_string()).unwrap(),
            event.ingress_sequence,
            Sha256Digest::parse(event.request_binding_sha256.clone()).unwrap(),
            Sha256Digest::parse(event.request_commitment_sha256.clone()).unwrap(),
            event.spool_phase(),
            Sha256Digest::compute(&bytes),
            bytes,
        ).unwrap()
    }

    fn verified(event: &ShadowSpoolEvent) -> VerifiedShadowSpillReceipt {
        terminal_receipt_fixture::verify(event, ShadowSpoolDisposition::Appended, Fault::None)
            .expect("real local signature and exact storage/retrieval binding")
    }

    fn durable(receipt: &VerifiedShadowSpillReceipt) -> DurableShadowEventReceipt {
        // Use the real modeled arena/reference conversion; never hand-build a
        // VerifiedShadowSpillReceipt or its retained durable reference.
        let mut arena = PolicyCoreModeledReceiptArena::try_new(1).unwrap();
        let modeled = ImmutableSpillReceiptRef::modeled_reference(receipt, 1).unwrap();
        let handle = arena.insert(modeled).unwrap();
        let reference = ImmutableSpillReceiptRef::from_verified(receipt, handle).unwrap();
        reference.durable_receipt(receipt.ingress_sequence())
    }

    #[test]
    fn active_terminal_record_retains_real_verified_component_receipt() {
        for dispatch in [false, true] {
            let decision = decision(dispatch);
            let event = event(&decision);
            let generation = sha256_prefixed(b"component generation");
            let spool = spool(&event, &generation);
            let verified = verified(&spool);
            let receipt = durable(&verified);
            let prepared = prepare(decision, &event, if dispatch { 200 } else { 403 }).unwrap();
            let record = prepared.match_receipt(receipt).unwrap().into_record();
            assert!(record.receipt.generation_id.matches_digest(verified.generation_id()));
            assert_eq!(record.receipt.ingress_sequence, verified.ingress_sequence());
            assert_eq!(record.receipt.event_ordinal, verified.event_ordinal());
            for (retained, authenticated) in [
                (record.receipt.event_sha256, verified.event_sha256()),
                (record.receipt.resulting_head_sha256, verified.resulting_head_sha256()),
                (record.receipt.signed_receipt_sha256, verified.signed_receipt_sha256()),
                (record.receipt.retrieval_id_sha256, verified.retrieval_id_sha256()),
                (record.receipt.retrieval_proof_sha256, verified.retrieval_proof_sha256()),
                (record.receipt.verified_payload_sha256, verified.canonical_payload_sha256()),
                (record.receipt.verified_trust_checkpoint_sha256,
                    &verified.verified_trust_checkpoint().checkpoint_id),
            ] {
                assert!(retained.matches_digest(authenticated));
            }
            assert_eq!(record.request_binding_sha256,
                InlineSha256Digest::from_str(&event.request_binding_sha256).unwrap());
            assert_eq!(record.request_commitment_sha256,
                InlineSha256Digest::from_str(&event.request_commitment_sha256).unwrap());
            assert_eq!(record.returned_http_status, if dispatch { 200 } else { 403 });
            assert_eq!(record.phase, spool.phase());
            assert_eq!(record.decision.final_decision_sha256,
                event.final_active_decision_sha256.unwrap());
        }
    }

    #[test]
    fn active_terminal_record_rejects_preappend_decision_and_status_drift() {
        let baseline = decision(false);
        let event = event(&baseline);
        assert!(prepare(baseline.clone(), &event, 403).is_ok());
        for label in ["plan", "final", "effect", "response", "status", "dispatch", "outcome"] {
            let mut changed = baseline.clone();
            let mut status = 403;
            match label {
                "plan" => changed.active_evaluation.semantic_sha256 = sha256_prefixed(b"other plan"),
                "final" => changed.final_decision_sha256 = sha256_prefixed(b"other final decision"),
                "effect" => changed.effect_results_sha256 = sha256_prefixed(b"other effects"),
                "response" => changed.terminal_response_sha256 = sha256_prefixed(b"other response"),
                "status" => status = 404,
                "dispatch" => changed.dispatch_authorized = true,
                "outcome" => changed.final_outcome = "error".to_string(),
                _ => unreachable!(),
            }
            assert_eq!(prepare(changed, &event, status).err().as_deref(),
                Some(if label == "effect" {
                    "terminal record credential prerequisite commitment mismatch"
                } else { "terminal record decision commitment mismatch" }), "{label}");
        }
        assert_eq!(prepare(baseline, &event, 199).err().as_deref(),
            Some("terminal record status or identity is invalid"));
    }

    #[test]
    fn active_terminal_record_rejects_preappend_event_drift() {
        let baseline = decision(false);
        let original = event(&baseline);
        for label in ["request-binding", "request-commitment", "ingress", "phase", "plan",
            "final", "effect", "response-facts", "response-validation", "outcome"]
        {
            let mut changed = original.clone();
            let other = Some(sha256_prefixed(b"changed event commitment"));
            match label {
                "request-binding" => changed.request_binding_sha256 = other.unwrap(),
                "request-commitment" => changed.request_commitment_sha256 = other.unwrap(),
                "ingress" => changed.ingress_sequence = 2,
                "phase" => changed.set_event(ShadowRuntimeEvent::ResponseTerminalAppended),
                "plan" => changed.active_plan_sha256 = other,
                "final" => changed.final_active_decision_sha256 = other,
                "effect" => changed.active_effect_results_sha256 = other,
                "response-facts" => changed.response_facts_sha256 = other,
                "response-validation" => changed.active_response_validation_sha256 = other,
                "outcome" => changed.active_disposition = Some("error".to_string()),
                _ => unreachable!(),
            }
            assert_eq!(prepare(baseline.clone(), &changed, 403).err().as_deref(),
                Some("terminal record event commitment mismatch"), "{label}");
        }
    }

    #[test]
    fn active_terminal_record_rejects_crossed_verified_receipts() {
        let baseline = decision(false);
        let original = event(&baseline);
        for label in ["generation", "ingress", "request-binding", "request-commitment", "phase", "event"] {
            let mut changed = original.clone();
            let mut generation = sha256_prefixed(b"component generation");
            match label {
                "generation" => generation = sha256_prefixed(b"different generation"),
                "ingress" => changed.ingress_sequence = 2,
                "request-binding" => changed.request_binding_sha256 = sha256_prefixed(b"different binding"),
                "request-commitment" => changed.request_commitment_sha256 = sha256_prefixed(b"different request"),
                "phase" => changed.set_event(ShadowRuntimeEvent::ResponseTerminalAppended),
                "event" => changed.active_effect_results_sha256 = Some(sha256_prefixed(b"different effects")),
                _ => unreachable!(),
            }
            let receipt = verified(&spool(&changed, &generation));
            let prepared = prepare(baseline.clone(), &original, 403).unwrap();
            assert_eq!(prepared.match_receipt(durable(&receipt)).err().as_deref(),
                Some("terminal record durable receipt binding mismatch"), "{label}");
        }
    }

    #[test]
    fn active_terminal_receipt_selection_requires_exact_appended_terminal() {
        let event = event(&decision(false));
        let generation = sha256_prefixed(b"component generation");
        let terminal_spool = spool(&event, &generation);
        let receipt = verified(&terminal_spool);
        for outcome in [TerminalSlotAppendOutcome::Committed(receipt.clone()),
            TerminalSlotAppendOutcome::Existing(receipt.clone())]
        {
            let selected = matching_terminal_append_receipt(&terminal_spool, Ok(outcome)).unwrap();
            assert_eq!(selected.signed_receipt_sha256(), receipt.signed_receipt_sha256());
        }
        assert!(matching_terminal_append_receipt(&terminal_spool,
            Ok(TerminalSlotAppendOutcome::Fork(receipt))).is_none());
        assert!(matching_terminal_append_receipt(&terminal_spool, Err(ShadowError::CustodyUnavailable)).is_none());
        let unavailable = terminal_receipt_fixture::verify(
            &terminal_spool, ShadowSpoolDisposition::Unavailable, Fault::None).unwrap();
        assert!(matching_terminal_append_receipt(&terminal_spool,
            Ok(TerminalSlotAppendOutcome::Committed(unavailable))).is_none());
        let mut changed = event.clone();
        changed.ingress_sequence = 2;
        let crossed = verified(&spool(&changed, &generation));
        assert!(matching_terminal_append_receipt(&terminal_spool,
            Ok(TerminalSlotAppendOutcome::Existing(crossed))).is_none());
        changed.set_event(ShadowRuntimeEvent::CandidateEvaluated);
        let nonterminal = spool(&changed, &generation);
        assert!(matching_terminal_append_receipt(&nonterminal,
            Ok(TerminalSlotAppendOutcome::Committed(verified(&nonterminal)))).is_none());
    }

    #[test]
    fn active_terminal_receipt_component_checks_real_crypto_time_and_storage() {
        let event = spool(&event(&decision(false)), &sha256_prefixed(b"component generation"));
        assert!(terminal_receipt_fixture::verify(&event,
            ShadowSpoolDisposition::Appended, Fault::None).is_ok());
        for (fault, expected) in [
            (Fault::Signature, ShadowError::SignatureInvalid),
            (Fault::PinnedKey, ShadowError::SignerBindingMismatch),
            (Fault::VerificationKey, ShadowError::SignatureInvalid),
            (Fault::StaleTime, ShadowError::EvidenceTooOld),
            (Fault::FutureTime, ShadowError::EvidenceTooOld),
            (Fault::Checkpoint, ShadowError::TrustCheckpointMismatch),
            (Fault::PersistenceBytes, ShadowError::PayloadDigestMismatch),
            (Fault::RetrievalBytes, ShadowError::BindingDrift),
        ] {
            assert_eq!(terminal_receipt_fixture::verify(&event,
                ShadowSpoolDisposition::Appended, fault).unwrap_err(), expected, "{fault:?}");
        }
    }

    fn credential_parent(baseline: &FinalActiveDecision) -> CredentialPrerequisiteParent {
        CredentialPrerequisiteParent {
            commitment: InlineSha256Digest::compute(b"component parent context"),
            generation: InlineSha256Digest::compute(b"component generation"),
            request_binding: InlineSha256Digest::compute(b"component request binding"),
            request_commitment: InlineSha256Digest::compute(b"component request commitment"),
            active_plan: InlineSha256Digest::from_str(&baseline.active_evaluation.semantic_sha256).unwrap(),
            scope: InlineSha256Digest::compute(b"component principal-route-slot scope"),
            credential_slot: InlineSha256Digest::compute(b"credential:component"),
            ingress_sequence: 1,
            decision_at_epoch_ms: baseline.decision_at_epoch_ms,
        }
    }

    fn credential_info(version: u64, secret_available: bool) -> CredentialLeaseInfo {
        let metadata = BTreeMap::from([("component".to_string(), json!("public metadata"))]);
        CredentialLeaseInfo { version, metadata_sha256: credential_lease_metadata_sha256(&metadata), metadata, secret_available }
    }

    fn credential_group(parent: CredentialPrerequisiteParent, lease: bool) -> [Option<ActiveEffectPreparation>; 2] {
        let kinds = if lease {
            [ActiveMutableEffectKind::CredentialLease, ActiveMutableEffectKind::CredentialDecrypt]
        } else {
            [ActiveMutableEffectKind::CredentialGeneration, ActiveMutableEffectKind::OauthRotation]
        };
        kinds.map(|kind| Some(ActiveEffectPreparation::new(parent.generation.to_digest().unwrap(),
            parent.ingress_sequence, kind, parent.commitment.to_digest().unwrap(), parent.scope.to_digest().unwrap()).unwrap()))
    }

    // Set up the actual production-used reservation/retention primitives with
    // real verified local receipts. This does not construct a live lifecycle,
    // assignment or RPC supervisor, and never manufactures a Verified value.
    fn retain_credential_group(
        evidence: &mut CredentialPrerequisiteEvidence,
        parent: CredentialPrerequisiteParent,
        group: &[Option<ActiveEffectPreparation>; 2],
        info: &CredentialLeaseInfo,
        state: ActiveEffectCommitState,
    ) {
        evidence.reserve(parent, group).unwrap();
        let result = CredentialOuterResult::from_info(info).unwrap();
        let digest = Sha256Digest::parse(result.result_commitment().unwrap()).unwrap();
        for preparation in group.iter().flatten() {
            let permit = effect_fixture::permit(preparation, effect_fixture::Fault::None).unwrap();
            let receipt = effect_fixture::commit(&permit, state, &digest, effect_fixture::Fault::None).unwrap();
            let compact = receipt.compact_for(preparation, permit.signed_receipt_sha256(), state, &digest).unwrap();
            let slot = evidence.slots[credential_outer_slot(preparation.effect_kind()).unwrap()].as_mut().unwrap();
            slot.attempted = true;
            slot.barrier = Some(InlineSha256Digest::from_digest(permit.signed_receipt_sha256()).unwrap());
            evidence.retain(parent, preparation, compact,
                (state == ActiveEffectCommitState::Committed).then_some(result)).unwrap();
        }
    }

    #[test]
    fn credential_prerequisites_retain_real_verified_outer_groups_and_exact_results() {
        let parent = credential_parent(&decision(false));
        let generation = credential_group(parent, false);
        let lease = credential_group(parent, true);
        let mut evidence = CredentialPrerequisiteEvidence::default();
        let metadata = credential_info(7, false);
        retain_credential_group(&mut evidence, parent, &generation, &metadata, ActiveEffectCommitState::Committed);
        evidence.publish_resolution(parent, &generation, CredentialOuterResult::from_info(&metadata).unwrap()).unwrap();
        let available = credential_info(7, true);
        retain_credential_group(&mut evidence, parent, &lease, &available, ActiveEffectCommitState::Committed);
        evidence.publish_resolution(parent, &lease, CredentialOuterResult::from_info(&available).unwrap()).unwrap();
        assert_eq!(evidence.slots.iter().flatten().count(), 4);
        assert!(!evidence.slots[0].unwrap().result.unwrap().secret_available);
        assert!(evidence.slots[2].unwrap().result.unwrap().secret_available);
        evidence.validate_decision(&json!({"credential_ref":"credential:component","credential_version":7,
            "policy_effect_results":{"credential_secret_available":true}}), true).unwrap();
        assert!(4 * (std::mem::size_of::<CredentialPrerequisiteEvidence>()
            + std::mem::size_of::<PrerequisiteEffectRoot>()) <= SHADOW_CREDENTIAL_PREREQUISITE_RETENTION_BYTES);
    }

    #[test]
    fn credential_prerequisites_freeze_parent_and_reserve_only_closed_nonempty_groups() {
        let baseline = decision(false);
        let parent = credential_parent(&baseline);
        let group = credential_group(parent, false);
        let mut evidence = CredentialPrerequisiteEvidence::default();
        evidence.reserve(parent, &group).unwrap();
        assert!(evidence.permits_binding(&baseline.active_evaluation.semantic_sha256, 1));
        assert!(!evidence.permits_binding(&baseline.active_evaluation.semantic_sha256, 2));
        assert!(!evidence.permits_binding(&sha256_prefixed(b"changed plan"), 1));
        assert_eq!(evidence.reserve(parent, &group).unwrap_err(), "credential prerequisite outer slot already reserved");
        assert_eq!(CredentialPrerequisiteEvidence::default().reserve(parent, &[None, None]).unwrap_err(), "invalid outer credential prerequisite group");
        for field in 0..7 {
            let mut changed = parent;
            match field {
                0 => changed.generation = InlineSha256Digest::compute(b"other generation"),
                1 => changed.ingress_sequence += 1,
                2 => changed.request_binding = InlineSha256Digest::compute(b"other request"),
                3 => changed.request_commitment = InlineSha256Digest::compute(b"other commitment"),
                4 => changed.active_plan = InlineSha256Digest::compute(b"other plan"),
                5 => changed.scope = InlineSha256Digest::compute(b"other scope"),
                _ => changed.decision_at_epoch_ms += 1,
            }
            assert_eq!(evidence.reserve(changed, &credential_group(changed, true)).unwrap_err(), "credential prerequisite parent binding changed");
        }
        let mut other = parent;
        other.ingress_sequence += 1;
        assert_eq!(CredentialPrerequisiteEvidence::default().reserve(parent, &credential_group(other, false)).unwrap_err(),
            "credential prerequisite preparation parent mismatch");
    }

    #[test]
    fn credential_prerequisites_reject_crossed_signed_results_and_recorded_barriers() {
        let parent = credential_parent(&decision(false));
        let group = credential_group(parent, false);
        let preparation = group[0].as_ref().unwrap();
        let info = credential_info(7, true);
        let result = CredentialOuterResult::from_info(&info).unwrap();
        let digest = Sha256Digest::parse(result.result_commitment().unwrap()).unwrap();
        let permit = effect_fixture::permit(preparation, effect_fixture::Fault::None).unwrap();
        let receipt = effect_fixture::commit(&permit, ActiveEffectCommitState::Committed, &digest, effect_fixture::Fault::None).unwrap();
        let compact = receipt.compact_for(preparation, permit.signed_receipt_sha256(), ActiveEffectCommitState::Committed, &digest).unwrap();
        let mut baseline = CredentialPrerequisiteEvidence::default();
        baseline.reserve(parent, &group).unwrap();
        baseline.slots[0].as_mut().unwrap().attempted = true;
        baseline.slots[0].as_mut().unwrap().barrier = Some(InlineSha256Digest::from_digest(permit.signed_receipt_sha256()).unwrap());
        let mut valid = baseline;
        valid.retain(parent, preparation, compact, Some(result)).unwrap();
        for field in 0..3 {
            let mut crossed = result;
            match field { 0 => crossed.version += 1,
                1 => crossed.metadata = InlineSha256Digest::compute(b"other metadata"),
                _ => crossed.secret_available = false }
            assert_eq!(baseline.retain(parent, preparation, compact, Some(crossed)).unwrap_err(), "credential prerequisite signed result mismatch");
        }
        let alternate = effect_fixture::alternate_permit(preparation).unwrap();
        let alternate_receipt = effect_fixture::commit(&alternate, ActiveEffectCommitState::Committed, &digest, effect_fixture::Fault::None).unwrap();
        let alternate_compact = alternate_receipt.compact_for(preparation, alternate.signed_receipt_sha256(), ActiveEffectCommitState::Committed, &digest).unwrap();
        assert_eq!(baseline.retain(parent, preparation, alternate_compact, Some(result)).unwrap_err(), "credential prerequisite recorded barrier mismatch");
        assert_eq!(receipt.compact_for(preparation, alternate.signed_receipt_sha256(), ActiveEffectCommitState::Committed, &digest).unwrap_err(), ShadowError::BindingDrift);
        let other = group[1].as_ref().unwrap();
        let other_permit = effect_fixture::permit(other, effect_fixture::Fault::None).unwrap();
        let other_receipt = effect_fixture::commit(&other_permit, ActiveEffectCommitState::Committed, &digest, effect_fixture::Fault::None).unwrap();
        let other_compact = other_receipt.compact_for(other, other_permit.signed_receipt_sha256(), ActiveEffectCommitState::Committed, &digest).unwrap();
        assert_eq!(baseline.retain(parent, preparation, other_compact, Some(result)).unwrap_err(), "credential prerequisite recorded barrier mismatch");
        let other_lifecycle = ActiveEffectPreparation::new(parent.generation.to_digest().unwrap(),
            parent.ingress_sequence + 1, ActiveMutableEffectKind::CredentialGeneration,
            parent.commitment.to_digest().unwrap(), parent.scope.to_digest().unwrap()).unwrap();
        let crossed_permit = effect_fixture::permit(&other_lifecycle, effect_fixture::Fault::None).unwrap();
        let crossed_receipt = effect_fixture::commit(&crossed_permit, ActiveEffectCommitState::Committed, &digest, effect_fixture::Fault::None).unwrap();
        let crossed_compact = crossed_receipt.compact_for(&other_lifecycle, crossed_permit.signed_receipt_sha256(),
            ActiveEffectCommitState::Committed, &digest).unwrap();
        assert_eq!(baseline.retain(parent, preparation, crossed_compact, Some(result)).unwrap_err(), "credential prerequisite recorded barrier mismatch");
    }

    #[test]
    fn credential_prerequisites_preserve_failures_and_reject_cross_group_generation_drift() {
        let parent = credential_parent(&decision(false));
        let generation = credential_group(parent, false);
        let lease = credential_group(parent, true);
        for state in [ActiveEffectCommitState::Aborted, ActiveEffectCommitState::OutcomeUnknown, ActiveEffectCommitState::ReconcileRequired] {
            let mut evidence = CredentialPrerequisiteEvidence::default();
            let info = credential_info(7, false);
            retain_credential_group(&mut evidence, parent, &generation, &info, state);
            assert!(evidence.failed && evidence.resolved.is_none());
            assert_eq!(evidence.slots[0].unwrap().receipt.unwrap().terminal_state(), state);
            assert_eq!(evidence.publish_resolution(parent, &generation, CredentialOuterResult::from_info(&info).unwrap()).unwrap_err(), "credential prerequisite group is not committed");
            evidence.validate_decision(&json!({}), false).unwrap();
        }
        for metadata_drift in [false, true] {
            let mut evidence = CredentialPrerequisiteEvidence::default();
            let info = credential_info(7, false);
            retain_credential_group(&mut evidence, parent, &generation, &info, ActiveEffectCommitState::Committed);
            evidence.publish_resolution(parent, &generation, CredentialOuterResult::from_info(&info).unwrap()).unwrap();
            let mut changed = credential_info(if metadata_drift { 7 } else { 8 }, true);
            if metadata_drift {
                changed.metadata.insert("component".into(), json!("different coherent metadata"));
                changed.metadata_sha256 = credential_lease_metadata_sha256(&changed.metadata);
            }
            retain_credential_group(&mut evidence, parent, &lease, &changed, ActiveEffectCommitState::Committed);
            assert_eq!(evidence.publish_resolution(parent, &lease, CredentialOuterResult::from_info(&changed).unwrap()).unwrap_err(), "credential prerequisite generation changed between outer groups");
            assert!(evidence.failed);
            assert_eq!(evidence.resolved.unwrap().version, 7);
            assert_eq!(evidence.slots[2].unwrap().result.unwrap().version, changed.version);
        }
    }

    #[test]
    fn credential_prerequisites_distinguish_denial_omission_from_dispatch_and_false_claims() {
        let parent = credential_parent(&decision(false));
        let group = credential_group(parent, false);
        let info = credential_info(7, true);
        let mut evidence = CredentialPrerequisiteEvidence::default();
        retain_credential_group(&mut evidence, parent, &group, &info, ActiveEffectCommitState::Committed);
        evidence.publish_resolution(parent, &group, CredentialOuterResult::from_info(&info).unwrap()).unwrap();
        for denial in [json!({}), json!({"credential_ref":null,"credential_version":null}), json!({"credential_ref":"credential:component"})] {
            evidence.validate_decision(&denial, false).unwrap();
        }
        let dispatch = json!({"credential_ref":"credential:component","credential_version":7,
            "policy_effect_results":{"credential_secret_available":true}});
        assert!(evidence.validate_decision(&dispatch, true).is_err()); // generation-only is insufficient
        let lease = credential_group(parent, true);
        retain_credential_group(&mut evidence, parent, &lease, &info, ActiveEffectCommitState::Committed);
        evidence.publish_resolution(parent, &lease, CredentialOuterResult::from_info(&info).unwrap()).unwrap();
        evidence.validate_decision(&dispatch, true).unwrap();
        for denied in [json!({"credential_ref":7}), json!({"credential_version":"7"}),
            json!({"credential_ref":"other"}), json!({"credential_version":8}),
            json!({"credential_ref":"credential:component","policy_effect_results":{"credential_secret_available":false}}),
            json!({"credential_ref":"credential:component","policy_effect_results":{"credential_secret_available":"true"}})]
        {
            assert_eq!(evidence.validate_decision(&denied, false).unwrap_err(), "active decision contradicts retained credential prerequisite result");
        }
        let mut invalid = credential_info(0, true);
        assert!(CredentialOuterResult::from_info(&invalid).is_err());
        invalid.version = 7;
        invalid.metadata_sha256 = sha256_prefixed(b"not actual metadata");
        assert!(CredentialOuterResult::from_info(&invalid).is_err());
        let metadata_only = credential_info(7, false);
        let mut no_secret = CredentialPrerequisiteEvidence::default();
        for group in [&group, &lease] {
            retain_credential_group(&mut no_secret, parent, group, &metadata_only, ActiveEffectCommitState::Committed);
            no_secret.publish_resolution(parent, group, CredentialOuterResult::from_info(&metadata_only).unwrap()).unwrap();
        }
        assert!(no_secret.validate_decision(&json!({"credential_ref":"credential:component","credential_version":7,
            "policy_effect_results":{"credential_secret_available":false}}), true).is_err());
    }

    #[test]
    fn credential_prerequisite_refs_are_bound_by_the_real_terminal_receipt() {
        let mut baseline = decision(false);
        let parent = credential_parent(&baseline);
        let group = credential_group(parent, false);
        let info = credential_info(7, false);
        retain_credential_group(&mut baseline.credential_prerequisites, parent, &group, &info, ActiveEffectCommitState::Committed);
        baseline.credential_prerequisites.publish_resolution(parent, &group, CredentialOuterResult::from_info(&info).unwrap()).unwrap();
        let commitment = baseline.credential_prerequisites.commitment();
        assert!(PrerequisiteEffectRoot::new(&baseline.credential_prerequisites, &json!({"explicitCommitments":[]})).is_err());
        assert!(PrerequisiteEffectRoot::new(&baseline.credential_prerequisites, &json!({"explicitCommitments":[commitment,commitment]})).is_err());
        let root = json!({"explicitCommitments":[commitment]});
        baseline.prerequisite_effect_root = PrerequisiteEffectRoot::new(&baseline.credential_prerequisites, &root).unwrap();
        baseline.effect_results_sha256 = digest_json_ensure_ascii(&root);
        baseline.final_decision_sha256 = final_active_outcome_digest(&baseline.active_evaluation.semantic_sha256,
            "deny", 403, false, &baseline.effect_results_sha256, &baseline.terminal_response_sha256);
        let terminal_event = event(&baseline);
        let signed = verified(&spool(&terminal_event, &sha256_prefixed(b"component generation")));
        let record = prepare(baseline.clone(), &terminal_event, 403).unwrap()
            .match_receipt(durable(&signed)).unwrap().into_record();
        assert_eq!(record.decision.credential_prerequisites, baseline.credential_prerequisites);
        let mut changed = baseline.clone();
        changed.credential_prerequisites.resolved.as_mut().unwrap().version += 1;
        assert_eq!(prepare(changed, &terminal_event, 403).err().as_deref(), Some("terminal record credential prerequisite commitment mismatch"));
        let mut changed = baseline;
        changed.prerequisite_effect_root.effect_results = InlineSha256Digest::compute(b"different root");
        assert_eq!(prepare(changed, &terminal_event, 403).err().as_deref(), Some("terminal record credential prerequisite commitment mismatch"));
    }

    #[test]
    fn credential_prerequisite_rpc_seal_and_recovery_boundaries_are_source_pinned_only() {
        // No claim of executed production RPC, generation race or lock/CAS
        // failure. These bounded source slices cannot match their own literals.
        let source = include_str!("policy_core.rs");
        let prepare = source.split_once("pub(crate) fn prepare_credential_prerequisite(").unwrap().1
            .split_once("pub(crate) fn settle_credential_prerequisite(").unwrap().0;
        assert!(prepare.find("self.validate_credential_reservation(reservation)?").unwrap()
            < prepare.find("self.prepare_mutable_effect(").unwrap());
        assert!(prepare.contains("self.reconcile_mutable_effect(preparation.effect_id_sha256())"));
        let settle = source.split_once("pub(crate) fn settle_credential_prerequisite(").unwrap().1
            .split_once("pub(crate) fn publish_credential_resolution(").unwrap().0;
        assert!(settle.find("let result = (||").unwrap() < settle.find("CredentialOuterResult::from_info").unwrap());
        assert!(settle.find("self.commit_mutable_effect(").unwrap() < settle.find("if state.credential_prerequisites_sealed").unwrap());
        assert!(settle.contains("self.reconcile_bound_mutable_effect(generation, *ingress, actual)"));
        let pending = source.split_once("fn explicit_pending_active(").unwrap().1
            .split_once("fn record_failure(").unwrap().0;
        assert!(pending.contains("state.credential_prerequisites_sealed = true"));
        let finalize = source.split_once("fn finalize_terminal(").unwrap().1
            .split_once("pub(crate) fn record_unready_accounting").unwrap().0;
        let postappend = finalize.split_once("let matched_record = prepared_record.match_receipt").unwrap().1;
        assert!(postappend.find("state.credential_prerequisites != matched_record.prepared.decision.credential_prerequisites").unwrap()
            < postappend.find("state.final_active = Some(matched_record.into_record())").unwrap());
    }

    #[test]
    fn active_terminal_retention_has_fixed_bounded_queue_charge() {
        assert_eq!(std::mem::size_of::<DurableShadowEventReceipt>(), 272);
        assert!(std::mem::size_of::<ActiveTerminalRecord>()
            - std::mem::size_of::<FinalActiveDecision>() <= SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES);
        assert!(std::mem::size_of::<Option<ActiveTerminalRecord>>()
            - std::mem::size_of::<Option<FinalActiveDecision>>() <= SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES);
        let surcharge = SHADOW_ACTIVE_TERMINAL_RETENTION_BYTES + SHADOW_CREDENTIAL_PREREQUISITE_RETENTION_BYTES;
        assert_eq!(shadow_job_bytes_with_terminal_retention(0), surcharge);
        assert_eq!(shadow_job_bytes_with_terminal_retention(SHADOW_MAX_JOB_BYTES - surcharge),
            SHADOW_MAX_JOB_BYTES);
        assert!(shadow_job_bytes_with_terminal_retention(SHADOW_MAX_JOB_BYTES - surcharge + 1)
            > SHADOW_MAX_JOB_BYTES);
        assert_eq!(shadow_job_bytes_with_terminal_retention(usize::MAX), usize::MAX);
        // Source wiring is distinct from executing queue admission under RPC.
        let source = include_str!("policy_core.rs");
        let request = source.split_once("fn enqueue_request_evaluation(&self)").unwrap().1;
        assert!(request.split_once("if estimated_bytes > SHADOW_MAX_JOB_BYTES").unwrap().0
            .contains("shadow_job_bytes_with_terminal_retention(self"));
        let response = source.split_once("impl ShadowResponseAttempt").unwrap().1
            .split_once("pub(crate) fn finish_parsed_unavailable").unwrap().0;
        assert!(response.contains("shadow_job_bytes_with_terminal_retention(capture"));
    }

    #[test]
    fn active_terminal_publication_failure_boundary_is_source_pinned_only() {
        // Not a full finalize_terminal/CAS/RPC test: assert the production
        // publication remains after every existing postappend local guard.
        let source = include_str!("policy_core.rs");
        let finalize = source.split_once("fn finalize_terminal(").unwrap().1
            .split_once("pub(crate) fn record_unready_accounting").unwrap().0;
        let prepared = finalize.find("PreparedActiveTerminalRecord::new(").unwrap();
        let appended = finalize.find("self.inner.ledger.record_with_receipt(").unwrap();
        let matched = finalize.find("prepared_record.match_receipt(receipt)").unwrap();
        let final_cas = finalize.find(".finalization_consumed").unwrap();
        // The preappend duplicate check uses finalization_consumed first;
        // locate the actual postappend CAS separately.
        let postappend = &finalize[matched..];
        let consume = postappend.find(".compare_exchange(").unwrap();
        let response = postappend.find("if dispatch_authorized").unwrap();
        let state = postappend.find("let mut state = match self.inner.state.try_lock()").unwrap();
        let published = postappend.find("state.final_active = Some(matched_record.into_record())").unwrap();
        assert!(prepared < appended && appended < matched && final_cas < appended);
        assert!(consume < response && response < state && state < published);
        assert!(postappend[consume..response].contains("return Err("));
        assert!(postappend[response..state].contains("return Err("));
        assert!(postappend[state..published].contains("return Err("));
        assert_eq!(finalize.matches("matched_record.into_record()").count(), 1);
    }
}

#[cfg(test)]
mod response_explicit_time_tests {
    use super::*;

    const OBSERVED_AT: u64 = 1_000_000_000_000;

    fn route() -> Route {
        let mut route = super::super::tests::test_snapshot(1).routes[0].clone();
        route.constraints.push(json!({
            "id":"response-age","type":"responseDateWindow","phase":"response",
            "dateFields":["created_at"],"formats":["epochMillis"],
            "maxAgeDays":1,"required":true,"allowFutureSkewSeconds":1,
        }));
        route
    }

    fn evaluate(
        route: &Route,
        body: &[u8],
        operation: Option<&Value>,
        observed_at: u64,
    ) -> Result<CandidateResponseBehavior, Value> {
        // Actual candidate behavior component, without transport/custody mocks
        // or a claim that active live validation shares this reference time.
        evaluate_candidate_response_behavior(
            route, StatusCode::OK, Some("application/json"), body, operation, observed_at,
        )
    }

    #[test]
    fn candidate_response_date_window_uses_observed_time_before_projection() {
        let operation = json!({"operation":"generic.read"});
        for mode in ["json", "any"] {
            let mut route = route();
            route.adapter_config["response"]["mode"] = json!(mode);
            if mode == "any" {
                route.adapter_config["response"]["allowedFields"] = json!([]);
            }
            for timestamp in [OBSERVED_AT - 86_400_000, OBSERVED_AT, OBSERVED_AT + 1000] {
                let body = format!(r#"{{"created_at":"{timestamp}","safe":"ok"}}"#);
                let accepted = evaluate(&route, body.as_bytes(), Some(&operation), OBSERVED_AT)
                    .expect("historical response time admits exact endpoints");
                let expected = if mode == "json" { &br#"{"safe":"ok"}"#[..] } else { body.as_bytes() };
                assert_eq!(accepted.released_body_sha256, sha256_prefixed(expected));
                assert_eq!(accepted.released_body_bytes, expected.len() as u64);
                assert_eq!(accepted.released_content_type.as_deref(), Some("application/json"));
                assert_eq!(accepted.release_mode, if mode == "json" { "json-projection" } else { "passthrough" });
            }
            for (timestamp, observed_at, error) in [
                (OBSERVED_AT - 86_400_000, OBSERVED_AT + 1, "response_date_window_exceeded"),
                (OBSERVED_AT + 1000, OBSERVED_AT - 1, "response_date_future_denied"),
            ] {
                let body = format!(r#"{{"created_at":"{timestamp}","safe":"ok"}}"#);
                let denied = evaluate(&route, body.as_bytes(), Some(&operation), observed_at)
                    .err().expect("one millisecond beyond the bound must deny before projection");
                assert_eq!(denied["error"], error);
                assert_eq!(denied["status_code"], 502);
            }
        }
    }

    #[test]
    fn candidate_response_date_window_preserves_scopes_and_failure_guards() {
        let mut route = route();
        route.constraints.last_mut().unwrap()["operations"] = json!(["generic.read"]);
        let operation = json!({"operation":"generic.read"});
        let valid = format!(r#"{{"created_at":"{OBSERVED_AT}","safe":"ok"}}"#);
        evaluate(&route, valid.as_bytes(), Some(&operation), OBSERVED_AT).unwrap();
        let missing_operation = evaluate(&route, valid.as_bytes(), None, OBSERVED_AT)
            .err().expect("scoped response rule requires actual operation context");
        assert_eq!(missing_operation["error"], "response_operation_context_missing");
        for (body, error) in [
            (&b"not-json"[..], "response_invalid_json"),
            (&br#"{"safe":"ok"}"#[..], "response_date_field_missing"),
            (&br#"{"created_at":"not-a-date","safe":"ok"}"#[..], "response_date_field_invalid"),
        ] {
            assert_eq!(evaluate(&route, body, Some(&operation), OBSERVED_AT)
                .err().expect("invalid response must remain denied")["error"], error);
        }
        evaluate(&route, br#"{"safe":"ok"}"#, Some(&json!({"operation":"generic.other"})), OBSERVED_AT)
            .expect("a date rule scoped to another operation remains inapplicable");
        route.constraints.last_mut().unwrap()["phase"] = json!("request");
        assert_eq!(evaluate(&route, valid.as_bytes(), Some(&operation), OBSERVED_AT)
            .err().expect("invalid phase is not bypassed")["error"], "constraint_type_unsupported_at_runtime");
    }

    #[test]
    fn candidate_gmail_response_dates_share_the_explicit_observation_time() {
        let mut route = route();
        route.adapter_type = "gmail.v1".to_string();
        route.adapter_config["maxAgeDays"] = json!(1);
        route.adapter_config["response"]["allowedFields"] = json!(["id", "internalDate"]);
        let operation = json!({"operation":"gmail.message.get"});
        for validate_internal in [false, true] {
            route.adapter_config["response"]["validateInternalDate"] = json!(validate_internal);
            let cutoff = OBSERVED_AT - 86_400_000;
            let body = format!(r#"{{"created_at":"{cutoff}","id":"message-1","internalDate":"{OBSERVED_AT}"}}"#);
            let accepted = evaluate(&route, body.as_bytes(), Some(&operation), OBSERVED_AT).unwrap();
            let expected = format!(r#"{{"id":"message-1","internalDate":"{OBSERVED_AT}"}}"#);
            assert_eq!(accepted.released_body_sha256, sha256_prefixed(expected.as_bytes()));
            assert_eq!(accepted.released_body_bytes, expected.len() as u64);
            assert_eq!(evaluate(&route, body.as_bytes(), Some(&operation), OBSERVED_AT + 1)
                .err().expect("generic response age remains bound to observation time")["error"],
                "response_date_window_exceeded");
        }
        let cutoff = OBSERVED_AT - 86_400_000;
        let body = format!(r#"{{"created_at":"{OBSERVED_AT}","id":"message-1","internalDate":"{cutoff}"}}"#);
        evaluate(&route, body.as_bytes(), Some(&operation), OBSERVED_AT).unwrap();
        assert_eq!(evaluate(&route, body.as_bytes(), Some(&operation), OBSERVED_AT + 1)
            .err().expect("Gmail internalDate keeps the same explicit reference")["error"],
            "gmail_response_too_old");
        route.adapter_config["response"]["allowedFields"] = json!([]);
        route.adapter_config["response"]["validateInternalDate"] = json!(false);
        assert_eq!(evaluate(&route, body.as_bytes(), Some(&operation), OBSERVED_AT)
            .err().expect("no projection guard is waived to reach a legacy branch")["error"],
            "response_allowed_fields_invalid");
    }
}

#[cfg(test)]
mod query_explicit_time_tests {
    use super::*;

    const DECISION_AT: u64 = 1_000_000_000_000;

    fn snapshot() -> Arc<Snapshot> {
        // A closed, credentialless route exercises the real pure evaluator;
        // this fixture has no custody, provider or active effect authority.
        let mut snapshot = (*super::super::tests::test_snapshot(1)).clone();
        snapshot.routes[0].adapter_config["request"]["allowedQueryKeys"] = json!(["at"]);
        snapshot.routes[0].constraints.push(json!({
            "id":"query-age","type":"queryDateWindow","parameters":["at"],
            "formats":["epochMillis"],"maxAgeDays":1,"required":true,
            "allowFutureSkewSeconds":1,
        }));
        Arc::new(snapshot)
    }

    fn request(timestamp: u64) -> DecisionRequest {
        DecisionRequest {
            client_ip: Some("127.0.0.1".to_string()),
            method: "GET".to_string(),
            url: format!("https://example.test/resource?at={timestamp}"),
            headers: BTreeMap::new(),
            body: String::new(),
            body_sha256: None,
            forwarded_body_length: None,
            forwarded_body_utf8_valid: None,
            credential_metadata: BTreeMap::new(),
            gmail_proofs: Vec::new(),
            client_request_digest: None,
        }
    }

    fn evaluate_all(
        snapshot: &Arc<Snapshot>,
        request: &DecisionRequest,
        captured_at: u64,
        decision_at: u64,
    ) -> [PolicyEvaluation; 4] {
        let facts = AdmittedRequestFacts::capture(
            request, None, ShadowIngressKind::ForwardedHttp, captured_at, None,
        ).expect("bounded admitted facts");
        let active = PolicyPlanSnapshot::active(snapshot).expect("active projection");
        let candidate = PolicyPlanSnapshot::candidate(snapshot).expect("candidate projection");
        [
            evaluate_policy_plan(&active, &facts,
                PolicyEvaluationContext::active(captured_at, decision_at, None)).unwrap(),
            evaluate_policy_plan_borrowed(&active, request, None, ShadowIngressKind::ForwardedHttp,
                captured_at, PolicyEvaluationContext::active(captured_at, decision_at, None)).unwrap(),
            evaluate_policy_plan(&candidate, &facts,
                PolicyEvaluationContext::candidate(captured_at, decision_at, None, None)).unwrap(),
            evaluate_policy_plan_borrowed(&candidate, request, None, ShadowIngressKind::ForwardedHttp,
                captured_at, PolicyEvaluationContext::candidate(captured_at, decision_at, None, None)).unwrap(),
        ]
    }

    fn assert_denied(evaluation: &PolicyEvaluation, expected: &str) {
        match &evaluation.disposition {
            PureDisposition::Deny { status, reason, payload } => {
                assert_eq!(*status, 403);
                assert_eq!(reason, expected);
                assert_eq!(payload["error"], expected);
            }
            _ => panic!("expected query denial, got {}", evaluation.disposition_label()),
        }
        assert!(evaluation.operation.is_none());
    }

    #[test]
    fn query_date_window_uses_decision_time_in_both_pure_lanes() {
        let snapshot = snapshot();
        let request = request(DECISION_AT - 86_400_000);
        let first = evaluate_all(&snapshot, &request, DECISION_AT - 1000, DECISION_AT);
        let later_capture = evaluate_all(&snapshot, &request, DECISION_AT - 100, DECISION_AT);
        for (original, repeated) in first.iter().zip(later_capture.iter()) {
            assert_eq!(original.disposition_label(), "permit");
            assert_eq!(repeated.disposition_label(), "permit");
            assert_eq!(original.route_id.as_deref(), Some("route:test"));
            assert_eq!(original.operation.as_ref(), Some(&json!({"operation":"generic.read"})));
            assert_eq!(original.semantic_sha256, repeated.semantic_sha256);
        }
        assert_eq!(first[0].semantic_sha256, first[1].semantic_sha256);
        assert_eq!(first[2].semantic_sha256, first[3].semantic_sha256);
        assert!(first[0].active_plan().is_some() && first[0].candidate_plan().is_none());
        assert!(first[2].candidate_plan().is_some() && first[2].active_plan().is_none());
        // Same admitted facts, one millisecond later: neither capture time nor
        // a fresh host-clock read may keep this formerly eligible date valid.
        for evaluation in evaluate_all(&snapshot, &request, DECISION_AT - 1000, DECISION_AT + 1) {
            assert_denied(&evaluation, "query_date_window_exceeded");
        }
    }

    #[test]
    fn query_date_window_future_skew_follows_explicit_decision_time() {
        let snapshot = snapshot();
        let request = request(DECISION_AT + 1000);
        for evaluation in evaluate_all(&snapshot, &request, DECISION_AT - 1000, DECISION_AT) {
            assert_eq!(evaluation.disposition_label(), "permit");
        }
        for evaluation in evaluate_all(&snapshot, &request, DECISION_AT - 1000, DECISION_AT - 1) {
            assert_denied(&evaluation, "query_date_future_denied");
        }
    }
}

#[cfg(test)]
mod principal_explicit_time_tests {
    use super::*;

    const CAPTURED_AT: u64 = 1_000;
    const EXPIRES_AT: u64 = 2_000;
    const TOKEN: &str = "local-explicit-time-selector";

    fn snapshot() -> Arc<Snapshot> {
        // Reuse the real closed generic route fixture. No effect executor,
        // credential store, custody authority or network is installed here.
        let mut snapshot = (*super::super::tests::test_snapshot(1)).clone();
        snapshot.principals[0].source_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
        snapshot.principals[0].proxy_authorization = Some(ProxyAuthorizationPolicy::BearerToken {
            token_sha256: sha256_prefixed(TOKEN.as_bytes()),
            source_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
            expires_at_ms: Some(u128::from(EXPIRES_AT)),
        });
        Arc::new(snapshot)
    }

    fn request(token: &str, client_ip: &str) -> DecisionRequest {
        DecisionRequest {
            client_ip: Some(client_ip.to_string()),
            method: "GET".to_string(),
            url: "https://example.test/resource".to_string(),
            headers: BTreeMap::from([("Proxy-Authorization".to_string(), format!("Bearer {token}"))]),
            body: String::new(),
            body_sha256: None,
            forwarded_body_length: None,
            forwarded_body_utf8_valid: None,
            credential_metadata: BTreeMap::new(),
            gmail_proofs: Vec::new(),
            client_request_digest: None,
        }
    }

    fn evaluate_all(
        snapshot: &Arc<Snapshot>,
        request: &DecisionRequest,
        decision_at: u64,
    ) -> [PolicyEvaluation; 4] {
        let facts = AdmittedRequestFacts::capture(
            request, None, ShadowIngressKind::ForwardedHttp, CAPTURED_AT, None,
        ).expect("actual admitted facts");
        let active = PolicyPlanSnapshot::active(snapshot).expect("active projection");
        let candidate = PolicyPlanSnapshot::candidate(snapshot).expect("candidate projection");
        [
            evaluate_policy_plan(&active, &facts,
                PolicyEvaluationContext::active(CAPTURED_AT, decision_at, None))
                .expect("active captured-facts evaluation"),
            evaluate_policy_plan_borrowed(&active, request, None, ShadowIngressKind::ForwardedHttp,
                CAPTURED_AT, PolicyEvaluationContext::active(CAPTURED_AT, decision_at, None))
                .expect("active borrowed evaluation"),
            evaluate_policy_plan(&candidate, &facts,
                PolicyEvaluationContext::candidate(CAPTURED_AT, decision_at, None, None))
                .expect("candidate captured-facts evaluation"),
            evaluate_policy_plan_borrowed(&candidate, request, None, ShadowIngressKind::ForwardedHttp,
                CAPTURED_AT, PolicyEvaluationContext::candidate(CAPTURED_AT, decision_at, None, None))
                .expect("candidate borrowed evaluation"),
        ]
    }

    fn assert_permitted(evaluation: &PolicyEvaluation) {
        assert_eq!(evaluation.disposition_label(), "permit");
        assert_eq!(evaluation.route_id.as_deref(), Some("route:test"));
        assert_eq!(evaluation.operation.as_ref(), Some(&json!({"operation":"generic.read"})));
        match &evaluation.plan {
            SeparatedPolicyPlan::Active(plan) => assert!(matches!(plan.outcome(), PolicyOutcome::Permit)),
            SeparatedPolicyPlan::Candidate(plan) => assert!(matches!(plan.outcome(), PolicyOutcome::Permit)),
        }
    }

    fn assert_principal_denied(evaluation: &PolicyEvaluation) {
        match &evaluation.disposition {
            PureDisposition::Deny { status, reason, payload } => {
                assert_eq!(*status, 403);
                assert_eq!(reason, "client_principal_denied");
                assert_eq!(payload, &json!({"error":"client_principal_denied","status_code":403}));
            }
            _ => panic!("expected principal denial, got {}", evaluation.disposition_label()),
        }
        assert!(evaluation.route_id.is_none());
        assert!(evaluation.operation.is_none());
    }

    #[test]
    fn principal_matching_uses_historical_explicit_time_in_both_pure_lanes() {
        let snapshot = snapshot();
        let request = request(TOKEN, "127.0.0.1");
        // These fixed historical times deliberately differ from the host
        // clock: the former implicit-clock fallback cannot pass this baseline.
        let first = evaluate_all(&snapshot, &request, EXPIRES_AT - 1);
        let repeated = evaluate_all(&snapshot, &request, EXPIRES_AT - 1);
        for (original, repeat) in first.iter().zip(repeated.iter()) {
            assert_permitted(original);
            assert_permitted(repeat);
            assert_eq!(original.semantic_sha256, repeat.semantic_sha256);
        }
        assert_eq!(first[0].semantic_sha256, first[1].semantic_sha256);
        assert_eq!(first[2].semantic_sha256, first[3].semantic_sha256);
        assert!(first[0].active_plan().is_some() && first[0].candidate_plan().is_none());
        assert!(first[2].candidate_plan().is_some() && first[2].active_plan().is_none());
    }

    #[test]
    fn principal_matching_denies_at_exact_explicit_expiry_not_capture_time() {
        let snapshot = snapshot();
        let request = request(TOKEN, "127.0.0.1");
        for evaluation in evaluate_all(&snapshot, &request, EXPIRES_AT - 1) {
            assert_permitted(&evaluation);
        }
        for decision_at in [EXPIRES_AT, EXPIRES_AT + 1] {
            for evaluation in evaluate_all(&snapshot, &request, decision_at) {
                assert_principal_denied(&evaluation);
            }
        }
    }

    #[test]
    fn principal_explicit_time_keeps_token_and_source_ip_denials() {
        let snapshot = snapshot();
        for evaluation in evaluate_all(&snapshot, &request(TOKEN, "127.0.0.1"), EXPIRES_AT - 1) {
            assert_permitted(&evaluation);
        }
        for invalid in [request("wrong-local-token", "127.0.0.1"), request(TOKEN, "127.0.0.2")] {
            for evaluation in evaluate_all(&snapshot, &invalid, EXPIRES_AT - 1) {
                assert_principal_denied(&evaluation);
            }
        }
    }
}
