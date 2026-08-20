#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::OnceLock;
use time::OffsetDateTime;

use crate::coder_controller_v11::{
    CanonicalControllerRequestV11, CanonicalPreallocationFrameV11,
    FIXED_FRAME_BYTES as V11_FIXED_FRAME_BYTES,
};
use crate::receipt_contract_v12::{
    canonical_json, ed25519_spki_sha256, envelope_digest,
    extract_request_v11_summary, final_trust_observation_digest, h11, h12,
    log_bundle_digest, logged_receipt_bundle_digest, parse_canonical_json,
    parse_rfc3339, pre_final_log_leaf_digest, receipt_body_digest,
    receipt_envelope_digest, replay_identity_digest, sha256_bytes,
    verify_consistency_proof,
    request_admission_digest, trust_generation_bundle_digest,
    verify_envelope_cryptography, verify_inclusion_proof, AuthorityRoleV12,
    AuthorityTrustMaterialV12, AuthorityTrustObservationV12,
    CanonicalRequestAdmissionV12, CanonicalU64, ContractError, DigestHex,
    ExternalWitnessCheckpointV12, FinalTrustObservationV12,
    FinalSettlementArtifactV12, FinalSettlementOutcomeV12,
    LoggedReceiptBundleV12, ReceiptAuthenticationEnvelopeV12, ReceiptV12,
    RequestV11Summary, RequesterTrustMaterialV11, Result,
    TrustGenerationBundleV12,
    VerificationHighWaterV12, VerdictV12, EXTERNAL_WITNESS_DOMAIN, FINAL_VERDICT_DOMAIN,
    FINAL_SETTLEMENT_DOMAIN, CONTROLLER_RECEIVE_DOMAIN,
    MAX_RECEIPT_BYTES, RECEIPT_AUTHENTICATION_DOMAIN,
    RECEIPT_CONTRACT_VERSION, RECEIPT_TREE_HEAD_DOMAIN,
    REQUEST_CONTRACT_VERSION, TRUST_GENERATION_AUTHORIZATION_DOMAIN,
    TRUST_GENERATION_DOMAIN,
};

const REQUEST_SCHEMA_V11: &str =
    include_str!("../../../schemas/coder-test-controller-request.v1.schema.json");
const RECEIPT_SCHEMA_V12: &str =
    include_str!("../../../schemas/coder-test-controller-receipt.v12.schema.json");
static REQUEST_SCHEMA_VALIDATOR_V11:
    OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();
static RECEIPT_SCHEMA_VALIDATOR_V12:
    OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestAuthorityPinV11 {
    pub schema_sha256: DigestHex,
    pub principal_id: String,
    pub key_id: String,
    pub verifying_key_base64url: String,
    pub spki_der_sha256: DigestHex,
    pub physical_private_key_identity_sha256: DigestHex,
    pub key_leaf_sha256: DigestHex,
    pub trust_root_sha256: DigestHex,
    pub trust_revision: CanonicalU64,
    pub non_revocation_root_sha256: DigestHex,
    pub non_revocation_revision: CanonicalU64,
    pub high_water: CanonicalU64,
    pub authorization_high_water: CanonicalU64,
    pub revocation_high_water: CanonicalU64,
    pub valid_from: String,
    pub valid_until: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPinV12 {
    pub role: AuthorityRoleV12,
    pub principal_id: String,
    pub key_id: String,
    pub verifying_key_base64url: String,
    pub spki_der_sha256: DigestHex,
    pub physical_private_key_identity_sha256: DigestHex,
    pub key_authorization_sha256: DigestHex,
    pub authorization_root_sha256: DigestHex,
    pub authorization_revision: CanonicalU64,
    pub revocation_root_sha256: DigestHex,
    pub revocation_revision: CanonicalU64,
    pub high_water: CanonicalU64,
    pub valid_from: String,
    pub valid_until: String,
    pub status: String,
}

impl AuthorityPinV12 {
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.verifying_key_base64url)
            .map_err(|_| ContractError::Invalid("authority key is not base64url"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| ContractError::Invalid("authority key is not 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)?;
        if ed25519_spki_sha256(&key) != self.spki_der_sha256 {
            return Err(ContractError::Invalid("authority pin SPKI mismatch"));
        }
        Ok(key)
    }

    pub fn observation(&self, observed_at: String) -> AuthorityTrustObservationV12 {
        AuthorityTrustObservationV12 {
            role: self.role,
            principal_id: self.principal_id.clone(),
            key_id: self.key_id.clone(),
            spki_der_sha256: self.spki_der_sha256.clone(),
            physical_private_key_identity_sha256: self
                .physical_private_key_identity_sha256
                .clone(),
            key_authorization_sha256: self.key_authorization_sha256.clone(),
            authorization_root_sha256: self.authorization_root_sha256.clone(),
            authorization_revision: self.authorization_revision.clone(),
            revocation_root_sha256: self.revocation_root_sha256.clone(),
            revocation_revision: self.revocation_revision.clone(),
            high_water: self.high_water.clone(),
            observed_at,
            status: self.status.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StrictVerifierPinsV12 {
    pub receipt_v12_schema_sha256: DigestHex,
    pub request_v11: RequestAuthorityPinV11,
    pub controller_ingress: AuthorityPinV12,
    pub receipt_authentication: AuthorityPinV12,
    pub receipt_log: AuthorityPinV12,
    pub external_witness: AuthorityPinV12,
    pub final_verdict: AuthorityPinV12,
    pub trust_root: AuthorityPinV12,
    pub final_settlement: AuthorityPinV12,
    pub current_trust_generation_principal_id: String,
    pub current_trust_generation_key_id: String,
    pub current_trust_generation_spki_der_sha256: DigestHex,
    pub minimum_trust_generation_sequence: CanonicalU64,
    pub minimum_trust_rollback_floor: CanonicalU64,
}

impl StrictVerifierPinsV12 {
    pub fn validate(&self) -> Result<()> {
        if sha256_bytes(RECEIPT_SCHEMA_V12.as_bytes())
            != self.receipt_v12_schema_sha256
        {
            return Err(ContractError::Invalid(
                "receipt-v12 schema source digest differs from pin",
            ));
        }
        require_pin_role(
            &self.controller_ingress,
            AuthorityRoleV12::ControllerIngress,
        )?;
        require_pin_role(
            &self.receipt_authentication,
            AuthorityRoleV12::ReceiptAuthentication,
        )?;
        require_pin_role(&self.receipt_log, AuthorityRoleV12::ReceiptLog)?;
        require_pin_role(
            &self.external_witness,
            AuthorityRoleV12::ExternalWitness,
        )?;
        require_pin_role(&self.final_verdict, AuthorityRoleV12::FinalVerdict)?;
        require_pin_role(&self.trust_root, AuthorityRoleV12::TrustRoot)?;
        require_pin_role(
            &self.final_settlement,
            AuthorityRoleV12::FinalSettlement,
        )?;
        let pins = [
            &self.controller_ingress,
            &self.receipt_authentication,
            &self.receipt_log,
            &self.external_witness,
            &self.final_verdict,
            &self.trust_root,
            &self.final_settlement,
        ];
        for (index, left) in pins.iter().enumerate() {
            left.verifying_key()?;
            for right in pins.iter().skip(index + 1) {
                if left.principal_id == right.principal_id
                    || left.key_id == right.key_id
                    || left.spki_der_sha256 == right.spki_der_sha256
                    || left.physical_private_key_identity_sha256
                        == right.physical_private_key_identity_sha256
                {
                    return Err(ContractError::Invalid(
                        "receipt authority pins are not pairwise distinct",
                    ));
                }
            }
        }
        validate_request_pin(&self.request_v11)?;
        for authority in pins {
            if authority.principal_id == self.request_v11.principal_id
                || authority.key_id == self.request_v11.key_id
                || authority.spki_der_sha256 == self.request_v11.spki_der_sha256
                || authority.physical_private_key_identity_sha256
                    == self.request_v11.physical_private_key_identity_sha256
            {
                return Err(ContractError::Invalid(
                    "requester and receipt authorities are not pairwise distinct",
                ));
            }
        }
        if self.current_trust_generation_principal_id.is_empty()
            || self.current_trust_generation_key_id.is_empty()
            || self.minimum_trust_generation_sequence.get()? == 0
            || self.minimum_trust_rollback_floor.get()?
                > self.minimum_trust_generation_sequence.get()?
        {
            return Err(ContractError::Invalid(
                "current trust-generation policy is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedRequestV11 {
    pub summary: RequestV11Summary,
    pub trust_observation_sha256: DigestHex,
    pub admission_sha256: DigestHex,
    pub requester_principal_id: String,
    pub request_deadline_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedLoggedBundleV12 {
    pub bundle: LoggedReceiptBundleV12,
    pub logged_bundle_sha256: DigestHex,
    pub request: VerifiedRequestV11,
    pub authenticated_at: OffsetDateTime,
    pub tree_issued_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct VerifiedReceiptV12 {
    pub receipt: ReceiptV12,
    pub exact_bytes: Vec<u8>,
    pub next_high_water: VerificationHighWaterV12,
    pub exact_retry: bool,
}

pub fn verify_logged_bundle_v12(
    exact_bytes: &[u8],
    pins: &StrictVerifierPinsV12,
    high_water: &VerificationHighWaterV12,
) -> Result<VerifiedLoggedBundleV12> {
    pins.validate()?;
    let bundle: LoggedReceiptBundleV12 =
        parse_canonical_json(exact_bytes, MAX_RECEIPT_BYTES)?;
    if bundle.contract_version != RECEIPT_CONTRACT_VERSION
        || bundle.request_contract_version != REQUEST_CONTRACT_VERSION
    {
        return Err(ContractError::Invalid("wrong logged-bundle version"));
    }
    verify_root_identity(
        &bundle.receipt_id,
        &bundle.receipt_sequence,
        &bundle.requester_principal_id,
        &bundle.replay_identity.replay_key_sha256,
        &bundle.request_v11_sha256,
        &bundle.request_envelope_sha256,
        &bundle.request_canonical_bytes,
        &bundle.receipt_body,
    )?;
    replay_identity_digest(&bundle.replay_identity)?;

    let request = verify_canonical_request_v11_admission(
        &bundle.request_v11,
        &bundle.request_admission,
        pins,
        false,
    )?;
    if request.summary.request_v11_sha256 != bundle.request_v11_sha256
        || request.summary.request_envelope_sha256
        != bundle.request_envelope_sha256
        || request.summary.request_canonical_bytes
            != bundle.request_canonical_bytes
        || request.admission_sha256 != bundle.request_admission_sha256
        || request.requester_principal_id != bundle.requester_principal_id
    {
        return Err(ContractError::Invalid(
            "logged bundle does not join verified request v11",
        ));
    }

    let (body_sha256, body_bytes) = receipt_body_digest(&bundle.receipt_body)?;
    if body_sha256 != bundle.receipt_body_sha256
        || body_bytes != bundle.receipt_body_canonical_bytes
    {
        return Err(ContractError::Invalid("receipt body digest or length mismatch"));
    }

    let authentication_digest = verify_receipt_authentication_envelope_v12(
        &bundle.receipt_authentication_envelope,
        &pins.receipt_authentication,
    )?;
    if authentication_digest
        != bundle.receipt_authentication_envelope_sha256
    {
        return Err(ContractError::Invalid(
            "receipt authentication envelope digest mismatch",
        ));
    }
    verify_authentication_join(&bundle)?;

    if pre_final_log_leaf_digest(&bundle.pre_final_log_leaf)?
        != bundle.pre_final_log_leaf.leaf_sha256
    {
        return Err(ContractError::Invalid("pre-final log leaf digest mismatch"));
    }
    verify_log_leaf_join(&bundle)?;

    verify_authority_envelope(
        &bundle.signed_tree_head,
        RECEIPT_TREE_HEAD_DOMAIN,
        AuthorityRoleV12::ReceiptLog,
        &pins.receipt_log,
    )?;
    let tree_head_digest = envelope_digest(&bundle.signed_tree_head)?;
    if tree_head_digest != bundle.signed_tree_head_envelope_sha256 {
        return Err(ContractError::Invalid("signed tree-head digest mismatch"));
    }
    if bundle.signed_tree_head.payload.issued_at
        != bundle.signed_tree_head.signature.signed_at
        || bundle.signed_tree_head.payload.issued_at
            != bundle.signed_tree_head.signature.accepted_at
    {
        return Err(ContractError::Invalid(
            "tree-head timestamp is not signature-bound",
        ));
    }
    verify_log_proofs_and_checkpoint(&bundle, high_water)?;

    let authenticated_at = parse_rfc3339(
        &bundle
            .receipt_authentication_envelope
            .payload
            .authenticated_at,
    )?;
    let tree_issued_at =
        parse_rfc3339(&bundle.signed_tree_head.payload.issued_at)?;
    if authenticated_at > tree_issued_at {
        return Err(ContractError::Invalid(
            "tree head predates receipt authentication",
        ));
    }
    if parse_rfc3339(&bundle.receipt_body.completed_at)? > authenticated_at {
        return Err(ContractError::Invalid(
            "receipt body completion follows authentication",
        ));
    }
    let receipt_sequence = bundle.receipt_sequence.get()?;
    if receipt_sequence <= high_water.receipt_sequence.get()? {
        return Err(ContractError::Invalid(
            "new logged bundle does not advance receipt high-water",
        ));
    }

    Ok(VerifiedLoggedBundleV12 {
        logged_bundle_sha256: logged_receipt_bundle_digest(&bundle)?,
        bundle,
        request,
        authenticated_at,
        tree_issued_at,
    })
}

pub fn verify_receipt_v12(
    exact_bytes: &[u8],
    pins: &StrictVerifierPinsV12,
    high_water: &VerificationHighWaterV12,
) -> Result<VerifiedReceiptV12> {
    pins.validate()?;
    let receipt_value: Value =
        parse_canonical_json(exact_bytes, MAX_RECEIPT_BYTES)?;
    receipt_schema_validator_v12()?
        .validate(&receipt_value)
        .map_err(|error| {
            ContractError::InvalidOwned(format!(
                "receipt-v12 schema validation failed at {}: {error}",
                error.instance_path(),
            ))
        })?;
    let receipt: ReceiptV12 = serde_json::from_value(receipt_value)?;
    if receipt.contract_version != RECEIPT_CONTRACT_VERSION
        || receipt.request_contract_version != REQUEST_CONTRACT_VERSION
    {
        return Err(ContractError::Invalid("wrong receipt contract version"));
    }
    verify_trust_generation_bundle(
        &receipt.final_trust_observation.trust_generation,
        pins,
        high_water,
        false,
    )?;
    let receipt_pins = pins_for_generation(
        pins,
        &receipt.final_trust_observation.trust_generation,
    )?;

    let computed_receipt_envelope = receipt_envelope_digest(&receipt)?;
    if computed_receipt_envelope != receipt.receipt_envelope_sha256 {
        return Err(ContractError::Invalid("receipt envelope digest mismatch"));
    }
    if request_admission_digest(&receipt.request_admission)?
        != receipt.request_admission_sha256
    {
        return Err(ContractError::Invalid(
            "receipt request-admission digest mismatch",
        ));
    }
    if receipt.receipt_canonical_bytes.get()? != exact_bytes.len() as u64 {
        return Err(ContractError::Invalid("receipt canonical length mismatch"));
    }

    let sequence = receipt.receipt_sequence.get()?;
    let current_sequence = high_water.receipt_sequence.get()?;
    let exact_retry = sequence == current_sequence
        && receipt.receipt_envelope_sha256
            == high_water.receipt_envelope_sha256;
    if sequence < current_sequence
        || (sequence == current_sequence && !exact_retry)
    {
        return Err(ContractError::Invalid(
            "receipt sequence conflicts with verifier high-water",
        ));
    }

    let logged_bundle = logged_bundle_from_receipt(&receipt);
    let logged_bytes = canonical_json(&logged_bundle, MAX_RECEIPT_BYTES)?;
    let logged = if exact_retry {
        verify_logged_bundle_retry(&logged_bytes, &receipt_pins, high_water)?
    } else {
        verify_logged_bundle_v12(&logged_bytes, &receipt_pins, high_water)?
    };

    verify_external_witness(
        &receipt.external_witness_checkpoint,
        &receipt_pins.external_witness,
        &receipt.signed_tree_head_envelope_sha256,
        &receipt.signed_tree_head.payload.log_id,
        &receipt.signed_tree_head.payload.tree_size,
        &receipt.signed_tree_head.payload.root_sha256,
    )?;
    let witness_digest =
        envelope_digest(&receipt.external_witness_checkpoint)?;
    if witness_digest
        != receipt.external_witness_checkpoint_envelope_sha256
    {
        return Err(ContractError::Invalid(
            "external witness envelope digest mismatch",
        ));
    }
    let witness_payload = &receipt.external_witness_checkpoint.payload;
    if !exact_retry
        && witness_payload.previous_witness_checkpoint_envelope_sha256
            != high_water.witness_checkpoint_envelope_sha256
    {
        return Err(ContractError::Invalid(
            "external witness checkpoint does not extend verifier high-water",
        ));
    }

    let computed_log_bundle = log_bundle_digest(
        &receipt.previous_checkpoint,
        &receipt.pre_final_log_leaf,
        &receipt.signed_tree_head_envelope_sha256,
        &receipt.inclusion_proof,
        &receipt.consistency_proof,
        &receipt.external_witness_checkpoint_envelope_sha256,
    )?;
    if computed_log_bundle != receipt.log_bundle_sha256 {
        return Err(ContractError::Invalid("log bundle digest mismatch"));
    }

    let computed_trust =
        final_trust_observation_digest(&receipt.final_trust_observation)?;
    if computed_trust != receipt.final_trust_observation_sha256 {
        return Err(ContractError::Invalid(
            "final trust observation digest mismatch",
        ));
    }
    let retry_trust_high_water;
    let trust_high_water = if exact_retry {
        retry_trust_high_water = VerificationHighWaterV12 {
            receipt_sequence: receipt
                .final_trust_observation
                .minimum_accepted_receipt_sequence
                .clone(),
            receipt_envelope_sha256: DigestHex::zero(),
            tree_size: receipt.previous_checkpoint.tree_size.clone(),
            tree_root_sha256: receipt.previous_checkpoint.root_sha256.clone(),
            signed_tree_head_envelope_sha256: receipt
                .previous_checkpoint
                .signed_tree_head_envelope_sha256
                .clone(),
            witness_sequence: receipt
                .final_trust_observation
                .minimum_accepted_witness_sequence
                .clone(),
            witness_checkpoint_envelope_sha256: receipt
                .external_witness_checkpoint
                .payload
                .previous_witness_checkpoint_envelope_sha256
                .clone(),
            settlement_sequence: high_water.settlement_sequence.clone(),
            settlement_checkpoint_envelope_sha256: high_water
                .settlement_checkpoint_envelope_sha256
                .clone(),
            trust_generation_sequence: receipt
                .final_trust_observation
                .trust_generation_sequence
                .clone(),
            trust_generation_envelope_sha256: receipt
                .final_trust_observation
                .trust_generation_envelope_sha256
                .clone(),
            trust_rollback_floor: receipt
                .final_trust_observation
                .trust_rollback_floor
                .clone(),
            authorization_high_water: high_water.authorization_high_water.clone(),
            revocation_high_water: high_water.revocation_high_water.clone(),
        };
        &retry_trust_high_water
    } else {
        high_water
    };
    verify_final_trust_observation(
        &receipt.final_trust_observation,
        pins,
        trust_high_water,
        &logged.request,
        &receipt.signed_tree_head_envelope_sha256,
        &receipt.external_witness_checkpoint_envelope_sha256,
    )?;
    if exact_retry
        && (receipt
            .final_trust_observation
            .minimum_accepted_receipt_sequence
            .get()?
            >= receipt.receipt_sequence.get()?
            || receipt
                .final_trust_observation
                .minimum_accepted_tree_size
                != receipt.previous_checkpoint.tree_size
            || receipt
                .external_witness_checkpoint
                .payload
                .witness_sequence
                .get()?
                != receipt
                    .final_trust_observation
                    .minimum_accepted_witness_sequence
                    .get()?
                    .checked_add(1)
                    .ok_or(ContractError::Invalid("witness sequence exhausted"))?)
    {
        return Err(ContractError::Invalid(
            "exact retry does not preserve its predecessor high-water",
        ));
    }

    verify_authority_envelope(
        &receipt.final_verdict_envelope,
        FINAL_VERDICT_DOMAIN,
        AuthorityRoleV12::FinalVerdict,
        &receipt_pins.final_verdict,
    )?;
    let verdict_digest = envelope_digest(&receipt.final_verdict_envelope)?;
    if verdict_digest != receipt.final_verdict_envelope_sha256 {
        return Err(ContractError::Invalid("final verdict digest mismatch"));
    }
    verify_final_verdict_join(&receipt)?;

    let issued_at =
        parse_rfc3339(&receipt.final_verdict_envelope.payload.issued_at)?;
    let observed_at =
        parse_rfc3339(&receipt.final_trust_observation.observed_at)?;
    if issued_at != observed_at {
        return Err(ContractError::Invalid(
            "final verdict is not simultaneous with final trust observation",
        ));
    }
    if logged.authenticated_at > issued_at || logged.tree_issued_at > issued_at {
        return Err(ContractError::Invalid(
            "final verdict predates authenticated receipt evidence",
        ));
    }
    let accepted_times = [
        parse_rfc3339(
            &receipt
                .receipt_authentication_envelope
                .signature
                .accepted_at,
        )?,
        parse_rfc3339(&receipt.signed_tree_head.signature.accepted_at)?,
        parse_rfc3339(
            &receipt
                .external_witness_checkpoint
                .signature
                .accepted_at,
        )?,
    ];
    if accepted_times.iter().any(|accepted| *accepted > observed_at)
        || parse_rfc3339(&receipt.final_verdict_envelope.signature.signed_at)?
            != observed_at
        || parse_rfc3339(&receipt.final_verdict_envelope.signature.accepted_at)?
            != observed_at
    {
        return Err(ContractError::Invalid(
            "signature chronology does not terminate at final trust observation",
        ));
    }

    let witness_sequence = receipt
        .external_witness_checkpoint
        .payload
        .witness_sequence
        .get()?;
    let tree_size = receipt.signed_tree_head.payload.tree_size.get()?;
    if exact_retry {
        if tree_size != high_water.tree_size.get()?
            || receipt.signed_tree_head_envelope_sha256
                != high_water.signed_tree_head_envelope_sha256
            || witness_sequence != high_water.witness_sequence.get()?
            || receipt.external_witness_checkpoint_envelope_sha256
                != high_water.witness_checkpoint_envelope_sha256
        {
            return Err(ContractError::Invalid(
                "exact receipt retry conflicts with verifier checkpoint",
            ));
        }
    } else if tree_size <= high_water.tree_size.get()?
        || witness_sequence
            != high_water
                .witness_sequence
                .get()?
                .checked_add(1)
                .ok_or(ContractError::Invalid("witness sequence exhausted"))?
    {
        return Err(ContractError::Invalid(
            "receipt does not advance tree and witness high-water",
        ));
    }

    let next_high_water = VerificationHighWaterV12 {
        receipt_sequence: receipt.receipt_sequence.clone(),
        receipt_envelope_sha256: receipt.receipt_envelope_sha256.clone(),
        tree_size: receipt.signed_tree_head.payload.tree_size.clone(),
        tree_root_sha256: receipt.signed_tree_head.payload.root_sha256.clone(),
        signed_tree_head_envelope_sha256: receipt
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_sequence: receipt
            .external_witness_checkpoint
            .payload
            .witness_sequence
            .clone(),
        witness_checkpoint_envelope_sha256: receipt
            .external_witness_checkpoint_envelope_sha256
            .clone(),
        settlement_sequence: high_water.settlement_sequence.clone(),
        settlement_checkpoint_envelope_sha256: high_water
            .settlement_checkpoint_envelope_sha256
            .clone(),
        trust_generation_sequence: receipt
            .final_trust_observation
            .trust_generation_sequence
            .clone(),
        trust_generation_envelope_sha256: receipt
            .final_trust_observation
            .trust_generation_envelope_sha256
            .clone(),
        trust_rollback_floor: receipt
            .final_trust_observation
            .trust_rollback_floor
            .clone(),
        authorization_high_water: maximum_authorization_high_water(
            &receipt.final_trust_observation.trust_generation,
        )?,
        revocation_high_water: maximum_revocation_high_water(
            &receipt.final_trust_observation.trust_generation,
        )?,
    };
    Ok(VerifiedReceiptV12 {
        receipt,
        exact_bytes: exact_bytes.to_vec(),
        next_high_water,
        exact_retry,
    })
}

pub fn verify_historical_receipt_v12(
    exact_bytes: &[u8],
    pins: &StrictVerifierPinsV12,
) -> Result<VerifiedReceiptV12> {
    let receipt: ReceiptV12 =
        parse_canonical_json(exact_bytes, MAX_RECEIPT_BYTES)?;
    let predecessor = VerificationHighWaterV12 {
        receipt_sequence: receipt
            .final_trust_observation
            .minimum_accepted_receipt_sequence
            .clone(),
        receipt_envelope_sha256: DigestHex::zero(),
        tree_size: receipt.previous_checkpoint.tree_size.clone(),
        tree_root_sha256: receipt.previous_checkpoint.root_sha256.clone(),
        signed_tree_head_envelope_sha256: receipt
            .previous_checkpoint
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_sequence: receipt
            .final_trust_observation
            .minimum_accepted_witness_sequence
            .clone(),
        witness_checkpoint_envelope_sha256: receipt
            .external_witness_checkpoint
            .payload
            .previous_witness_checkpoint_envelope_sha256
            .clone(),
        settlement_sequence: CanonicalU64::new(0),
        settlement_checkpoint_envelope_sha256: DigestHex::zero(),
        trust_generation_sequence: CanonicalU64::new(
            receipt
                .final_trust_observation
                .trust_generation_sequence
                .get()?
                .saturating_sub(1),
        ),
        trust_generation_envelope_sha256: receipt
            .final_trust_observation
            .trust_generation
            .generation
            .payload
            .previous_generation_envelope_sha256
            .clone(),
        trust_rollback_floor: receipt
            .final_trust_observation
            .trust_rollback_floor
            .clone(),
        authorization_high_water: CanonicalU64::new(0),
        revocation_high_water: CanonicalU64::new(0),
    };
    let verified = verify_receipt_v12(exact_bytes, pins, &predecessor)?;
    if verified.exact_retry {
        return Err(ContractError::Invalid(
            "historical receipt was not verified from its predecessor",
        ));
    }
    Ok(verified)
}

pub fn verify_final_settlement_artifact_v12(
    artifact: &FinalSettlementArtifactV12,
    pins: &StrictVerifierPinsV12,
    predecessor: &VerificationHighWaterV12,
) -> Result<VerificationHighWaterV12> {
    let generation_digest = verify_trust_generation_bundle(
        &artifact.trust_generation,
        pins,
        predecessor,
        false,
    )?;
    let generation_pins = pins_for_generation(pins, &artifact.trust_generation)?;
    verify_authority_envelope(
        &artifact.final_settlement_checkpoint,
        FINAL_SETTLEMENT_DOMAIN,
        AuthorityRoleV12::FinalSettlement,
        &generation_pins.final_settlement,
    )?;
    let checkpoint_digest =
        envelope_digest(&artifact.final_settlement_checkpoint)?;
    if checkpoint_digest
        != artifact.final_settlement_checkpoint_envelope_sha256
    {
        return Err(ContractError::Invalid(
            "final-settlement checkpoint digest mismatch",
        ));
    }
    let logged_bytes =
        canonical_json(&artifact.logged_bundle, MAX_RECEIPT_BYTES)?;
    let verified_logged =
        verify_logged_bundle_v12(&logged_bytes, &generation_pins, predecessor)?;
    verify_external_witness(
        &artifact.external_witness_checkpoint,
        &generation_pins.external_witness,
        &artifact.logged_bundle.signed_tree_head_envelope_sha256,
        &artifact.logged_bundle.signed_tree_head.payload.log_id,
        &artifact.logged_bundle.signed_tree_head.payload.tree_size,
        &artifact.logged_bundle.signed_tree_head.payload.root_sha256,
    )?;
    let witness_digest =
        envelope_digest(&artifact.external_witness_checkpoint)?;
    if artifact
        .external_witness_checkpoint
        .payload
        .previous_witness_checkpoint_envelope_sha256
        != predecessor.witness_checkpoint_envelope_sha256
        || artifact
            .external_witness_checkpoint
            .payload
            .witness_sequence
            .get()?
            != predecessor
                .witness_sequence
                .get()?
                .checked_add(1)
                .ok_or(ContractError::Invalid("witness sequence exhausted"))?
    {
        return Err(ContractError::Invalid(
            "settlement witness does not extend predecessor high-water",
        ));
    }
    let payload = &artifact.final_settlement_checkpoint.payload;
    if payload.outcome != artifact.outcome
        || payload.settlement_sequence.get()?
            != predecessor
                .settlement_sequence
                .get()?
                .checked_add(1)
                .ok_or(ContractError::Invalid("settlement sequence exhausted"))?
        || payload.previous_settlement_checkpoint_envelope_sha256
            != predecessor.settlement_checkpoint_envelope_sha256
        || payload.trust_generation_envelope_sha256 != generation_digest
        || payload.trust_generation_sequence
            != artifact.trust_generation.generation.payload.generation_sequence
        || payload.receipt_id != artifact.logged_bundle.receipt_id
        || payload.receipt_sequence != artifact.logged_bundle.receipt_sequence
        || payload.requester_principal_id
            != artifact.logged_bundle.requester_principal_id
        || payload.replay_key_sha256
            != artifact.logged_bundle.replay_identity.replay_key_sha256
        || payload.request_v11_sha256
            != artifact.logged_bundle.request_v11_sha256
        || payload.pre_final_log_leaf_sha256
            != artifact.logged_bundle.pre_final_log_leaf.leaf_sha256
        || payload.tree_size
            != artifact.logged_bundle.signed_tree_head.payload.tree_size
        || payload.tree_root_sha256
            != artifact.logged_bundle.signed_tree_head.payload.root_sha256
        || payload.signed_tree_head_envelope_sha256
            != artifact.logged_bundle.signed_tree_head_envelope_sha256
        || payload.witness_sequence
            != artifact.external_witness_checkpoint.payload.witness_sequence
        || payload.witness_checkpoint_envelope_sha256 != witness_digest
        || payload.settled_at
            != artifact.final_settlement_checkpoint.signature.signed_at
        || payload.settled_at
            != artifact.final_settlement_checkpoint.signature.accepted_at
    {
        return Err(ContractError::Invalid(
            "final-settlement checkpoint does not extend its predecessor",
        ));
    }
    let mut high_water = predecessor.clone();
    match artifact.outcome {
        FinalSettlementOutcomeV12::Genesis => {
            return Err(ContractError::Invalid(
                "genesis checkpoint is not a finalization artifact",
            ));
        }
        FinalSettlementOutcomeV12::Receipt => {
            let receipt = artifact.receipt.as_ref().ok_or(
                ContractError::Invalid("receipt settlement lacks receipt"),
            )?;
            if artifact.terminal_abort_reason.is_some() {
                return Err(ContractError::Invalid(
                    "receipt settlement carries an abort reason",
                ));
            }
            let exact = canonical_json(receipt, MAX_RECEIPT_BYTES)?;
            let verified = verify_receipt_v12(&exact, pins, predecessor)?;
            if payload.receipt_id != receipt.receipt_id
                || payload.receipt_sequence != receipt.receipt_sequence
                || payload.requester_principal_id
                    != receipt.requester_principal_id
                || payload.replay_key_sha256
                    != receipt.replay_identity.replay_key_sha256
                || payload.request_v11_sha256 != receipt.request_v11_sha256
                || payload.pre_final_log_leaf_sha256
                    != receipt.pre_final_log_leaf.leaf_sha256
                || payload.receipt_envelope_sha256
                    != receipt.receipt_envelope_sha256
                || payload.terminal_abort_reason_sha256 != DigestHex::zero()
                || payload.tree_size != verified.next_high_water.tree_size
                || payload.tree_root_sha256
                    != verified.next_high_water.tree_root_sha256
                || payload.signed_tree_head_envelope_sha256
                    != verified
                        .next_high_water
                        .signed_tree_head_envelope_sha256
                || payload.witness_checkpoint_envelope_sha256
                    != verified
                        .next_high_water
                        .witness_checkpoint_envelope_sha256
                || payload.witness_sequence
                    != verified.next_high_water.witness_sequence
                || logged_bundle_from_receipt(receipt)
                    != artifact.logged_bundle
                || receipt.external_witness_checkpoint
                    != artifact.external_witness_checkpoint
                || receipt.final_trust_observation.trust_generation
                    != artifact.trust_generation
            {
                return Err(ContractError::Invalid(
                    "final settlement does not bind the exact final receipt",
                ));
            }
            high_water = verified.next_high_water;
        }
        FinalSettlementOutcomeV12::TerminalAbort => {
            let reason = artifact.terminal_abort_reason.as_deref().ok_or(
                ContractError::Invalid("terminal abort lacks a reason"),
            )?;
            if artifact.receipt.is_some()
                || reason.is_empty()
                || reason.len() > 1024
                || payload.receipt_envelope_sha256 != DigestHex::zero()
                || payload.terminal_abort_reason_sha256
                    != h12("terminal-abort-reason", &[reason.as_bytes()])
                || payload.pre_final_log_leaf_sha256 == DigestHex::zero()
            {
                return Err(ContractError::Invalid(
                    "terminal-abort settlement binding is invalid",
                ));
            }
            high_water.receipt_sequence =
                verified_logged.bundle.receipt_sequence.clone();
            high_water.receipt_envelope_sha256 = DigestHex::zero();
            high_water.tree_size =
                verified_logged.bundle.signed_tree_head.payload.tree_size.clone();
            high_water.tree_root_sha256 =
                verified_logged.bundle.signed_tree_head.payload.root_sha256.clone();
            high_water.signed_tree_head_envelope_sha256 =
                verified_logged.bundle.signed_tree_head_envelope_sha256.clone();
            high_water.witness_checkpoint_envelope_sha256 =
                witness_digest;
            high_water.witness_sequence = artifact
                .external_witness_checkpoint
                .payload
                .witness_sequence
                .clone();
        }
    }
    high_water.settlement_sequence = payload.settlement_sequence.clone();
    high_water.settlement_checkpoint_envelope_sha256 = checkpoint_digest;
    high_water.trust_generation_sequence =
        payload.trust_generation_sequence.clone();
    high_water.trust_generation_envelope_sha256 = generation_digest;
    high_water.trust_rollback_floor =
        artifact.trust_generation.generation.payload.rollback_floor.clone();
    high_water.authorization_high_water =
        maximum_authorization_high_water(&artifact.trust_generation)?;
    high_water.revocation_high_water =
        maximum_revocation_high_water(&artifact.trust_generation)?;
    Ok(high_water)
}

pub fn verify_genesis_final_settlement_anchor_v12(
    checkpoint: &crate::receipt_contract_v12::FinalSettlementCheckpointV12,
    pins: &StrictVerifierPinsV12,
) -> Result<VerificationHighWaterV12> {
    pins.validate()?;
    verify_authority_envelope(
        checkpoint,
        FINAL_SETTLEMENT_DOMAIN,
        AuthorityRoleV12::FinalSettlement,
        &pins.final_settlement,
    )?;
    let payload = &checkpoint.payload;
    if payload.outcome != FinalSettlementOutcomeV12::Genesis
        || payload.receipt_id != "serverware:genesis"
        || payload.requester_principal_id != "serverware:genesis"
        || payload.receipt_sequence.get()? != 0
        || payload.replay_key_sha256 != DigestHex::zero()
        || payload.request_v11_sha256 != DigestHex::zero()
        || payload.pre_final_log_leaf_sha256 != DigestHex::zero()
        || payload.settlement_sequence.get()? != 0
        || payload.tree_size.get()? != 0
        || payload.witness_sequence.get()? != 0
        || payload.receipt_envelope_sha256 != DigestHex::zero()
        || payload.terminal_abort_reason_sha256 != DigestHex::zero()
        || payload.previous_settlement_checkpoint_envelope_sha256
            != DigestHex::zero()
        || payload.tree_root_sha256
            != VerificationHighWaterV12::genesis().tree_root_sha256
        || payload.signed_tree_head_envelope_sha256 != DigestHex::zero()
        || payload.witness_checkpoint_envelope_sha256 != DigestHex::zero()
        || payload.trust_generation_envelope_sha256 != DigestHex::zero()
        || payload.trust_generation_sequence.get()? != 0
    {
        return Err(ContractError::Invalid(
            "external final-settlement genesis anchor is invalid",
        ));
    }
    let mut high_water = VerificationHighWaterV12::genesis();
    high_water.settlement_checkpoint_envelope_sha256 =
        envelope_digest(checkpoint)?;
    Ok(high_water)
}

pub fn build_final_trust_observation(
    trust_generation: TrustGenerationBundleV12,
    pins: &StrictVerifierPinsV12,
    high_water: &VerificationHighWaterV12,
    request_trust_observation_sha256: DigestHex,
    body_trust_observation_sha256: DigestHex,
    signed_tree_head_envelope_sha256: DigestHex,
    external_witness_checkpoint_envelope_sha256: DigestHex,
    observed_at: String,
) -> Result<FinalTrustObservationV12> {
    let generation_digest =
        verify_trust_generation_bundle(&trust_generation, pins, high_water, true)?;
    parse_rfc3339(&observed_at)?;
    let generation = &trust_generation.generation.payload;
    Ok(FinalTrustObservationV12 {
        trust_generation_envelope_sha256: generation_digest,
        trust_generation_sequence: generation.generation_sequence.clone(),
        trust_rollback_floor: generation.rollback_floor.clone(),
        controller_ingress_authority: material_observation(
            &generation.controller_ingress,
            observed_at.clone(),
        ),
        receipt_authentication_authority: material_observation(
            &generation.receipt_authentication,
            observed_at.clone(),
        ),
        receipt_log_authority: material_observation(
            &generation.receipt_log,
            observed_at.clone(),
        ),
        external_witness_authority: material_observation(
            &generation.external_witness,
            observed_at.clone(),
        ),
        final_verdict_authority: material_observation(
            &generation.final_verdict,
            observed_at.clone(),
        ),
        final_settlement_authority: material_observation(
            &generation.final_settlement,
            observed_at.clone(),
        ),
        trust_generation,
        receipt_schema_sha256: pins.receipt_v12_schema_sha256.clone(),
        request_trust_observation_sha256,
        body_trust_observation_sha256,
        signed_tree_head_envelope_sha256,
        external_witness_checkpoint_envelope_sha256,
        minimum_accepted_receipt_sequence: high_water.receipt_sequence.clone(),
        minimum_accepted_tree_size: high_water.tree_size.clone(),
        minimum_accepted_witness_sequence: high_water.witness_sequence.clone(),
        observed_at,
    })
}

pub fn verify_trust_generation_bundle(
    bundle: &TrustGenerationBundleV12,
    pins: &StrictVerifierPinsV12,
    high_water: &VerificationHighWaterV12,
    require_current_policy: bool,
) -> Result<DigestHex> {
    pins.validate()?;
    verify_authority_envelope(
        &bundle.authorization_chain,
        TRUST_GENERATION_AUTHORIZATION_DOMAIN,
        AuthorityRoleV12::TrustRoot,
        &pins.trust_root,
    )?;
    let chain_digest = envelope_digest(&bundle.authorization_chain)?;
    if chain_digest != bundle.authorization_chain_envelope_sha256 {
        return Err(ContractError::Invalid(
            "trust-generation authorization-chain digest mismatch",
        ));
    }
    let authorization = &bundle.authorization_chain.payload;
    let generation = &bundle.generation;
    let generation_payload = &generation.payload;
    let generation_sequence = generation_payload.generation_sequence.get()?;
    let generation_key = verifying_key_from_base64(
        &authorization.generation_verifying_key_base64url,
        &authorization.generation_spki_der_sha256,
    )?;
    verify_envelope_cryptography(
        generation,
        TRUST_GENERATION_DOMAIN,
        AuthorityRoleV12::TrustGeneration,
        &generation_key,
    )?;
    let generation_digest = envelope_digest(generation)?;
    if generation_digest != bundle.generation_envelope_sha256
        || generation_payload.authorization_chain_envelope_sha256
            != bundle.authorization_chain_envelope_sha256
        || generation.signature.signer_principal_id
            != authorization.generation_principal_id
        || generation.signature.signer_key_id != authorization.generation_key_id
        || generation.signature.signer_spki_der_sha256
            != authorization.generation_spki_der_sha256
        || generation.signature
            .key_authorization
            .physical_private_key_identity_sha256
            != authorization.generation_physical_private_key_identity_sha256
        || generation_sequence < authorization.minimum_generation_sequence.get()?
        || generation_sequence > authorization.maximum_generation_sequence.get()?
        || generation_payload.rollback_floor.get()? > generation_sequence
    {
        return Err(ContractError::Invalid(
            "trust generation does not join its retained signed authorization",
        ));
    }
    let generated_at = parse_rfc3339(&generation_payload.generated_at)?;
    if generation_payload.generated_at != generation.signature.signed_at
        || generation_payload.generated_at != generation.signature.accepted_at
        || generated_at < parse_rfc3339(&authorization.valid_from)?
        || generated_at > parse_rfc3339(&authorization.valid_until)?
    {
        return Err(ContractError::Invalid(
            "trust generation is outside its signed validity interval",
        ));
    }
    if generation_payload.request_v11_schema_sha256
        != pins.request_v11.schema_sha256
        || generation_payload.receipt_v12_schema_sha256
            != pins.receipt_v12_schema_sha256
    {
        return Err(ContractError::Invalid(
            "trust generation selects a different request or receipt schema",
        ));
    }
    verify_generation_roles_and_uniqueness(generation_payload, pins)?;
    let previous_sequence = high_water.trust_generation_sequence.get()?;
    let exact_generation_retry = generation_sequence == previous_sequence
        && generation_digest == high_water.trust_generation_envelope_sha256;
    if (!exact_generation_retry && generation_sequence <= previous_sequence)
        || generation_payload.rollback_floor.get()? < high_water.trust_rollback_floor.get()?
        || (!exact_generation_retry
            && previous_sequence != 0
            && generation_payload.previous_generation_envelope_sha256
                != high_water.trust_generation_envelope_sha256)
        || maximum_authorization_high_water(bundle)?.get()?
            < high_water.authorization_high_water.get()?
        || maximum_revocation_high_water(bundle)?.get()?
            < high_water.revocation_high_water.get()?
    {
        return Err(ContractError::Invalid(
            "trust generation rolls back or mixes verifier trust state",
        ));
    }
    if require_current_policy
        && (authorization.generation_principal_id
            != pins.current_trust_generation_principal_id
            || authorization.generation_key_id
                != pins.current_trust_generation_key_id
            || authorization.generation_spki_der_sha256
                != pins.current_trust_generation_spki_der_sha256
            || generation_sequence < pins.minimum_trust_generation_sequence.get()?
            || generation_payload.rollback_floor.get()?
                < pins.minimum_trust_rollback_floor.get()?)
    {
        return Err(ContractError::Invalid(
            "trust generation is not authorized by current issuance policy",
        ));
    }
    if require_current_policy {
        require_requester_material_matches_pin(
            &generation_payload.requester,
            &pins.request_v11,
        )?;
        for (material, pin) in [
            (&generation_payload.controller_ingress, &pins.controller_ingress),
            (
                &generation_payload.receipt_authentication,
                &pins.receipt_authentication,
            ),
            (&generation_payload.receipt_log, &pins.receipt_log),
            (&generation_payload.external_witness, &pins.external_witness),
            (&generation_payload.final_verdict, &pins.final_verdict),
            (&generation_payload.final_settlement, &pins.final_settlement),
        ] {
            require_material_matches_pin(material, pin)?;
        }
    }
    if trust_generation_bundle_digest(bundle)? == DigestHex::zero() {
        return Err(ContractError::Invalid("trust-generation bundle digest is zero"));
    }
    Ok(generation_digest)
}

pub fn verify_receipt_authentication_envelope_v12(
    envelope: &ReceiptAuthenticationEnvelopeV12,
    pin: &AuthorityPinV12,
) -> Result<DigestHex> {
    verify_authority_envelope(
        envelope,
        RECEIPT_AUTHENTICATION_DOMAIN,
        AuthorityRoleV12::ReceiptAuthentication,
        pin,
    )?;
    if envelope.payload.authenticated_at != envelope.signature.signed_at
        || envelope.payload.authenticated_at != envelope.signature.accepted_at
    {
        return Err(ContractError::Invalid(
            "receipt authentication timestamp is not signature-bound",
        ));
    }
    envelope_digest(envelope)
}

fn verify_logged_bundle_retry(
    exact_bytes: &[u8],
    pins: &StrictVerifierPinsV12,
    high_water: &VerificationHighWaterV12,
) -> Result<VerifiedLoggedBundleV12> {
    let bundle: LoggedReceiptBundleV12 =
        parse_canonical_json(exact_bytes, MAX_RECEIPT_BYTES)?;
    let lowered = VerificationHighWaterV12 {
        receipt_sequence: CanonicalU64::new(
            high_water.receipt_sequence.get()?.saturating_sub(1),
        ),
        receipt_envelope_sha256: DigestHex::zero(),
        tree_size: bundle.previous_checkpoint.tree_size.clone(),
        tree_root_sha256: bundle.previous_checkpoint.root_sha256.clone(),
        signed_tree_head_envelope_sha256: bundle
            .previous_checkpoint
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_sequence: CanonicalU64::new(
            high_water.witness_sequence.get()?.saturating_sub(1),
        ),
        witness_checkpoint_envelope_sha256: DigestHex::zero(),
        settlement_sequence: high_water.settlement_sequence.clone(),
        settlement_checkpoint_envelope_sha256: high_water
            .settlement_checkpoint_envelope_sha256
            .clone(),
        trust_generation_sequence: high_water.trust_generation_sequence.clone(),
        trust_generation_envelope_sha256: high_water
            .trust_generation_envelope_sha256
            .clone(),
        trust_rollback_floor: high_water.trust_rollback_floor.clone(),
        authorization_high_water: high_water.authorization_high_water.clone(),
        revocation_high_water: high_water.revocation_high_water.clone(),
    };
    verify_logged_bundle_v12(exact_bytes, pins, &lowered)
}

pub fn verify_canonical_request_v11_admission(
    request_projection: &Value,
    admission: &CanonicalRequestAdmissionV12,
    pins: &StrictVerifierPinsV12,
    require_live_deadline: bool,
) -> Result<VerifiedRequestV11> {
    pins.validate()?;
    let exact_request = URL_SAFE_NO_PAD
        .decode(&admission.exact_request_base64url)
        .map_err(|_| ContractError::Invalid("exact v11 request is not base64url"))?;
    let frame_bytes = URL_SAFE_NO_PAD
        .decode(&admission.preallocation_frame_base64url)
        .map_err(|_| ContractError::Invalid("v11 preallocation frame is not base64url"))?;
    let frame_bytes: [u8; V11_FIXED_FRAME_BYTES] = frame_bytes
        .try_into()
        .map_err(|_| ContractError::Invalid("v11 preallocation frame is not 256 bytes"))?;
    let frame = CanonicalPreallocationFrameV11::decode(&frame_bytes)
        .map_err(|error| ContractError::InvalidOwned(format!(
            "canonical v11 frame rejected: {error}"
        )))?;
    let request_key = request_verifying_key(&pins.request_v11)?;
    let canonical = CanonicalControllerRequestV11::parse_and_verify(
        exact_request.clone(),
        &frame,
        &request_key,
        pins.request_v11.spki_der_sha256.decode()?,
        Some(&admission.trusted_receive_envelope.payload.accepted_at),
    )
    .map_err(|error| ContractError::InvalidOwned(format!(
        "canonical v11 request rejected: {error}"
    )))?;
    if canonical.root() != request_projection {
        return Err(ContractError::Invalid(
            "request projection differs from exact canonical v11 bytes",
        ));
    }
    let summary = extract_request_v11_summary(canonical.root())?;
    let observation = &admission.trusted_receive_envelope;
    verify_authority_envelope(
        observation,
        CONTROLLER_RECEIVE_DOMAIN,
        AuthorityRoleV12::ControllerIngress,
        &pins.controller_ingress,
    )?;
    let observation_digest = envelope_digest(observation)?;
    if observation_digest != admission.trusted_receive_envelope_sha256 {
        return Err(ContractError::Invalid(
            "trusted receive envelope digest mismatch",
        ));
    }
    let received = &observation.payload;
    frame
        .verify_receive_deadline(received.frame_received_at_unix_ms.get()?)
        .map_err(|error| ContractError::InvalidOwned(format!(
            "trusted v11 receive time rejected: {error}"
        )))?;
    let requester_authorization_sha256 =
        request_authorization_digest_v11(&pins.request_v11)?;
    let verifier_profile_sha256 = canonical_v11_verifier_profile_sha256(
        &pins.request_v11.schema_sha256,
    )?;
    let verified_relationships_sha256 = h12(
        "canonical-v11-verified-relationships",
        &[
            &summary.request_v11_sha256.decode()?,
            &summary.request_envelope_sha256.decode()?,
            &requester_authorization_sha256.decode()?,
            &verifier_profile_sha256.decode()?,
            &received.controller_configuration_sha256.decode()?,
        ],
    );
    if received.request_v11_sha256 != summary.request_v11_sha256
        || received.request_envelope_sha256 != summary.request_envelope_sha256
        || received.request_canonical_bytes != summary.request_canonical_bytes
        || received.preallocation_frame_sha256
            != DigestHex::parse(hex_digest(frame.frame_sha256))?
        || received.request_deadline_unix_ms.get()? != canonical.deadline_unix_ms
        || received.requester_key_leaf_sha256
            != pins.request_v11.key_leaf_sha256
        || received.requester_authorization_sha256
            != requester_authorization_sha256
        || received.requester_authorization_high_water
            != pins.request_v11.authorization_high_water
        || received.requester_revocation_high_water
            != pins.request_v11.revocation_high_water
        || received.canonical_verifier_profile_sha256
            != verifier_profile_sha256
        || received.verified_relationships_sha256
            != verified_relationships_sha256
        || received.accepted_at != canonical.accepted_at
    {
        return Err(ContractError::Invalid(
            "trusted receive observation does not join canonical v11 verification",
        ));
    }
    if received.frame_received_boottime_ns.get()? == 0
        || received.boot_id_sha256
            != crate::receipt_contract_v12::boot_id_sha256_v12()?
    {
        return Err(ContractError::Invalid(
            "trusted receive observation lacks current-boot CLOCK_BOOTTIME binding",
        ));
    }
    if require_live_deadline {
        let now_unix_ms = u64::try_from(
            OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
        )
        .map_err(|_| ContractError::Invalid("authority wall clock is before epoch"))?;
        if now_unix_ms > canonical.deadline_unix_ms {
            return Err(ContractError::Invalid(
                "canonical v11 absolute request deadline expired",
            ));
        }
    }
    let trust_observation_sha256 = h12(
        "verified-request-v11",
        &[
            &pins.request_v11.schema_sha256.decode()?,
            &summary.request_v11_sha256.decode()?,
            &summary.request_envelope_sha256.decode()?,
            summary.request_canonical_bytes.as_str().as_bytes(),
            &admission.trusted_receive_envelope_sha256.decode()?,
            &requester_authorization_sha256.decode()?,
            pins.request_v11.authorization_high_water.as_str().as_bytes(),
            pins.request_v11.revocation_high_water.as_str().as_bytes(),
        ],
    );
    Ok(VerifiedRequestV11 {
        summary,
        trust_observation_sha256,
        admission_sha256: request_admission_digest(admission)?,
        requester_principal_id: pins.request_v11.principal_id.clone(),
        request_deadline_unix_ms: canonical.deadline_unix_ms,
    })
}

fn canonical_v11_verifier_profile_sha256(
    schema_sha256: &DigestHex,
) -> Result<DigestHex> {
    Ok(h12(
        "canonical-v11-verifier-profile",
        &[
            &schema_sha256.decode()?,
            b"fixed-preallocation-frame;exact-canonical-request;request-envelope;replay-identity;trusted-receive;absolute-deadline;current-requester-authorization;current-requester-non-revocation;authority-snapshot;plan-root;final-checkpoint;immutable-evidence;state-quorum;state-epoch-floor;witness-admin;bounded-retrieval;atomic-replay-cas;pipeline-continuity",
        ],
    ))
}

fn request_authorization_digest_v11(
    pin: &RequestAuthorityPinV11,
) -> Result<DigestHex> {
    Ok(h12(
        "current-requester-authorization-v11",
        &[
            pin.principal_id.as_bytes(),
            pin.key_id.as_bytes(),
            &pin.key_leaf_sha256.decode()?,
            &pin.trust_root_sha256.decode()?,
            pin.trust_revision.as_str().as_bytes(),
            &pin.non_revocation_root_sha256.decode()?,
            pin.non_revocation_revision.as_str().as_bytes(),
            pin.authorization_high_water.as_str().as_bytes(),
            pin.revocation_high_water.as_str().as_bytes(),
        ],
    ))
}

fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn verify_authentication_join(bundle: &LoggedReceiptBundleV12) -> Result<()> {
    let payload = &bundle.receipt_authentication_envelope.payload;
    if payload.receipt_id != bundle.receipt_id
        || payload.receipt_sequence != bundle.receipt_sequence
        || payload.requester_principal_id != bundle.requester_principal_id
        || payload.replay_key_sha256
            != bundle.replay_identity.replay_key_sha256
        || payload.request_v11_sha256 != bundle.request_v11_sha256
        || payload.request_envelope_sha256 != bundle.request_envelope_sha256
        || payload.request_canonical_bytes != bundle.request_canonical_bytes
        || payload.receipt_body_sha256 != bundle.receipt_body_sha256
        || payload.receipt_body_canonical_bytes
            != bundle.receipt_body_canonical_bytes
        || payload.terminal_evidence_root_sha256
            != bundle.receipt_body.terminal_evidence_root_sha256
        || payload.terminal_state_root_sha256
            != bundle.receipt_body.terminal_state_root_sha256
        || payload.body_trust_observation_sha256
            != bundle.receipt_body.body_trust_observation_sha256
    {
        return Err(ContractError::Invalid(
            "receipt authentication component splicing detected",
        ));
    }
    Ok(())
}

fn verify_log_leaf_join(bundle: &LoggedReceiptBundleV12) -> Result<()> {
    let leaf = &bundle.pre_final_log_leaf;
    if leaf.receipt_id != bundle.receipt_id
        || leaf.receipt_sequence != bundle.receipt_sequence
        || leaf.requester_principal_id != bundle.requester_principal_id
        || leaf.replay_key_sha256 != bundle.replay_identity.replay_key_sha256
        || leaf.request_v11_sha256 != bundle.request_v11_sha256
        || leaf.request_envelope_sha256 != bundle.request_envelope_sha256
        || leaf.receipt_body_sha256 != bundle.receipt_body_sha256
        || leaf.receipt_authentication_envelope_sha256
            != bundle.receipt_authentication_envelope_sha256
        || leaf.terminal_evidence_root_sha256
            != bundle.receipt_body.terminal_evidence_root_sha256
        || leaf.terminal_state_root_sha256
            != bundle.receipt_body.terminal_state_root_sha256
    {
        return Err(ContractError::Invalid(
            "pre-final log leaf component splicing detected",
        ));
    }
    Ok(())
}

fn verify_log_proofs_and_checkpoint(
    bundle: &LoggedReceiptBundleV12,
    high_water: &VerificationHighWaterV12,
) -> Result<()> {
    verify_inclusion_proof(&bundle.inclusion_proof)?;
    verify_consistency_proof(&bundle.consistency_proof)?;
    let head = &bundle.signed_tree_head.payload;
    let leaf = &bundle.pre_final_log_leaf;
    if head.log_id != leaf.log_id
        || head.latest_leaf_sha256 != leaf.leaf_sha256
        || head.latest_receipt_sequence != bundle.receipt_sequence
        || head.tree_size != bundle.inclusion_proof.tree_size
        || head.root_sha256 != bundle.inclusion_proof.root_sha256
        || leaf.leaf_ordinal != bundle.inclusion_proof.leaf_ordinal
        || leaf.leaf_sha256 != bundle.inclusion_proof.leaf_sha256
        || head.tree_size != bundle.consistency_proof.to_tree_size
        || head.root_sha256 != bundle.consistency_proof.to_root_sha256
        || bundle.previous_checkpoint.tree_size
            != bundle.consistency_proof.from_tree_size
        || bundle.previous_checkpoint.root_sha256
            != bundle.consistency_proof.from_root_sha256
        || head.previous_signed_tree_head_envelope_sha256
            != bundle
                .previous_checkpoint
                .signed_tree_head_envelope_sha256
    {
        return Err(ContractError::Invalid(
            "tree head, leaf, and Merkle proofs do not join",
        ));
    }
    if leaf.leaf_ordinal.get()? + 1 != head.tree_size.get()? {
        return Err(ContractError::Invalid(
            "pre-final receipt leaf is not the signed head's final leaf",
        ));
    }
    if leaf.leaf_ordinal.get()? != bundle.previous_checkpoint.tree_size.get()?
        || head.tree_size.get()?
            != bundle
                .previous_checkpoint
                .tree_size
                .get()?
                .checked_add(1)
                .ok_or(ContractError::Invalid("receipt tree size exhausted"))?
        || head.checkpoint_sequence != head.tree_size
    {
        return Err(ContractError::Invalid(
            "signed tree head is not the immediate one-leaf successor",
        ));
    }
    match bundle.previous_checkpoint.checkpoint_kind {
        crate::receipt_contract_v12::CheckpointKindV12::Genesis => {
            if bundle.previous_checkpoint.tree_size.get()? != 0
                || bundle
                    .previous_checkpoint
                    .signed_tree_head_envelope_sha256
                    != DigestHex::zero()
                || bundle.previous_checkpoint.root_sha256
                    != h12(
                        "merkle-empty",
                        &[crate::receipt_contract_v12::RECEIPT_LOG_TREE_DOMAIN.as_bytes()],
                    )
            {
                return Err(ContractError::Invalid(
                    "invalid genesis receipt checkpoint",
                ));
            }
        }
        crate::receipt_contract_v12::CheckpointKindV12::SignedTreeHead => {
            if bundle.previous_checkpoint.tree_size.get()? == 0
                || bundle
                    .previous_checkpoint
                    .signed_tree_head_envelope_sha256
                    == DigestHex::zero()
            {
                return Err(ContractError::Invalid(
                    "invalid non-genesis receipt checkpoint",
                ));
            }
        }
    }
    if bundle.previous_checkpoint.tree_size != high_water.tree_size
        || bundle.previous_checkpoint.root_sha256
            != high_water.tree_root_sha256
        || bundle
            .previous_checkpoint
            .signed_tree_head_envelope_sha256
            != high_water.signed_tree_head_envelope_sha256
    {
        return Err(ContractError::Invalid(
            "previous checkpoint does not equal verifier high-water",
        ));
    }
    Ok(())
}

fn verify_external_witness(
    witness: &ExternalWitnessCheckpointV12,
    pin: &AuthorityPinV12,
    tree_head_digest: &DigestHex,
    log_id: &str,
    tree_size: &CanonicalU64,
    root_sha256: &DigestHex,
) -> Result<()> {
    verify_authority_envelope(
        witness,
        EXTERNAL_WITNESS_DOMAIN,
        AuthorityRoleV12::ExternalWitness,
        pin,
    )?;
    if witness.payload.signed_tree_head_envelope_sha256 != *tree_head_digest
        || witness.payload.log_id != log_id
        || witness.payload.tree_size != *tree_size
        || witness.payload.root_sha256 != *root_sha256
    {
        return Err(ContractError::Invalid(
            "external witness does not bind the exact signed tree head",
        ));
    }
    if witness.payload.observed_at != witness.signature.signed_at
        || witness.payload.observed_at != witness.signature.accepted_at
    {
        return Err(ContractError::Invalid(
            "external-witness timestamp is not signature-bound",
        ));
    }
    Ok(())
}

fn verify_final_trust_observation(
    observation: &FinalTrustObservationV12,
    pins: &StrictVerifierPinsV12,
    high_water: &VerificationHighWaterV12,
    request: &VerifiedRequestV11,
    tree_head_digest: &DigestHex,
    witness_digest: &DigestHex,
) -> Result<()> {
    let generation_digest = verify_trust_generation_bundle(
        &observation.trust_generation,
        pins,
        high_water,
        false,
    )?;
    let generation = &observation.trust_generation.generation.payload;
    require_material_observation(
        &observation.controller_ingress_authority,
        &generation.controller_ingress,
        &observation.observed_at,
    )?;
    require_material_observation(
        &observation.receipt_authentication_authority,
        &generation.receipt_authentication,
        &observation.observed_at,
    )?;
    require_material_observation(
        &observation.receipt_log_authority,
        &generation.receipt_log,
        &observation.observed_at,
    )?;
    require_material_observation(
        &observation.external_witness_authority,
        &generation.external_witness,
        &observation.observed_at,
    )?;
    require_material_observation(
        &observation.final_verdict_authority,
        &generation.final_verdict,
        &observation.observed_at,
    )?;
    require_material_observation(
        &observation.final_settlement_authority,
        &generation.final_settlement,
        &observation.observed_at,
    )?;
    if observation.trust_generation_envelope_sha256 != generation_digest
        || observation.trust_generation_envelope_sha256
            != observation.trust_generation.generation_envelope_sha256
        || observation.trust_generation_sequence != generation.generation_sequence
        || observation.trust_rollback_floor != generation.rollback_floor
        || observation.request_trust_observation_sha256
        != request.trust_observation_sha256
        || observation.receipt_schema_sha256
            != pins.receipt_v12_schema_sha256
        || observation.signed_tree_head_envelope_sha256 != *tree_head_digest
        || observation.external_witness_checkpoint_envelope_sha256
            != *witness_digest
        || observation.minimum_accepted_receipt_sequence
            != high_water.receipt_sequence
        || observation.minimum_accepted_tree_size != high_water.tree_size
        || observation.minimum_accepted_witness_sequence
            != high_water.witness_sequence
    {
        return Err(ContractError::Invalid(
            "final trust observation does not join current verifier state",
        ));
    }
    Ok(())
}

fn verify_final_verdict_join(receipt: &ReceiptV12) -> Result<()> {
    let payload = &receipt.final_verdict_envelope.payload;
    if payload.receipt_id != receipt.receipt_id
        || payload.receipt_sequence != receipt.receipt_sequence
        || payload.requester_principal_id != receipt.requester_principal_id
        || payload.replay_key_sha256 != receipt.replay_identity.replay_key_sha256
        || payload.request_v11_sha256 != receipt.request_v11_sha256
        || payload.request_envelope_sha256 != receipt.request_envelope_sha256
        || payload.request_canonical_bytes != receipt.request_canonical_bytes
        || payload.receipt_body_sha256 != receipt.receipt_body_sha256
        || payload.receipt_body_canonical_bytes
            != receipt.receipt_body_canonical_bytes
        || payload.terminal_evidence_root_sha256
            != receipt.receipt_body.terminal_evidence_root_sha256
        || payload.terminal_state_root_sha256
            != receipt.receipt_body.terminal_state_root_sha256
        || payload.receipt_authentication_envelope_sha256
            != receipt.receipt_authentication_envelope_sha256
        || payload.signed_tree_head_envelope_sha256
            != receipt.signed_tree_head_envelope_sha256
        || payload.external_witness_checkpoint_envelope_sha256
            != receipt.external_witness_checkpoint_envelope_sha256
        || payload.log_bundle_sha256 != receipt.log_bundle_sha256
        || payload.final_trust_observation_sha256
            != receipt.final_trust_observation_sha256
        || payload.tree_size != receipt.signed_tree_head.payload.tree_size
        || payload.tree_root_sha256
            != receipt.signed_tree_head.payload.root_sha256
        || payload.verdict != receipt.receipt_body.verdict
        || receipt.final_trust_observation.body_trust_observation_sha256
            != receipt.receipt_body.body_trust_observation_sha256
    {
        return Err(ContractError::Invalid(
            "final-verdict component splicing detected",
        ));
    }
    Ok(())
}

fn verify_root_identity(
    receipt_id: &str,
    receipt_sequence: &CanonicalU64,
    requester_principal_id: &str,
    replay_key_sha256: &DigestHex,
    request_v11_sha256: &DigestHex,
    request_envelope_sha256: &DigestHex,
    request_canonical_bytes: &CanonicalU64,
    body: &crate::receipt_contract_v12::ReceiptBodyV12,
) -> Result<()> {
    crate::receipt_contract_v12::validate_identifier(receipt_id)?;
    crate::receipt_contract_v12::validate_identifier(requester_principal_id)?;
    if receipt_sequence.get()? == 0
        || body.receipt_id != receipt_id
        || body.receipt_sequence != *receipt_sequence
        || body.requester_principal_id != requester_principal_id
        || body.replay_key_sha256 != *replay_key_sha256
        || body.request_v11_sha256 != *request_v11_sha256
        || body.request_envelope_sha256 != *request_envelope_sha256
        || body.request_canonical_bytes != *request_canonical_bytes
    {
        return Err(ContractError::Invalid(
            "receipt root and body identities do not join",
        ));
    }
    Ok(())
}

fn verify_authority_envelope<T: Serialize>(
    envelope: &crate::receipt_contract_v12::SignedEnvelopeV12<T>,
    domain: &str,
    role: AuthorityRoleV12,
    pin: &AuthorityPinV12,
) -> Result<()> {
    require_pin_role(pin, role)?;
    let authorization = &envelope.signature.key_authorization;
    if envelope.signature.signer_principal_id != pin.principal_id
        || envelope.signature.signer_key_id != pin.key_id
        || envelope.signature.signer_spki_der_sha256 != pin.spki_der_sha256
        || authorization.role != pin.role
        || authorization.principal_id != pin.principal_id
        || authorization.key_id != pin.key_id
        || authorization.spki_der_sha256 != pin.spki_der_sha256
        || authorization.physical_private_key_identity_sha256
            != pin.physical_private_key_identity_sha256
        || authorization.key_authorization_sha256
            != pin.key_authorization_sha256
        || authorization.authorization_root_sha256
            != pin.authorization_root_sha256
        || authorization.authorization_revision
            != pin.authorization_revision
        || authorization.revocation_root_sha256 != pin.revocation_root_sha256
        || authorization.revocation_revision != pin.revocation_revision
        || authorization.high_water != pin.high_water
        || authorization.valid_from != pin.valid_from
        || authorization.valid_until != pin.valid_until
        || authorization.status != pin.status
    {
        return Err(ContractError::Invalid(
            "carried authority state differs from current independent pin",
        ));
    }
    let signed_at = parse_rfc3339(&envelope.signature.signed_at)?;
    let accepted_at = parse_rfc3339(&envelope.signature.accepted_at)?;
    let valid_from = parse_rfc3339(&pin.valid_from)?;
    let valid_until = parse_rfc3339(&pin.valid_until)?;
    if signed_at > accepted_at
        || accepted_at - signed_at > time::Duration::seconds(30)
        || signed_at < valid_from
        || accepted_at > valid_until
    {
        return Err(ContractError::Invalid(
            "authority signature timestamp is unauthorized",
        ));
    }
    verify_envelope_cryptography(
        envelope,
        domain,
        role,
        &pin.verifying_key()?,
    )?;
    Ok(())
}

fn require_observation(
    observation: &AuthorityTrustObservationV12,
    pin: &AuthorityPinV12,
    observed_at: &str,
) -> Result<()> {
    if observation != &pin.observation(observed_at.to_owned()) {
        return Err(ContractError::Invalid(
            "final authority observation differs from current pin",
        ));
    }
    let instant = parse_rfc3339(observed_at)?;
    if instant < parse_rfc3339(&pin.valid_from)?
        || instant > parse_rfc3339(&pin.valid_until)?
    {
        return Err(ContractError::Invalid(
            "final authority observation is outside key validity",
        ));
    }
    Ok(())
}

fn material_observation(
    material: &AuthorityTrustMaterialV12,
    observed_at: String,
) -> AuthorityTrustObservationV12 {
    AuthorityTrustObservationV12 {
        role: material.role,
        principal_id: material.principal_id.clone(),
        key_id: material.key_id.clone(),
        spki_der_sha256: material.spki_der_sha256.clone(),
        physical_private_key_identity_sha256: material
            .physical_private_key_identity_sha256
            .clone(),
        key_authorization_sha256: material.key_authorization_sha256.clone(),
        authorization_root_sha256: material.authorization_root_sha256.clone(),
        authorization_revision: material.authorization_revision.clone(),
        revocation_root_sha256: material.revocation_root_sha256.clone(),
        revocation_revision: material.revocation_revision.clone(),
        high_water: material.authorization_high_water.clone(),
        observed_at,
        status: material.status.clone(),
    }
}

fn require_material_observation(
    observation: &AuthorityTrustObservationV12,
    material: &AuthorityTrustMaterialV12,
    observed_at: &str,
) -> Result<()> {
    if observation != &material_observation(material, observed_at.to_owned()) {
        return Err(ContractError::Invalid(
            "final authority observation differs from signed trust generation",
        ));
    }
    let instant = parse_rfc3339(observed_at)?;
    if instant < parse_rfc3339(&material.valid_from)?
        || instant > parse_rfc3339(&material.valid_until)?
        || material.status != "ACTIVE"
    {
        return Err(ContractError::Invalid(
            "signed trust-generation authority is not active at observation time",
        ));
    }
    Ok(())
}

fn verifying_key_from_base64(
    encoded: &str,
    expected_spki: &DigestHex,
) -> Result<VerifyingKey> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ContractError::Invalid("trust-generation key is not base64url"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ContractError::Invalid("trust-generation key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    if ed25519_spki_sha256(&key) != *expected_spki {
        return Err(ContractError::Invalid(
            "trust-generation key SPKI digest mismatch",
        ));
    }
    Ok(key)
}

fn authority_pin_from_material(
    material: &AuthorityTrustMaterialV12,
) -> AuthorityPinV12 {
    AuthorityPinV12 {
        role: material.role,
        principal_id: material.principal_id.clone(),
        key_id: material.key_id.clone(),
        verifying_key_base64url: material.verifying_key_base64url.clone(),
        spki_der_sha256: material.spki_der_sha256.clone(),
        physical_private_key_identity_sha256: material
            .physical_private_key_identity_sha256
            .clone(),
        key_authorization_sha256: material.key_authorization_sha256.clone(),
        authorization_root_sha256: material.authorization_root_sha256.clone(),
        authorization_revision: material.authorization_revision.clone(),
        revocation_root_sha256: material.revocation_root_sha256.clone(),
        revocation_revision: material.revocation_revision.clone(),
        high_water: material.authorization_high_water.clone(),
        valid_from: material.valid_from.clone(),
        valid_until: material.valid_until.clone(),
        status: material.status.clone(),
    }
}

fn request_pin_from_material(
    schema_sha256: DigestHex,
    material: &RequesterTrustMaterialV11,
) -> RequestAuthorityPinV11 {
    RequestAuthorityPinV11 {
        schema_sha256,
        principal_id: material.principal_id.clone(),
        key_id: material.key_id.clone(),
        verifying_key_base64url: material.verifying_key_base64url.clone(),
        spki_der_sha256: material.spki_der_sha256.clone(),
        physical_private_key_identity_sha256: material
            .physical_private_key_identity_sha256
            .clone(),
        key_leaf_sha256: material.key_leaf_sha256.clone(),
        trust_root_sha256: material.trust_root_sha256.clone(),
        trust_revision: material.trust_revision.clone(),
        non_revocation_root_sha256: material.non_revocation_root_sha256.clone(),
        non_revocation_revision: material.non_revocation_revision.clone(),
        high_water: material.authorization_high_water.clone(),
        authorization_high_water: material.authorization_high_water.clone(),
        revocation_high_water: material.revocation_high_water.clone(),
        valid_from: material.valid_from.clone(),
        valid_until: material.valid_until.clone(),
        status: material.status.clone(),
    }
}

fn pins_for_generation(
    roots: &StrictVerifierPinsV12,
    bundle: &TrustGenerationBundleV12,
) -> Result<StrictVerifierPinsV12> {
    let generation = &bundle.generation.payload;
    let mut pins = roots.clone();
    pins.request_v11 = request_pin_from_material(
        generation.request_v11_schema_sha256.clone(),
        &generation.requester,
    );
    pins.controller_ingress =
        authority_pin_from_material(&generation.controller_ingress);
    pins.receipt_authentication =
        authority_pin_from_material(&generation.receipt_authentication);
    pins.receipt_log = authority_pin_from_material(&generation.receipt_log);
    pins.external_witness =
        authority_pin_from_material(&generation.external_witness);
    pins.final_verdict =
        authority_pin_from_material(&generation.final_verdict);
    pins.final_settlement =
        authority_pin_from_material(&generation.final_settlement);
    pins.validate()?;
    Ok(pins)
}

fn require_material_matches_pin(
    material: &AuthorityTrustMaterialV12,
    pin: &AuthorityPinV12,
) -> Result<()> {
    if authority_pin_from_material(material) != *pin {
        return Err(ContractError::Invalid(
            "fresh trust generation differs from current authority policy",
        ));
    }
    Ok(())
}

fn require_requester_material_matches_pin(
    material: &RequesterTrustMaterialV11,
    pin: &RequestAuthorityPinV11,
) -> Result<()> {
    if request_pin_from_material(pin.schema_sha256.clone(), material) != *pin {
        return Err(ContractError::Invalid(
            "fresh trust generation differs from current requester policy",
        ));
    }
    Ok(())
}

fn verify_generation_roles_and_uniqueness(
    generation: &crate::receipt_contract_v12::TrustGenerationPayloadV12,
    pins: &StrictVerifierPinsV12,
) -> Result<()> {
    for (material, role) in [
        (&generation.controller_ingress, AuthorityRoleV12::ControllerIngress),
        (
            &generation.receipt_authentication,
            AuthorityRoleV12::ReceiptAuthentication,
        ),
        (&generation.receipt_log, AuthorityRoleV12::ReceiptLog),
        (
            &generation.external_witness,
            AuthorityRoleV12::ExternalWitness,
        ),
        (&generation.final_verdict, AuthorityRoleV12::FinalVerdict),
        (
            &generation.final_settlement,
            AuthorityRoleV12::FinalSettlement,
        ),
    ] {
        if material.role != role
            || material.status != "ACTIVE"
            || material.authorization_high_water.get()? == 0
            || material.revocation_high_water.get()? == 0
        {
            return Err(ContractError::Invalid(
                "trust generation has an invalid role or high-water",
            ));
        }
        verifying_key_from_base64(
            &material.verifying_key_base64url,
            &material.spki_der_sha256,
        )?;
    }
    let mut identities = Vec::new();
    identities.push((
        generation.requester.principal_id.as_str(),
        generation.requester.key_id.as_str(),
        &generation.requester.spki_der_sha256,
        &generation.requester.physical_private_key_identity_sha256,
    ));
    for material in [
        &generation.controller_ingress,
        &generation.receipt_authentication,
        &generation.receipt_log,
        &generation.external_witness,
        &generation.final_verdict,
        &generation.final_settlement,
    ] {
        identities.push((
            material.principal_id.as_str(),
            material.key_id.as_str(),
            &material.spki_der_sha256,
            &material.physical_private_key_identity_sha256,
        ));
    }
    identities.push((
        pins.trust_root.principal_id.as_str(),
        pins.trust_root.key_id.as_str(),
        &pins.trust_root.spki_der_sha256,
        &pins.trust_root.physical_private_key_identity_sha256,
    ));
    for (index, left) in identities.iter().enumerate() {
        for right in identities.iter().skip(index + 1) {
            if left.0 == right.0
                || left.1 == right.1
                || left.2 == right.2
                || left.3 == right.3
            {
                return Err(ContractError::Invalid(
                    "requester and generated authority identities are not pairwise distinct",
                ));
            }
        }
    }
    Ok(())
}

fn maximum_authorization_high_water(
    bundle: &TrustGenerationBundleV12,
) -> Result<CanonicalU64> {
    let generation = &bundle.generation.payload;
    let mut maximum = generation.requester.authorization_high_water.get()?;
    for material in [
        &generation.controller_ingress,
        &generation.receipt_authentication,
        &generation.receipt_log,
        &generation.external_witness,
        &generation.final_verdict,
        &generation.final_settlement,
    ] {
        maximum = maximum.max(material.authorization_high_water.get()?);
    }
    Ok(CanonicalU64::new(maximum))
}

fn maximum_revocation_high_water(
    bundle: &TrustGenerationBundleV12,
) -> Result<CanonicalU64> {
    let generation = &bundle.generation.payload;
    let mut maximum = generation.requester.revocation_high_water.get()?;
    for material in [
        &generation.controller_ingress,
        &generation.receipt_authentication,
        &generation.receipt_log,
        &generation.external_witness,
        &generation.final_verdict,
        &generation.final_settlement,
    ] {
        maximum = maximum.max(material.revocation_high_water.get()?);
    }
    Ok(CanonicalU64::new(maximum))
}

fn require_pin_role(pin: &AuthorityPinV12, role: AuthorityRoleV12) -> Result<()> {
    if pin.role != role
        || pin.status != "ACTIVE"
        || pin.authorization_revision.get()? == 0
        || pin.high_water.get()? == 0
        || pin.physical_private_key_identity_sha256 == DigestHex::zero()
        || pin.key_authorization_sha256 == DigestHex::zero()
        || pin.authorization_root_sha256 == DigestHex::zero()
        || pin.revocation_root_sha256 == DigestHex::zero()
    {
        return Err(ContractError::Invalid("invalid authority pin"));
    }
    crate::receipt_contract_v12::validate_identifier(&pin.principal_id)?;
    crate::receipt_contract_v12::validate_identifier(&pin.key_id)?;
    if parse_rfc3339(&pin.valid_from)? >= parse_rfc3339(&pin.valid_until)? {
        return Err(ContractError::Invalid(
            "authority pin has an invalid validity interval",
        ));
    }
    Ok(())
}

fn validate_request_pin(pin: &RequestAuthorityPinV11) -> Result<()> {
    if pin.status != "ACTIVE"
        || pin.trust_revision.get()? == 0
        || pin.high_water.get()? == 0
        || pin.authorization_high_water.get()? == 0
        || pin.revocation_high_water.get()? == 0
        || pin.high_water != pin.authorization_high_water
        || pin.physical_private_key_identity_sha256 == DigestHex::zero()
        || pin.key_leaf_sha256 == DigestHex::zero()
        || pin.trust_root_sha256 == DigestHex::zero()
        || pin.non_revocation_root_sha256 == DigestHex::zero()
        || parse_rfc3339(&pin.valid_from)? >= parse_rfc3339(&pin.valid_until)?
    {
        return Err(ContractError::Invalid("invalid request-v11 authority pin"));
    }
    crate::receipt_contract_v12::validate_identifier(&pin.principal_id)?;
    crate::receipt_contract_v12::validate_identifier(&pin.key_id)?;
    if sha256_bytes(REQUEST_SCHEMA_V11.as_bytes()) != pin.schema_sha256 {
        return Err(ContractError::Invalid(
            "request-v11 schema source digest differs from pin",
        ));
    }
    request_verifying_key(pin)?;
    Ok(())
}

fn request_schema_validator_v11() -> Result<&'static jsonschema::Validator> {
    REQUEST_SCHEMA_VALIDATOR_V11
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(REQUEST_SCHEMA_V11)
                .map_err(|error| format!("parse embedded request-v11 schema: {error}"))?;
            jsonschema::draft202012::options()
                .build(&schema)
                .map_err(|error| {
                    format!("compile embedded request-v11 schema: {error}")
                })
        })
        .as_ref()
        .map_err(|error| ContractError::InvalidOwned(error.clone()))
}

fn receipt_schema_validator_v12() -> Result<&'static jsonschema::Validator> {
    RECEIPT_SCHEMA_VALIDATOR_V12
        .get_or_init(|| {
            let schema = closed_receipt_schema_v12()?;
            jsonschema::draft202012::options()
                .build(&schema)
                .map_err(|error| {
                    format!("compile closed receipt-v12 schema: {error}")
                })
        })
        .as_ref()
        .map_err(|error| ContractError::InvalidOwned(error.clone()))
}

fn closed_receipt_schema_v12() -> std::result::Result<Value, String> {
    let mut receipt: Value = serde_json::from_str(RECEIPT_SCHEMA_V12)
        .map_err(|error| format!("parse embedded receipt-v12 schema: {error}"))?;
    let mut request: Value = serde_json::from_str(REQUEST_SCHEMA_V11)
        .map_err(|error| format!("parse embedded request-v11 schema: {error}"))?;
    let request_object = request
        .as_object_mut()
        .ok_or("embedded request-v11 schema is not an object")?;
    let request_definitions = request_object
        .remove("$defs")
        .and_then(|value| value.as_object().cloned())
        .ok_or("embedded request-v11 schema has no $defs registry")?;
    request_object.remove("$id");
    request_object.remove("$schema");
    rewrite_request_schema_refs(&mut request)?;

    let receipt_object = receipt
        .as_object_mut()
        .ok_or("embedded receipt-v12 schema is not an object")?;
    let request_property = receipt_object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("requestV11"))
        .ok_or("receipt-v12 schema has no requestV11 property")?;
    *request_property = serde_json::json!({
        "$ref": "#/$defs/requestV11__root"
    });
    let receipt_definitions = receipt_object
        .get_mut("$defs")
        .and_then(Value::as_object_mut)
        .ok_or("embedded receipt-v12 schema has no $defs registry")?;
    for (name, mut definition) in request_definitions {
        rewrite_request_schema_refs(&mut definition)?;
        let bundled_name = format!("requestV11__{name}");
        if receipt_definitions
            .insert(bundled_name.clone(), definition)
            .is_some()
        {
            return Err(format!(
                "receipt schema bundle definition {bundled_name} is duplicated"
            ));
        }
    }
    if receipt_definitions
        .insert("requestV11__root".to_owned(), request)
        .is_some()
    {
        return Err(
            "receipt schema bundle request-v11 root is duplicated".to_owned(),
        );
    }
    Ok(receipt)
}

fn rewrite_request_schema_refs(
    value: &mut Value,
) -> std::result::Result<(), String> {
    match value {
        Value::Array(items) => {
            for item in items {
                rewrite_request_schema_refs(item)?;
            }
        }
        Value::Object(object) => {
            if let Some(reference) = object.get_mut("$ref") {
                let raw = reference
                    .as_str()
                    .ok_or("request-v11 schema $ref is not a string")?;
                let name = raw.strip_prefix("#/$defs/").ok_or_else(|| {
                    format!(
                        "request-v11 schema has unresolved or network-capable $ref {raw}"
                    )
                })?;
                *reference =
                    Value::String(format!("#/$defs/requestV11__{name}"));
            }
            for child in object.values_mut() {
                rewrite_request_schema_refs(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn request_verifying_key(pin: &RequestAuthorityPinV11) -> Result<VerifyingKey> {
    let decoded = URL_SAFE_NO_PAD
        .decode(&pin.verifying_key_base64url)
        .map_err(|_| ContractError::Invalid("request key is not base64url"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ContractError::Invalid("request key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    if ed25519_spki_sha256(&key) != pin.spki_der_sha256 {
        return Err(ContractError::Invalid("request pin SPKI mismatch"));
    }
    Ok(key)
}

fn verify_v11_merkle_proof(
    value: &Value,
    expected_domain: &str,
    expected_leaf: &DigestHex,
    expected_root: &DigestHex,
) -> Result<()> {
    let proof = value
        .as_object()
        .ok_or(ContractError::Invalid("v11 Merkle proof is not an object"))?;
    require_json_string(proof, "treeDomain", expected_domain)?;
    require_json_string(proof, "leafSha256", expected_leaf.as_str())?;
    require_json_string(proof, "rootSha256", expected_root.as_str())?;
    let ordinal = parse_d20(json_string(proof, "leafOrdinal")?)?;
    let tree_size = parse_d20(json_string(proof, "treeSize")?)?;
    if tree_size == 0 || ordinal >= tree_size {
        return Err(ContractError::Invalid("invalid v11 Merkle proof bounds"));
    }
    let path = proof
        .get("path")
        .and_then(Value::as_array)
        .ok_or(ContractError::Invalid("v11 Merkle path is missing"))?;
    if path.len() > 64 {
        return Err(ContractError::Invalid("v11 Merkle path exceeds bound"));
    }
    let mut expected_directions = Vec::new();
    collect_v11_inclusion_directions(
        tree_size as usize,
        ordinal as usize,
        &mut expected_directions,
    );
    if path.len() != expected_directions.len() {
        return Err(ContractError::Invalid(
            "v11 Merkle path length does not match tree shape",
        ));
    }
    let mut current = h11(
        "merkle-leaf",
        &[expected_domain.as_bytes(), &expected_leaf.decode()?],
    );
    for (step, expected_direction) in
        path.iter().zip(expected_directions.iter())
    {
        let step = step
            .as_object()
            .ok_or(ContractError::Invalid("v11 Merkle step is not an object"))?;
        let sibling =
            DigestHex::parse(json_string(step, "siblingSha256")?)?;
        let direction = json_string(step, "direction")?;
        if direction != *expected_direction {
            return Err(ContractError::Invalid(
                "v11 Merkle direction does not match ordinal",
            ));
        }
        current = match direction {
            "LEFT" => h11(
                "merkle-node",
                &[
                    expected_domain.as_bytes(),
                    &sibling.decode()?,
                    &current.decode()?,
                ],
            ),
            "RIGHT" => h11(
                "merkle-node",
                &[
                    expected_domain.as_bytes(),
                    &current.decode()?,
                    &sibling.decode()?,
                ],
            ),
            _ => return Err(ContractError::Invalid("invalid v11 Merkle direction")),
        };
    }
    if current != *expected_root {
        return Err(ContractError::Invalid("v11 Merkle root mismatch"));
    }
    Ok(())
}

fn collect_v11_inclusion_directions(
    tree_size: usize,
    ordinal: usize,
    directions: &mut Vec<&'static str>,
) {
    if tree_size == 1 {
        return;
    }
    let split = largest_power_of_two_less_than(tree_size);
    if ordinal < split {
        collect_v11_inclusion_directions(split, ordinal, directions);
        directions.push("RIGHT");
    } else {
        collect_v11_inclusion_directions(
            tree_size - split,
            ordinal - split,
            directions,
        );
        directions.push("LEFT");
    }
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    let shift = usize::BITS - 1 - (value - 1).leading_zeros();
    1usize << shift
}

pub fn logged_bundle_from_receipt(receipt: &ReceiptV12) -> LoggedReceiptBundleV12 {
    LoggedReceiptBundleV12 {
        contract_version: receipt.contract_version,
        request_contract_version: receipt.request_contract_version,
        receipt_id: receipt.receipt_id.clone(),
        receipt_sequence: receipt.receipt_sequence.clone(),
        requester_principal_id: receipt.requester_principal_id.clone(),
        replay_identity: receipt.replay_identity.clone(),
        request_v11: receipt.request_v11.clone(),
        request_admission: receipt.request_admission.clone(),
        request_admission_sha256: receipt.request_admission_sha256.clone(),
        request_v11_sha256: receipt.request_v11_sha256.clone(),
        request_envelope_sha256: receipt.request_envelope_sha256.clone(),
        request_canonical_bytes: receipt.request_canonical_bytes.clone(),
        receipt_body: receipt.receipt_body.clone(),
        receipt_body_sha256: receipt.receipt_body_sha256.clone(),
        receipt_body_canonical_bytes: receipt.receipt_body_canonical_bytes.clone(),
        receipt_authentication_envelope: receipt
            .receipt_authentication_envelope
            .clone(),
        receipt_authentication_envelope_sha256: receipt
            .receipt_authentication_envelope_sha256
            .clone(),
        previous_checkpoint: receipt.previous_checkpoint.clone(),
        pre_final_log_leaf: receipt.pre_final_log_leaf.clone(),
        signed_tree_head: receipt.signed_tree_head.clone(),
        signed_tree_head_envelope_sha256: receipt
            .signed_tree_head_envelope_sha256
            .clone(),
        inclusion_proof: receipt.inclusion_proof.clone(),
        consistency_proof: receipt.consistency_proof.clone(),
    }
}

fn require_json_string(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<()> {
    if json_string(object, field)? != expected {
        return Err(ContractError::InvalidOwned(format!(
            "JSON field {field} does not match independent trust input"
        )));
    }
    Ok(())
}

fn json_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::InvalidOwned(format!("missing string field {field}")))
}

fn json_timestamp(object: &Map<String, Value>, field: &str) -> Result<OffsetDateTime> {
    parse_rfc3339(json_string(object, field)?)
}

fn parse_d20(value: &str) -> Result<u64> {
    CanonicalU64::parse(value.to_owned())?.get()
}
