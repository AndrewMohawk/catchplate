//! Exact independently verified native origin. This decoder is data-only;
//! the separately granted DurableRecoveryStore performs initialization.
use super::*;
use super::ledger_spool_values::{invalid,Scope};
use crate::policy_shadow::{ShadowGenerationIdentity,RuntimeIdentity,CanonicalEd25519Signature,signature_preimage};
use catchplate_decision_gate::native_generation_origin_v1 as wire;
fn require(v:bool)->Result<(),ServiceError>{if v{Ok(())}else{Err(invalid())}}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Key {
    pub(super) key_id:Sha256Digest,pub(super) key_spki_sha256:Sha256Digest,
    pub(super) public_key_base64url:String,pub(super) not_before_unix_nanos:i64,pub(super) not_after_unix_nanos:i64,
}
impl Key {
    pub(super) fn material(&self)->Result<VerifyingKey,ServiceError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.public_key_base64url).map_err(|_|invalid())?;
        require(raw.len()==32 && URL_SAFE_NO_PAD.encode(&raw)==self.public_key_base64url
            && self.not_before_unix_nanos>0 && self.not_before_unix_nanos<self.not_after_unix_nanos)?;
        let key=VerifyingKey::from_bytes(&<[u8;32]>::try_from(raw.as_slice()).map_err(|_|invalid())?).map_err(|_|invalid())?;
        require(self.key_id==self.key_spki_sha256 && verifying_key_spki_sha256(&key).map_err(|_|invalid())?==self.key_spki_sha256)?;Ok(key)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {api_version:String,purpose:String,request:wire::Request,evidence_original:String,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {payload:Payload,signature:CanonicalEd25519Signature}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Evidence {statement:wire::Statement,signature:String,native_key_evidence:serde_json::Value}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Originals {
    api_version:String,install_request_sha256:Sha256Digest,generation:ShadowGenerationIdentity,
    assignment:serde_json::Value,load_receipt:serde_json::Value,runtime_attestation:serde_json::Value,
    runtime_attestation_verification:serde_json::Value,runtime_identity:RuntimeIdentity,
    publication:serde_json::Value,production_configuration_binding_sha256:Sha256Digest,
    trust_checkpoint:serde_json::Value,ledger_baseline:Baseline,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Baseline {event_ordinal:u64,head_sha256:Sha256Digest,original_count:u64,last_ingress:Option<(u64,Sha256Digest)>,observed_at_unix_nanos:i64}
/// No Deserialize: generated only from the independent original signature and
/// exact source-owned installed baseline. It does not become a Fleet load.
pub(super) struct Verified {generation:ShadowGenerationIdentity,runtime:RuntimeIdentity,origin_sha256:Sha256Digest,expires:i64}
impl Verified {
    pub(super) fn generation(&self)->&ShadowGenerationIdentity{&self.generation}
    pub(super) fn runtime(&self)->&RuntimeIdentity{&self.runtime}
    pub(super) fn sha256(&self)->&Sha256Digest{&self.origin_sha256}
    pub(super) fn expires(&self)->i64{self.expires}
}
pub(super) fn verify(raw:&str,scope:&Scope,key:&Key,earliest:i64,latest:i64)->Result<Verified,ServiceError>{
    require(raw.is_ascii() && !raw.is_empty() && raw.len()<=2*1024*1024 && earliest>0 && earliest<=latest)?;
    let value:Envelope=decode_canonical_frame(raw.as_bytes())?;let p=&value.payload;
    require(p.api_version=="catchplate.nativeGenerationOrigin/v1" && p.purpose=="native-installed-generation-origin"
        && p.signing_key_id==key.key_id && p.signing_key_spki_sha256==key.key_spki_sha256
        && p.issued_at_unix_nanos<=earliest && latest<p.expires_at_unix_nanos
        && p.issued_at_unix_nanos>=key.not_before_unix_nanos && p.expires_at_unix_nanos<=key.not_after_unix_nanos
        && p.expires_at_unix_nanos==i64::try_from(p.request.expires_at_epoch_ns).map_err(|_|invalid())?
        && p.request.context_sha256==super::ledger_spool_values::sha(scope)?.as_str()
        && p.request.assignment_payload_sha256==scope.assignment_payload_sha256.as_str()
        && p.request.generation_id==scope.generation_id.as_str())?;
    p.request.validate(latest as u64).map_err(|_|invalid())?;
    key.material()?.verify_strict(&signature_preimage("catchplate.nativeGenerationOrigin.signature/v1",&encode_canonical_frame(p)?),
        &Signature::from_bytes(&value.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())?;
    require(p.evidence_original.is_ascii() && p.evidence_original.len()<=wire::MAX_EVIDENCE)?;
    let evidence:Evidence=decode_canonical_frame(p.evidence_original.as_bytes())?;
    evidence.statement.validate(latest as u64).map_err(|_|invalid())?;
    require(encode_canonical_frame(&p.request)?==encode_canonical_frame(&evidence.statement.request)?)?;
    let originals:Originals=decode_canonical_frame(evidence.statement.originals.as_bytes())?;
    let b=&originals.ledger_baseline;let g=&originals.generation;
    require(originals.api_version=="catchplate.nativeInstalledGenerationOriginals/v1"
        && originals.production_configuration_binding_sha256==scope.production_configuration_binding_sha256
        && g.generation_id()==&scope.generation_id && g.assignment_payload_sha256()==&scope.assignment_payload_sha256
        && g.assignment_revision()==scope.assignment_revision
        && originals.runtime_identity.boot_id_sha256()==g.runtime_boot_id_sha256()
        && b.original_count==0 && b.last_ingress.is_none()
        && b.event_ordinal==g.authoritative_ledger_event_ordinal() && &b.head_sha256==g.authoritative_ledger_head_sha256()
        && b.observed_at_unix_nanos>=p.request.issued_at_epoch_ns as i64 && b.observed_at_unix_nanos<=earliest)?;
    Ok(Verified{generation:originals.generation,runtime:originals.runtime_identity,origin_sha256:Sha256Digest::compute(raw.as_bytes()),expires:p.expires_at_unix_nanos})
}
