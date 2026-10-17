//! Content-scoped receipt bytes are deterministic within the signed generation.
//! Attempt authority is carried separately by the original capture and artifact.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(super) const RECEIPT: &str = "catchplate.responseV2.stagedStorageReceipt/v1";
pub(super) const DOMAIN: &[u8] = b"catchplate.responseV2.stagedStorageReceipt/v1\0";
pub(super) const RESULT: &str = "catchplate.responseV2.stagedPersistenceResult/v1";
pub(super) const KIND: &str = "staged-request";
pub(super) const MEDIA: &str = "http11-request";
pub(super) const META_BOUND: usize = 256 * 1024;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReceiptBody {
    api_version: String,
    generation_id: String,
    generation: u64,
    configuration_sha256: String,
    ledger_service_id: String,
    ledger_key_id: String,
    pub object_id: String,
    pub object_kind: String,
    pub content_sha256: String,
    pub content_length: u64,
    pub media_type: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StorageReceipt {
    pub body: ReceiptBody,
    public_key_base64: String,
    signature: String,
}
impl StorageReceipt {
    fn body(config: &Config, descriptor: &ExactByteObjectDescriptor) -> Result<ReceiptBody, V2RuntimeError> {
        let topology = config.custody_topology();
        let process = topology.process(Role::ImmutableArtifactLedger).ok_or_else(|| fail("ledger absent"))?;
        let key = process.role_keys.iter().find(|key| key.logical_role == "persistence")
            .ok_or_else(|| fail("independent persistence key absent"))?;
        if descriptor.byte_length == 0 || descriptor.byte_length > MAX_EXACT_OBJECT_BYTES
            || !hash(&descriptor.sha256) || descriptor.media_type != ExactObjectMediaType::Http11Request {
            return Err(fail("staging input is not a bounded credential-free HTTP request"));
        }
        Ok(ReceiptBody { api_version:RECEIPT.to_owned(), generation_id:topology.generation_id.clone(),
            generation:topology.generation, configuration_sha256:config.guest_delivery.as_ref()
                .ok_or_else(|| fail("receipt requires actual signed configuration originals"))?.configuration_sha256()?,
            ledger_service_id:process.service_id.clone(), ledger_key_id:key.key_id.clone(),
            object_id:descriptor.object_id.clone(), object_kind:KIND.to_owned(),
            content_sha256:descriptor.sha256.clone(), content_length:descriptor.byte_length, media_type:MEDIA.to_owned() })
    }
    // A candidate is private until the blob and exact receipt are durable. Its
    // deterministic digest names the existing canonical CAS path; it is never
    // returned as a persistence observation merely because it was signed.
    pub(super) fn candidate(config: &Config, captured: &VerifiedStaged<'_>, key: &RoleSigningKey)
        -> Result<Self, V2RuntimeError> {
        if key.logical_role() != "persistence" { return Err(fail("wrong storage signer purpose")); }
        let body = Self::body(config, captured.descriptor())?;
        if key.key_id() != body.ledger_key_id { return Err(fail("held storage key differs")); }
        let result = Self { signature:key.sign(DOMAIN, &body)?, public_key_base64:key.public_key_base64(), body };
        result.verify(config, captured.descriptor())?;
        Ok(result)
    }
    pub(crate) fn verify(&self, config: &Config, descriptor: &ExactByteObjectDescriptor) -> Result<(), V2RuntimeError> {
        if self.body != Self::body(config, descriptor)? { return Err(fail("storage receipt content scope differs")); }
        let topology = config.custody_topology();
        let process = topology.process(Role::ImmutableArtifactLedger).ok_or_else(|| fail("ledger absent"))?;
        let descriptor = process.role_keys.iter().find(|key| key.logical_role == "persistence")
            .ok_or_else(|| fail("storage key absent"))?;
        let binding = topology.logical_role("persistence").ok_or_else(|| fail("storage assignment absent"))?;
        let public = STANDARD.decode(&self.public_key_base64).map_err(|_| fail("storage public key encoding"))?;
        let signature = STANDARD.decode(&self.signature).map_err(|_| fail("storage signature encoding"))?;
        if public.len() != 32 || signature.len() != 64 || STANDARD.encode(&public) != self.public_key_base64
            || STANDARD.encode(&signature) != self.signature || sha(&public) != descriptor.public_key_sha256
            || descriptor.key_id != descriptor.public_key_sha256 || binding.service_role != Role::ImmutableArtifactLedger
            || binding.key_id != descriptor.key_id || binding.public_key_sha256 != descriptor.public_key_sha256 {
            return Err(fail("storage receipt key is not independently assigned"));
        }
        let mut message = DOMAIN.to_vec(); message.extend(original(&self.body)?);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(&message, &signature).map_err(|_| fail("storage receipt signature differs"))
    }
    pub(crate) fn sha256(&self) -> Result<String, V2RuntimeError> { Ok(sha(&original(self)?)) }
    pub(super) fn locator(&self) -> Result<String, V2RuntimeError> {
        Ok(immutable_cas_locator(&Identifier(self.body.generation_id.clone()), &Identifier(self.body.object_id.clone()),
            &AuthorityDigest(self.sha256()?), &AuthorityDigest(self.body.content_sha256.clone())))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct PutResult {
    pub api_version:String,
    pub original_sha256:String,
    pub object:ImmutableObjectReference,
    pub storage_receipt:StorageReceipt,
    pub artifact_commit:SignedAuthorityArtifact,
    pub state_request:super::super::super::super::state_authority::rpc::RpcRequestFrame,
}
impl PutResult {
    pub(super) fn verify(&self,config:&Config,staged:&VerifiedStaged<'_>)->Result<(),V2RuntimeError> {
        use super::super::super::super::state_authority::rpc::FenceExpectationMode;
        staged.check()?;original(self)?;self.storage_receipt.verify(config,staged.descriptor())?;
        let binding=staged.request.binding();let receipt=&self.storage_receipt;
        let operation_id=format!("staged-put:{}",&staged.request.original_sha256()[7..]);
        let expected=ArtifactCommitArtifact{object_id:Identifier(receipt.body.object_id.clone()),object_kind:Identifier(KIND.into()),
            content_sha256:AuthorityDigest(receipt.body.content_sha256.clone()),content_length:receipt.body.content_length,
            immutable_storage_receipt_sha256:AuthorityDigest(receipt.sha256()?)};
        engine::verify_pinned_authority_artifact(config.custody_topology(),&self.artifact_commit,&binding.attempt_id,binding.fencing_token)?;
        let artifact=&self.artifact_commit.body;
        let frame=&self.state_request.request;
        let MutationPayload::CommitRawObject(commit)=&frame.payload else{return Err(fail("staged put frame is not ObjectCommitRaw"));};
        if self.api_version!=RESULT||self.original_sha256!=staged.request.original_sha256()
            ||self.object.object_type!=ImmutableObjectType::StagedRequest||self.object.object_sha256!=staged.descriptor.sha256
            ||self.object.byte_length!=staged.descriptor.byte_length||self.object.retrieval_id!=receipt.body.object_id
            ||self.object.persistence_receipt_sha256!=receipt.sha256()?
            ||artifact.operation!=OperationKind::ObjectCommitRaw||artifact.operation_id.0!=operation_id||artifact.artifact_id.0!=operation_id
            ||artifact.attempt_revision!=binding.attempt_revision||artifact.payload!=NestedAuthorityPayload::ArtifactCommit(expected)
            ||artifact.producing_logical_role.as_ref().map(|v|v.0.as_str())!=Some("persistence")
            ||artifact.expires_at_epoch_millis!=binding.deadline_at_epoch_ms
            ||frame.generation_id.0!=staged.generation_id()||frame.request_id.0!=operation_id||frame.operation_id.0!=operation_id
            ||frame.caller_role_id.0!=config.scoped_service_config(Role::ImmutableArtifactLedger)?.process.service_id
            ||frame.operation!=OperationKind::ObjectCommitRaw||frame.attempt_id.0!=binding.attempt_id
            ||frame.expected_revision!=binding.attempt_revision||frame.expected_state!=AttemptState::Authorized
            ||frame.fence.mode!=FenceExpectationMode::Exact||frame.fence.fence_token.as_ref().map(|v|v.0.as_str())!=Some(binding.fencing_token.to_string().as_str())
            ||frame.deadline!=*staged.request.deadline()||commit.object_id.0!=receipt.body.object_id||commit.object_kind.0!=KIND
            ||commit.media_type!=MEDIA||commit.expected_content_sha256.0!=receipt.body.content_sha256
            ||commit.expected_content_length!=receipt.body.content_length||commit.storage_locator!=receipt.locator()?
            ||commit.immutable_storage_receipt_sha256.0!=receipt.sha256()?||commit.artifact_commit!=self.artifact_commit {
            return Err(fail("staged publication does not bind the exact selected descriptor and signed predecessor frame"));
        }
        // The real StateAuthority verifies the full frame authentication and
        // commits it. This response is never itself proof of that later commit.
        Ok(())
    }
}
pub(super) fn original<T:Serialize>(value:&T)->Result<Vec<u8>,V2RuntimeError> {
    let raw=crate::canonical_json_bytes(value).map_err(|_|fail("staged storage canonical original"))?;
    if raw.is_empty()||raw.len()>META_BOUND{return Err(fail("staged storage metadata bound"));}Ok(raw)
}
pub(super) fn sha(raw:&[u8])->String{format!("sha256:{:x}",Sha256::digest(raw))}
fn hash(value:&str)->bool{crate::native_currentness_v1::digest(value)}
