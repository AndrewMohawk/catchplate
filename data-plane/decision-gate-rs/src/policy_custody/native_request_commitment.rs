//! Exact already-produced native computation retained by the receiving RPC.
//! This verifies its distinct existing purpose, not a reconstructed signature
//! or a second HMAC owner. Ordinary Dispatch replies cannot create provenance.
use super::super::*;
use super::production_dispatch::{ClosedProductionDispatchRequestV4 as Request,
    ClosedProductionDispatchResponseV4 as Response,ClosedProductionDispatchResultV4 as ResultBody};

#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Original {
    api_version:String,native_grant_sha256:Sha256Digest,request:Request,result:ResultBody,
    result_sha256:Sha256Digest,computed_at_boottime_nanos:u64,signature_base64url:String,
}
pub(super) fn verify_computation(value:&serde_json::Value,request:&Request,response:&Response,
    configuration:&ProductionCustodyConfiguration,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
    ->Result<(),ShadowError>{
    if !configuration.retains_native_closure_owner(){return Err(ShadowError::CustodyUnavailable);}
    configuration.revalidate_active_attestation(trust,time)?;
    if !configuration.remote_native_execution_closure().ok_or(ShadowError::CustodyUnavailable)?.request_facts_selected()? {
        return Err(ShadowError::CustodyUnavailable);
    }
    let raw=canonical_json_bytes(value)?;
    if raw.is_empty() || raw.len()>8*1024{return Err(ShadowError::BindingDrift);}
    let original:Original=serde_json::from_slice(&raw).map_err(|_|ShadowError::BindingDrift)?;
    let binding=request.binding();
    if canonical_json_bytes(&original)?!=raw || !matches!(request,Request::CommitRequest{..})
        || original.api_version!="serverware.nativeShadowCommitRequestComputation/v1"
        || original.native_grant_sha256==Sha256Digest::compute(&[])
        || original.request!=*request || original.result!=response.result
        || original.result_sha256!=response.result_sha256
        || original.result_sha256!=Sha256Digest::compute(&canonical_json_bytes(&original.result)?)
        || binding.production_configuration_binding_sha256!=*configuration.production_configuration_binding_sha256()
        || original.computed_at_boottime_nanos<binding.opened_at_boottime_nanos
        || original.computed_at_boottime_nanos>=binding.operation_deadline_boottime_nanos {
        return Err(ShadowError::BindingDrift);
    }
    let role=PolicyShadowCustodySignerRole::LedgerAppend;
    let assigned=configuration.authority_binding(AuthorityRole::CustodyLedgerAppend)?;
    let checkpoint=trust.current_checkpoint()?;
    // Resolve the current independently assigned Ledger key. Its existing
    // native CommitRequest owner uses the distinct computation domain below;
    // a Ledger spill signature is never accepted as that computation.
    let key=trust.resolve_ed25519_key(&checkpoint,role.signature_domain(),assigned.key_id(),assigned.key_spki_sha256())?;
    if &ed25519_public_key_material_sha256(&key)!=assigned.key_material_sha256(){
        return Err(ShadowError::SignerBindingMismatch);
    }
    let payload=canonical_json_bytes(&(&original.api_version,&original.native_grant_sha256,
        &original.request,&original.result,&original.result_sha256,original.computed_at_boottime_nanos))?;
    let preimage=super::protocol::domain_separated_signature_preimage(
        b"serverware.nativeShadowCommitRequestComputation.signature/v1",&payload)
        .map_err(|_|ShadowError::BindingDrift)?;
    use base64::Engine as _;
    let signature=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&original.signature_base64url)
        .map_err(|_|ShadowError::SignerBindingMismatch)?;
    if signature.len()!=64 || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature)!=original.signature_base64url {
        return Err(ShadowError::SignerBindingMismatch);
    }
    key.verify_strict(&preimage,&ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_|ShadowError::SignerBindingMismatch)?).map_err(|_|ShadowError::SignerBindingMismatch)?;
    Ok(())
}
