//! Later facts commitment from actual immutable pre-effect capture and the
//! installed classifier. Candidate evaluation remains effect-free: this is
//! the worker's separate, supervised accounting call to the real native owner.
use super::*;

fn identifier_hash(bytes:&[u8])->Result<Identifier,String>{
    Identifier::parse(sha256_prefixed(bytes)).map_err(shadow_error)
}
pub(super) fn capture(lifecycle:&ShadowRequestLifecycle,candidate:&PolicyEvaluation)
    ->Result<policy_shadow::ProtectedRequestFacts,String>{
    let captured=&lifecycle.facts;
    let principal=candidate.evaluated_principal_id.as_deref().ok_or("facts lack actual classified principal")?;
    if captured.authenticated_principal_id.as_deref().is_some_and(|expected|expected!=principal){
        return Err("captured principal differs from actual classifier".into());
    }
    let binding=lifecycle.generation.candidate.observed_authority_binding(candidate,principal)?;
    let route_id=candidate.route_id.as_deref().ok_or("facts lack actual classified route")?;
    let route=lifecycle.generation.candidate.snapshot.routes.iter().find(|route|route.id==route_id)
        .ok_or("classified route absent from installed candidate")?;
    let url=Url::parse(&captured.url).map_err(|_|"captured URL is not admitted")?;
    let scheme=match url.scheme(){"https"=>policy_shadow::RequestScheme::Https,"http"=>policy_shadow::RequestScheme::Http,
        _=>return Err("captured scheme unsupported".into())};
    // Preserve the exact original URL/header/body components by commitment,
    // never publish request secrets or substitute post-rewrite output.
    let headers=captured.headers.iter().map(|(name,value)|{
        identifier_hash(&canonical_json_bytes(&(name,value)).map_err(shadow_error)?)
    }).collect::<Result<Vec<_>,String>>()?;
    policy_shadow::ProtectedRequestFacts::new(
        Identifier::parse(captured.method.clone()).map_err(shadow_error)?,scheme,
        identifier_hash(canonical_authority(&url).as_bytes())?,
        identifier_hash(url.path().as_bytes())?,
        url.query().map(|query|identifier_hash(query.as_bytes())).transpose()?,
        headers,Some(identifier_hash(&captured.body)?),
        binding.principal_sha256().clone(),
        route.credential_ref.as_deref().map(|slot|Sha256Digest::compute(slot.as_bytes())),
        binding.route_sha256().clone(),binding.compiled_semantic_profile_sha256().clone(),binding.operation(),
    ).map_err(shadow_error)
}
pub(crate) fn commit(custody:&dyn PolicyShadowCustodyRpcSupervisor,
    facts:&policy_shadow::ProtectedRequestFacts,context:&policy_shadow::RequestCommitmentContext)
    ->Result<policy_shadow::RequestCommitment,String>{
    let original=canonical_json_bytes(&(facts,context)).map_err(shadow_error)?;
    if original.len()>8*1024{return Err("native protected facts exceed original bound before HMAC contact".into());}
    let binding=sha256_prefixed(&original);
    let call=custody_call_context(custody,PolicyShadowCustodyOperation::CommitRequest,"native-protected-facts",&binding)?;
    let result=custody.commit_request(&call,facts,context).map_err(shadow_error);
    let completed=finish_custody_call(custody,call);
    if !completed{return Err("native facts custody operation did not settle".into());}
    let result=result?;
    if result.native_computation_original().is_none(){return Err("native facts lacks actual signed computation".into());}
    Ok(result)
}
