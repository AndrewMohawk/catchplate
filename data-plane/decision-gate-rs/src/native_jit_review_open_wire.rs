//! Exact current-authorization and definite-commit domains. Public parsing is
//! not admission: only the cold-assigned Owner supplies these distinct keys.
use super::*;
use ed25519_dalek::Signature;

const SCOPE: &[&str] = &["reviewId","approvalRequestId","reviewerId","sessionId","credentialRecordId",
    "challengeSha256","parentOriginalSha256","childOriginalSha256","pairSha256","sealProofSha256",
    "sealedSourceContractDigest","sourceContractDigest","controlPlaneConfigurationDigest","openingAssignmentSha256",
    "ownerScopeDigest","browserNonceCommitment","recipientPublicKey","documentExpiresAtEpochNs",
    "approvalExpiresAtEpochNs","sessionExpiresAtEpochNs","assignmentExpiresAtEpochNs"];
const EPOCHS: &[&str] = &["documentExpiresAtEpochNs","approvalExpiresAtEpochNs","sessionExpiresAtEpochNs","assignmentExpiresAtEpochNs"];
const AUTHORIZATION: &str = "catchplate.nativeJitReviewOpeningAuthorization/v1";
const ACK: &str = "catchplate.nativeJitReviewOpeningCommitAcknowledgment/v1";
pub(super) fn integer(v: &Value) -> Result<u64, String> { v.as_u64().filter(|n| *n > 0 && *n <= i64::MAX as u64).ok_or_else(|| "review integer".into()) }
fn digest(v: &Value) -> Result<(), String> { require(v.as_str().is_some_and(current::digest)) }
fn scope(value: &Value) -> Result<u64, String> {
    fields(value, SCOPE)?;
    let mut expiry = i64::MAX as u64;
    for name in SCOPE {
        if EPOCHS.contains(name) { expiry = expiry.min(integer(&value[*name])?); }
        else if ["reviewId","approvalRequestId","reviewerId","sessionId","credentialRecordId"].contains(name) {
            let maximum = if ["reviewerId","credentialRecordId"].contains(name) { 1024 } else { 128 };
            let v = text(value,name,maximum)?; require(v.trim() == v && !v.chars().any(|c| c <= ' ' || c == '\u{7f}'))?;
        } else if *name == "recipientPublicKey" { require(current::bytes32(text(value,name,64)?)? != [0;32])?; }
        else { digest(&value[*name])?; }
    }
    Ok(expiry)
}
pub(super) fn authority(original: &str, policy: &Value, acknowledgment: bool, now: u64) -> Result<Value, String> {
    require(!original.is_empty() && original.len() <= 64*1024 && original.is_ascii())?;
    let envelope = crate::native_oauth_refresh_v1::response_document(original.as_bytes())?;
    fields(&envelope, &["schema","payload","signatureBase64Url"])?;
    require(canonical_ascii_bytes(&envelope)? == original.as_bytes())?;
    let schema = if acknowledgment { ACK } else { AUTHORIZATION };
    require(envelope["schema"] == schema.replacen("catchplate.native","catchplate.signedNative",1))?;
    let value = &envelope["payload"];
    fields(value, if acknowledgment {
        &["schema","operation","requestDigest","authorizationSha256","preparationSha256","scope","reviewDigest","receiptId",
            "receiptExpiresAtEpochNs","commitMarkerSha256","completionReceiptSha256","afterRootVectorDigest","committedAtEpochNs","expiresAtEpochNs"]
    } else { &["schema","operation","requestDigest","scope","currentRootVectorDigest","currentRootHeadDigest","currentRootSequence","issuedAtEpochNs","expiresAtEpochNs"] })?;
    require(value["schema"] == schema && value["operation"] == if acknowledgment { "jit.review-open.receipt.issue" } else { "jit.review-open.authorize" })?;
    digest(&value["requestDigest"])?;
    let issued = integer(&value[if acknowledgment { "committedAtEpochNs" } else { "issuedAtEpochNs" }])?;
    let expires = integer(&value["expiresAtEpochNs"])?;
    require(issued <= now && now < expires && expires - issued <= 30_000_000_000 && expires <= scope(&value["scope"])? )?;
    if acknowledgment {
        for name in ["authorizationSha256","preparationSha256","reviewDigest","commitMarkerSha256","completionReceiptSha256","afterRootVectorDigest"] { digest(&value[name])?; }
        let receipt_id = text(value,"receiptId",128)?;
        require(receipt_id.trim() == receipt_id && !receipt_id.chars().any(|c| c <= ' ' || c == '\u{7f}'))?;
        let receipt = integer(&value["receiptExpiresAtEpochNs"])?;
        require(expires <= receipt && receipt <= scope(&value["scope"])? )?;
    } else {
        digest(&value["currentRootVectorDigest"])?; digest(&value["currentRootHeadDigest"])?;
        require(value["currentRootSequence"].as_u64().is_some_and(|n| n <= i64::MAX as u64))?;
    }
    let encoded = text(&envelope,"signatureBase64Url",86)?;
    let signature = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| "review signature encoding")?;
    require(signature.len() == 64 && URL_SAFE_NO_PAD.encode(&signature) == encoded)?;
    let mut preimage = schema.as_bytes().to_vec(); preimage.push(0); preimage.extend(canonical_ascii_bytes(value)?);
    policy::purpose_key(&policy[if acknowledgment { "commitOwnerKey" } else { "authorizerKey" }])?
        .verify_strict(&preimage, &Signature::from_slice(&signature).map_err(|_| "review signature width")?)
        .map_err(|_| "review purpose signature refused")?;
    Ok(value.clone())
}
pub(super) fn grant_join(grant: &Value, challenge: &Value, original: &str, input: &Value, assignment_expiry: u64) -> Result<(), String> {
    let scope = &grant["scope"];
    for name in ["reviewId","approvalRequestId","sourceContractDigest","controlPlaneConfigurationDigest",
        "openingAssignmentSha256","ownerScopeDigest","browserNonceCommitment","recipientPublicKey"] { require(scope[name] == challenge[name])?; }
    require(scope["challengeSha256"] == sha(original.as_bytes()) && scope["assignmentExpiresAtEpochNs"] == assignment_expiry
        && integer(&grant["issuedAtEpochNs"])? >= integer(&challenge["issuedAtEpochNs"])?
        && integer(&grant["expiresAtEpochNs"])? <= integer(&challenge["expiresAtEpochNs"])? )?;
    for (field, input_name, bound) in [("parentOriginalSha256","parentOriginal",512*1024),("childOriginalSha256","childOriginal",512*1024),
        ("pairSha256","pairOriginal",1024*1024),("sealProofSha256","proofOriginal",128*1024)] {
        require(scope[field] == sha(text(input,input_name,bound)?.as_bytes()))?;
    }
    Ok(())
}
pub(super) fn ack_join(ack: &Value, prepared: &Value, proof_sha: &str) -> Result<(), String> {
    require(ack["scope"] == prepared["scope"] && ack["authorizationSha256"] == prepared["authorizationSha256"]
        && ack["preparationSha256"] == proof_sha && ack["reviewDigest"] == prepared["reviewDigest"]
        && integer(&ack["committedAtEpochNs"])? >= integer(&prepared["preparedAtEpochNs"])?
        && integer(&ack["expiresAtEpochNs"])? <= integer(&prepared["expiresAtEpochNs"])? )
}

// Read only the two immutable digest leaves without re-encoding historical
// parent/child numbers. The broker independently authenticates the full graph.
pub(super) fn review_digest_join(input: &Value, view: &[u8]) -> Result<(), String> {
    use serde_json::value::RawValue;
    let child: BTreeMap<String, &RawValue> = serde_json::from_str(text(input,"childOriginal",512*1024)?)
        .map_err(|_| "review child digest projection")?;
    let arguments: BTreeMap<String, &RawValue> = serde_json::from_str(child.get("arguments").ok_or("review child arguments")?.get())
        .map_err(|_| "review child arguments projection")?;
    let child_digest: &str = serde_json::from_str(arguments.get("redacted_display_digest").ok_or("review child display digest")?.get())
        .map_err(|_| "review child display digest projection")?;
    let pair: BTreeMap<String, &RawValue> = serde_json::from_str(text(input,"pairOriginal",1024*1024)?)
        .map_err(|_| "review pair projection")?;
    let items: Vec<&RawValue> = serde_json::from_str(pair.get("items").ok_or("review pair items")?.get())
        .map_err(|_| "review pair item projection")?;
    require(items.len()==2)?;
    let item: BTreeMap<String,&RawValue> = serde_json::from_str(items[1].get()).map_err(|_| "review display item projection")?;
    let pair_digest: &str = serde_json::from_str(item.get("plaintextSha256").ok_or("review pair display digest")?.get())
        .map_err(|_| "review pair display digest projection")?;
    require(current::digest(child_digest) && child_digest==pair_digest && child_digest==sha(view))
}
