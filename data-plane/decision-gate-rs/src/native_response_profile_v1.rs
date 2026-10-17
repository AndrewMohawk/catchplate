//! Explicit native response wire profiles, not authentication or authority.
//!
//! Producers select these from the actual retained native signer before any
//! reservation. Receivers select them from independently pinned expectations.
//! Incoming data cannot opt an old profile into the wider principal contract.

pub const NATIVE_BUFFERED: &str = "catchplate.nativeProxyResponseStatement/v1";
pub const NATIVE_STREAMING: &str = "catchplate.nativeStreamingResponseStatement/v1";
pub const NATIVE_OBSERVATION: &str = "catchplate.nativeResponseObservationStatement/v1";
pub const NATIVE_ENVELOPE: &str = "catchplate.nativeResponseRuntimeProof/v2";
pub const NATIVE_EXPECTATIONS: &str = "catchplate.nativeResponseAttestationExpectations/v2";
pub const NATIVE_STATEMENT_PROFILE: &str = "catchplate.nativeResponseStatements/v1";
pub const NATIVE_VERDICT: &str = "catchplate.nativeResponseAttestationVerification/v2";
pub const NATIVE_RECEIPT: &str = "catchplate.nativeControlPlaneAuthorizationReceipt/v1";
pub const NATIVE_RECEIPT_KIND: &str = "CatchplateNativeControlPlaneAuthorizationReceipt";
pub const NATIVE_COMMITMENT: &str = "catchplate.nativeResponseAuthorizationCommitment/v1";

/// Native principal text only. Route, credential, grant, actor and other
/// identifiers retain their respective existing contracts.
pub fn valid_principal(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= 1024
        && !value.chars().any(char::is_control)
}

/// Python-compatible sorted compact ensure_ascii JSON for NEW native binding,
/// approver-policy and lease commitments only. The historical recipe preserves a
/// literal DEL; Python escapes it. Do not silently alter legacy signed bytes.
pub fn canonical_ascii_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let legacy = crate::canonical_json_ensure_ascii_bytes(value)
        .map_err(|_| "encode native canonical ASCII original".to_owned())?;
    let mut original = Vec::with_capacity(legacy.len());
    for byte in legacy {
        if byte == 0x7f { original.extend_from_slice(b"\\u007f"); }
        else { original.push(byte); }
    }
    Ok(original)
}
