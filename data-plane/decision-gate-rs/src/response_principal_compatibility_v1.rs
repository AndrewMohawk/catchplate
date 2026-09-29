//! Early representability checks for the existing response-proof families.
//!
//! Native principal preflight admits a wider identity than these legacy
//! statements, receipts and bindings. Refuse that mismatch before contact or
//! provider effects; never widen a signed legacy contract by changing its name.
//! Passing this check is not authentication, route authorization or proof that
//! any response will be accepted. The complete existing validators still run.

#[derive(Clone, Copy)]
pub enum ResponseProofPrincipalProfile {
    Buffered,
    Streaming,
    Observation,
}

/// Check only the principal, without normalizing, truncating or exposing it.
///
/// Observation uses the stricter identifier predicate: its receiver, schemas
/// and post-dispatch receipt/binding paths impose this alphabet even where an
/// individual producer-side field accepts a bounded Unicode identity. Reusing
/// the custody predicates keeps the byte bound and alphabet unchanged.
pub fn require_response_principal_compatible(
    profile: ResponseProofPrincipalProfile,
    principal: &str,
) -> Result<(), String> {
    let (result, family) = match profile {
        ResponseProofPrincipalProfile::Buffered => (
            crate::validate_bounded_identity("principal_id", principal),
            "buffered",
        ),
        ResponseProofPrincipalProfile::Streaming => (
            crate::validate_streaming_identifier("principal_id", principal),
            "streaming",
        ),
        ResponseProofPrincipalProfile::Observation => (
            crate::validate_streaming_identifier("principal_id", principal),
            "observation",
        ),
    };
    result.map_err(|_| format!(
        "unsupported {family} response-proof principal: identity cannot be represented by the current statement, receipt and binding profiles"
    ))
}
