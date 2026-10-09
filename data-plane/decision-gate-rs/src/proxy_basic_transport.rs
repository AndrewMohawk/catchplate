//! Explicit operator-app token transport, not provider Basic authentication.
//! Decoded user/password bytes are bounded and zeroized; callers receive only
//! the existing token digest. No environment-dependent parser or secret Debug.
use super::{constant_time_eq, sha256_prefixed, GateState, ProxyAuthorizationPolicy, Snapshot};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

pub(super) const MAX_EXPIRY: u128 = 9_007_199_254_740_991;
pub(super) const REFUSED: &str = "operator_basic_transport_unavailable";

#[derive(Clone)]
pub(super) struct BasicTransport {
    username: String,
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    })
}

impl BasicTransport {
    pub(super) fn from_policy(config: &Map<String, Value>) -> Result<Option<Self>, String> {
        let Some(raw) = config.get("basicTransport") else { return Ok(None); };
        let refused = || "principal Basic transport contract invalid".to_owned();
        let fields = raw.as_object().filter(|fields| fields.len() == 1).ok_or_else(refused)?;
        let username = fields.get("username").and_then(Value::as_str).ok_or_else(refused)?;
        if !canonical_uuid(username) || config.get("tokenId").and_then(Value::as_str) != Some(username)
            || config.get("scheme").and_then(Value::as_str) != Some("Bearer")
            || config.get("expiresAtEpochMs").and_then(Value::as_u64)
                .is_none_or(|expiry| expiry == 0 || u128::from(expiry) > MAX_EXPIRY)
            || config.get("tokenSha256").and_then(Value::as_str).is_none_or(|digest| !super::is_sha256_digest(digest))
        { return Err(refused()); }
        Ok(Some(Self { username: username.to_owned() }))
    }

    pub(super) fn username(&self) -> &str { &self.username }

    pub(super) fn value(&self) -> Value { json!({"username":self.username}) }

    pub(super) fn token_sha256(&self, header: &str) -> Option<String> {
        // Exact parsed field value: HTTP intake's existing outer OWS handling
        // is separate. This parser adds no trim, alternate separator or decode.
        let raw = header.as_bytes();
        if raw.len() != 114 || !raw[..5].eq_ignore_ascii_case(b"Basic") || raw[5] != b' ' {
            return None;
        }
        let encoded = &raw[6..];
        // 81 bytes accommodates the decoder's rounded-up bound. Every exit,
        // including a partial decode failure, wipes the complete owned buffer.
        let mut decoded = Zeroizing::new([0u8; 81]);
        if STANDARD.decode_slice(encoded, decoded.as_mut_slice()).ok()? != 80 { return None; }
        let canonical = Zeroizing::new(STANDARD.encode(&decoded[..80]));
        if canonical.as_bytes() != encoded || decoded[36] != b':'
            || !constant_time_eq(std::str::from_utf8(&decoded[..36]).ok()?, &self.username)
            || !decoded[37..80].iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        { return None; }
        Some(sha256_prefixed(&decoded[37..80]))
    }
}

pub(super) fn validate_raw_policy(raw: &Value) -> Result<(), String> {
    for principal in raw.get("principals").and_then(Value::as_array).into_iter().flatten() {
        let Some(config) = principal.get("proxyAuthorization").and_then(Value::as_object) else { continue; };
        if !config.contains_key("basicTransport") { continue; }
        if raw.get("apiVersion").and_then(Value::as_str) != Some("serverware.policy/v1")
            || raw.get("metadata").and_then(|value| value.get("id")).and_then(Value::as_str)
                != Some("serverware-operator-demo")
        { return Err("Basic transport requires the signed operator v1 policy".to_owned()); }
        BasicTransport::from_policy(config)?;
    }
    Ok(())
}

pub(super) fn selected(snapshot: &Snapshot) -> bool {
    snapshot.principals.iter().any(|principal| matches!(&principal.proxy_authorization,
        Some(ProxyAuthorizationPolicy::BearerToken { basic_transport: Some(_), .. })))
}

pub(super) fn require_scope(snapshot: &Snapshot, admitted_operator: bool) -> Result<(), &'static str> {
    if selected(snapshot) && (!admitted_operator || snapshot.policy_id != "serverware-operator-demo") {
        Err(REFUSED)
    } else { Ok(()) }
}

pub(super) fn require_runtime(state: &GateState, snapshot: &Snapshot) -> Result<(), &'static str> {
    require_scope(snapshot, state.policy_shadow.is_operator_demo() && !state.is_production
        && state.native_serving_privileges.is_none() && state.native_secret_broker.is_none()
        && state.native_runtime_lifetime.is_none() && state.measured_canary_delivery.is_none()
        && state.policy_shadow_generation_control.is_none() && !state.atomic_release_authorization_enabled
        && state.proxy_ingress_attestation.mode == super::operator_demo::INGRESS_MODE)
}

#[cfg(test)]
#[path = "proxy_basic_transport_tests.rs"]
mod tests;
