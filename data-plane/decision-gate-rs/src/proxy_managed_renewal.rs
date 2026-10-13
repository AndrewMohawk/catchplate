//! Finite operator-only verifier overlap. This is policy data, not enrollment
//! or renewal authority; a CONNECT never substitutes the replacement verifier.
use super::{constant_time_eq, GateState, ProxyAuthorizationPolicy, Snapshot};
use serde_json::{json, Map, Value};

const MAX_TIME: u128 = 9_007_199_254_740_991;
const MAX_OVERLAP: u128 = 300_000;
const SCHEMA: &str = "serverware.proxyTokenRenewal/v1";
const REFUSED: &str = "operator_managed_renewal_unavailable";

#[derive(Clone)]
pub(super) struct ManagedRenewal {
    token_id: String,
    enrollment_id: String,
    enrollment_expires_at_ms: u128,
    rotated_at_ms: u128,
    previous: Option<PreviousToken>,
}

#[derive(Clone)]
struct PreviousToken {
    token_sha256: String,
    original_expires_at_ms: u128,
    expires_at_ms: u128,
}

fn refused() -> String { "principal managed renewal contract invalid".to_owned() }

fn timestamp(fields: &Map<String, Value>, name: &str) -> Result<u128, String> {
    fields.get(name).and_then(Value::as_u64).map(u128::from)
        .filter(|value| *value > 0 && *value <= MAX_TIME).ok_or_else(refused)
}

fn identifier(fields: &Map<String, Value>, name: &str) -> Result<String, String> {
    fields.get(name).and_then(Value::as_str).filter(|value| {
        value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
            else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
        })
    }).map(str::to_owned).ok_or_else(refused)
}

impl ManagedRenewal {
    pub(super) fn from_policy(config: &Map<String, Value>) -> Result<Option<Self>, String> {
        let Some(raw) = config.get("managedRenewal") else { return Ok(None); };
        let allowed = ["scheme", "tokenId", "tokenSha256", "sourceCidrs", "expiresAtEpochMs", "basicTransport", "managedRenewal"];
        if config.keys().any(|name| !allowed.contains(&name.as_str()))
            || config.get("scheme").and_then(Value::as_str) != Some("Bearer")
        { return Err(refused()); }
        let token_id = identifier(config, "tokenId")?;
        let current = config.get("tokenSha256").and_then(Value::as_str)
            .filter(|value| super::is_sha256_digest(value)).ok_or_else(refused)?;
        let current_expiry = timestamp(config, "expiresAtEpochMs")?;
        let fields = raw.as_object().ok_or_else(refused)?;
        let required = ["schema", "enrollmentId", "enrollmentExpiresAtEpochMs", "rotatedAtEpochMs"];
        if !required.iter().all(|name| fields.contains_key(*name))
            || fields.keys().any(|name| !required.contains(&name.as_str()) && name != "previousToken")
            || fields.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        { return Err(refused()); }
        let enrollment_id = identifier(fields, "enrollmentId")?;
        let enrollment_expires_at_ms = timestamp(fields, "enrollmentExpiresAtEpochMs")?;
        let rotated_at_ms = timestamp(fields, "rotatedAtEpochMs")?;
        if rotated_at_ms >= enrollment_expires_at_ms || current_expiry > enrollment_expires_at_ms { return Err(refused()); }
        let previous = if let Some(raw) = fields.get("previousToken") {
            if current_expiry <= rotated_at_ms { return Err(refused()); }
            let fields = raw.as_object().ok_or_else(refused)?;
            if fields.len() != 3 || !["tokenSha256", "originalExpiresAtEpochMs", "expiresAtEpochMs"]
                .iter().all(|name| fields.contains_key(*name)) { return Err(refused()); }
            let token_sha256 = fields.get("tokenSha256").and_then(Value::as_str)
                .filter(|value| super::is_sha256_digest(value) && !constant_time_eq(value, current))
                .ok_or_else(refused)?.to_owned();
            let original_expires_at_ms = timestamp(fields, "originalExpiresAtEpochMs")?;
            let expires_at_ms = timestamp(fields, "expiresAtEpochMs")?;
            if expires_at_ms <= rotated_at_ms || expires_at_ms > original_expires_at_ms
                || expires_at_ms - rotated_at_ms > MAX_OVERLAP
                || original_expires_at_ms > enrollment_expires_at_ms { return Err(refused()); }
            Some(PreviousToken { token_sha256, original_expires_at_ms, expires_at_ms })
        } else { None };
        Ok(Some(Self { token_id, enrollment_id, enrollment_expires_at_ms, rotated_at_ms, previous }))
    }

    pub(super) fn value(&self) -> Value {
        let mut value = json!({"schema":SCHEMA, "enrollmentId":self.enrollment_id,
            "enrollmentExpiresAtEpochMs":self.enrollment_expires_at_ms as u64,
            "rotatedAtEpochMs":self.rotated_at_ms as u64});
        if let Some(previous) = &self.previous {
            value["previousToken"] = json!({"tokenSha256":previous.token_sha256,
                "originalExpiresAtEpochMs":previous.original_expires_at_ms as u64,
                "expiresAtEpochMs":previous.expires_at_ms as u64});
        }
        value
    }

    pub(super) fn continuity_value(&self) -> Value {
        json!({"schema":SCHEMA, "tokenId":self.token_id, "enrollmentId":self.enrollment_id,
            "enrollmentExpiresAtEpochMs":self.enrollment_expires_at_ms as u64})
    }

    pub(super) fn token_id(&self) -> &str { &self.token_id }

    pub(super) fn accepted_original_expiry(&self, provided: &str, current: &str,
        current_expiry: Option<u128>, now: u128) -> Option<u128> {
        let expiry = current_expiry.filter(|expiry| *expiry > 0
            && *expiry <= self.enrollment_expires_at_ms)?;
        if now >= self.enrollment_expires_at_ms { return None; }
        if constant_time_eq(provided, current) && now < expiry { return Some(expiry); }
        self.previous.as_ref().filter(|previous| constant_time_eq(provided, &previous.token_sha256)
            && now < previous.expires_at_ms && now < previous.original_expires_at_ms)
            .map(|previous| previous.original_expires_at_ms)
    }
}

pub(super) fn validate_raw_policy(raw: &Value) -> Result<(), String> {
    for principal in raw.get("principals").and_then(Value::as_array).into_iter().flatten() {
        let Some(config) = principal.get("proxyAuthorization").and_then(Value::as_object) else { continue; };
        if !config.contains_key("managedRenewal") { continue; }
        if raw.get("apiVersion").and_then(Value::as_str) != Some("serverware.policy/v1")
            || raw.get("metadata").and_then(|value| value.get("id")).and_then(Value::as_str)
                != Some("serverware-operator-demo") { return Err(REFUSED.to_owned()); }
        ManagedRenewal::from_policy(config)?;
    }
    Ok(())
}

pub(super) fn require_scope(snapshot: &Snapshot, admitted_operator: bool) -> Result<(), &'static str> {
    let selected = snapshot.principals.iter().any(|principal| matches!(&principal.proxy_authorization,
        Some(ProxyAuthorizationPolicy::BearerToken { managed_renewal: Some(_), .. })));
    if selected && (!admitted_operator || snapshot.policy_id != "serverware-operator-demo") {
        Err(REFUSED)
    } else { Ok(()) }
}

pub(super) fn require_runtime(state: &GateState, snapshot: &Snapshot) -> Result<(), &'static str> {
    require_scope(snapshot, super::proxy_basic_transport::admitted_runtime(state))
}

#[cfg(test)]
#[path = "proxy_managed_renewal_tests.rs"]
mod tests;
