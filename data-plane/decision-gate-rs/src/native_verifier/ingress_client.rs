//! Fresh startup originals for a private single-connection trust store.
//!
//! This is not an installed CA or an independently admitted production release.
//! Startup expectations and the session's pinned static scope must agree. V1
//! pins the session challenge too; the additive path accepts a caller-owned
//! challenge without changing or re-encoding the pinned scope original.

use super::{config::TrustRoots, ensure, ingress::{self, EvidenceProfile},
    ingress_config::{Expectations, SessionScope}};
use serde_json::Value;

pub(crate) struct IngressClientBootstrap {
    pub(crate) leaf: Vec<u8>,
    pub(crate) ca: Vec<u8>,
    pub(crate) host: String,
    pub(crate) challenge: [u8; 32],
    pub(crate) valid_until_epoch_ns: u64,
    pub(crate) verification: Value,
}

pub(super) fn prepare(raw: &[u8], startup_raw: &[u8], session_raw: &[u8], roots_raw: &[u8])
    -> Result<IngressClientBootstrap, String> {
    let startup = Expectations::parse(startup_raw)?;
    let session = Expectations::parse(session_raw)?;
    ensure(startup.scope == session.scope && startup.nonce != session.nonce,
        "native client startup/session scopes differ or challenges were reused")?;
    prepare_checked(raw, startup_raw, roots_raw, &startup, session.scope, session.nonce)
}

pub(super) fn prepare_with_challenge(raw: &[u8], startup_raw: &[u8], scope_raw: &[u8],
    roots_raw: &[u8], challenge: [u8; 32]) -> Result<IngressClientBootstrap, String> {
    let startup = Expectations::parse(startup_raw)?;
    let scope = SessionScope::parse(scope_raw)?;
    ensure(challenge != [0; 32] && challenge != startup.nonce && startup.scope == scope,
        "native client startup/session scopes differ or challenge is zero or reused")?;
    prepare_checked(raw, startup_raw, roots_raw, &startup, scope, challenge)
}

fn prepare_checked(raw: &[u8], startup_raw: &[u8], roots_raw: &[u8],
    startup: &Expectations, scope: SessionScope, challenge: [u8; 32])
    -> Result<IngressClientBootstrap, String> {
    let roots = TrustRoots::parse(roots_raw)?;
    let checked = ingress::verify_original(raw, &startup.scope, &roots,
        EvidenceProfile::Startup, &startup.nonce)?;
    let fresh_until = checked.issued.checked_add(scope.max_age)
        .and_then(|value| value.checked_add(1)).ok_or("native client startup quote age overflow")?;
    let valid_until_epoch_ns = checked.valid_until.min(checked.quote_valid_until).min(fresh_until)
        .checked_mul(1_000_000_000).ok_or("native client startup expiry overflow")?;
    let verification = checked.summary(raw, startup_raw, roots_raw, startup);
    Ok(IngressClientBootstrap { leaf: checked.leaf, ca: checked.ca, host: scope.host,
        challenge, valid_until_epoch_ns, verification })
}
