//! Fresh startup originals for a private single-connection trust store.
//!
//! This is not an installed CA or an independently admitted production release.
//! Both original expectation sets are closed and must name the same scope;
//! only their separately held startup/session challenges may differ.

use super::{config::TrustRoots, ensure, ingress::{self, EvidenceProfile},
    ingress_config::Expectations};
use serde_json::Value;

pub(crate) struct IngressClientBootstrap {
    pub(crate) leaf: Vec<u8>,
    pub(crate) ca: Vec<u8>,
    pub(crate) host: String,
    pub(crate) challenge: [u8; 32],
    pub(crate) verification: Value,
}

pub(super) fn prepare(raw: &[u8], startup_raw: &[u8], session_raw: &[u8], roots_raw: &[u8])
    -> Result<IngressClientBootstrap, String> {
    let startup = Expectations::parse(startup_raw)?;
    let session = Expectations::parse(session_raw)?;
    ensure(startup.release_record == session.release_record
        && startup.policy == session.policy && startup.configuration == session.configuration
        && startup.client_trust == session.client_trust && startup.pcrs == session.pcrs
        && startup.module_id == session.module_id && startup.max_age == session.max_age
        && startup.future_skew == session.future_skew && startup.host == session.host
        && startup.instance == session.instance && startup.nonce != session.nonce,
        "native client startup/session scopes differ or challenges were reused")?;
    let roots = TrustRoots::parse(roots_raw)?;
    let checked = ingress::verify_original(raw, &startup, &roots,
        EvidenceProfile::Startup, &startup.nonce)?;
    let verification = checked.summary(raw, startup_raw, roots_raw, &startup);
    Ok(IngressClientBootstrap { leaf: checked.leaf, ca: checked.ca, host: session.host,
        challenge: session.nonce, verification })
}
