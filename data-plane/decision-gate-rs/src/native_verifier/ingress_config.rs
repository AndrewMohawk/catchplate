//! Closed independently pinned role-3 expectations and nonce-free session scope.
//!
//! These ordinary configuration values confer no release, enrollment or live
//! serving authority. No expectation is learned from the evidence being read.

use super::{config::parse_pcr_inventory, ensure, exact, fixed_b64, json, parse_digest, text, uint};
use rustls::pki_types::ServerName;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;
use url::Url;

pub(super) struct Expectations {
    pub(super) scope: SessionScope,
    pub(super) nonce: [u8; 32],
}

#[derive(Eq, PartialEq)]
pub(super) struct SessionScope {
    pub(super) release_record: [u8; 32],
    pub(super) policy: [u8; 32],
    pub(super) configuration: [u8; 32],
    pub(super) client_trust: [u8; 32],
    pub(super) pcrs: BTreeMap<u8, [u8; 48]>,
    pub(super) module_id: String,
    pub(super) max_age: u64,
    pub(super) future_skew: u64,
    pub(super) host: String,
    pub(super) instance: String,
}

impl Expectations {
    pub(super) fn parse(raw: &[u8]) -> Result<Self, String> {
        let value = json::parse(raw, 16 * 1024)?;
        exact(&value, &[
            "apiVersion", "releaseRecordSha256", "policyHash", "configurationSha256",
            "clientTrustBundleSha256", "expectedPcrs", "expectedEif", "expectedModuleId",
            "maxAgeSeconds", "futureSkewSeconds", "nonceBase64url", "ingressHost", "serverInstanceId",
        ])?;
        ensure(text(&value, "apiVersion")? == "serverware.nativeIngressAttestationExpectations/v1",
            "native ingress expectations version differs")?;
        let scope = SessionScope::parse_fields(&value)?;
        let nonce = fixed_b64::<32>(text(&value, "nonceBase64url")?)?;
        ensure(nonce != [0; 32], "native ingress expected nonce must be nonzero")?;
        Ok(Self { scope, nonce })
    }
}

impl SessionScope {
    pub(super) fn parse(raw: &[u8]) -> Result<Self, String> {
        let value = json::parse(raw, 16 * 1024)?;
        exact(&value, &[
            "apiVersion", "releaseRecordSha256", "policyHash", "configurationSha256",
            "clientTrustBundleSha256", "expectedPcrs", "expectedEif", "expectedModuleId",
            "maxAgeSeconds", "futureSkewSeconds", "ingressHost", "serverInstanceId",
        ])?;
        ensure(text(&value, "apiVersion")? == "serverware.nativeIngressSessionScope/v1",
            "native ingress session scope version differs")?;
        Self::parse_fields(&value)
    }

    // Both closed originals use these identical typed field checks. The
    // caller-owned challenge is never inserted into or re-encoded as a pin.
    fn parse_fields(value: &Value) -> Result<Self, String> {
        let pin = |field| parse_digest::<32>(text(&value, field)?, "sha256:", true);
        let pcrs = parse_pcr_inventory(&value["expectedPcrs"])?;
        let eif = parse_digest::<48>(text(&value, "expectedEif")?, "sha384:", true)?;
        ensure(pcrs.get(&0) == Some(&eif), "native expected EIF differs from PCR0")?;
        let module_id = text(&value, "expectedModuleId")?;
        ensure(!module_id.is_empty() && module_id.len() <= 256
            && module_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "native module ID is not bounded printable ASCII")?;
        let max_age = uint(&value, "maxAgeSeconds")?;
        let future_skew = uint(&value, "futureSkewSeconds")?;
        ensure((1..=300).contains(&max_age) && future_skew <= 30, "native age limits differ")?;
        let host = text(&value, "ingressHost")?;
        ensure(canonical_host(host), "native ingress host is not canonical bounded DNS or IP")?;
        let instance = text(&value, "serverInstanceId")?;
        ensure(canonical_spiffe(instance), "native ingress instance is not a canonical bounded SPIFFE ID")?;
        Ok(Self {
            release_record: pin("releaseRecordSha256")?,
            policy: pin("policyHash")?,
            configuration: pin("configurationSha256")?,
            client_trust: pin("clientTrustBundleSha256")?,
            pcrs, module_id: module_id.to_owned(), max_age, future_skew,
            host: host.to_owned(), instance: instance.to_owned(),
        })
    }
}

fn canonical_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.is_ascii()
        || value != value.to_ascii_lowercase() || value.contains('*') || value.ends_with('.') {
        return false;
    }
    match value.parse::<IpAddr>() {
        Ok(address) => address.to_string() == value,
        Err(_) => dns_trust_domain(value)
            && matches!(ServerName::try_from(value), Ok(ServerName::DnsName(_))),
    }
}

// Same lower-case LDH trust-domain and canonical URL/path rules as the main
// data plane's canonical_spiffe_id, with an explicit ASCII configuration bound.
fn dns_trust_domain(value: &str) -> bool {
    value == value.to_ascii_lowercase() && !value.is_empty() && value.len() <= 253
        && value.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && label.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-') && !label.ends_with('-'))
}

fn canonical_spiffe(value: &str) -> bool {
    if !value.starts_with("spiffe://") || value.len() > 2048 || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| url.as_str() == value && url.scheme() == "spiffe"
        && url.username().is_empty() && url.password().is_none()
        && url.host_str().is_some_and(dns_trust_domain)
        && url.port().is_none() && url.query().is_none() && url.fragment().is_none()
        && !url.path().contains("//")
        && !url.path().split('/').any(|segment| matches!(segment, "." | "..")))
}
