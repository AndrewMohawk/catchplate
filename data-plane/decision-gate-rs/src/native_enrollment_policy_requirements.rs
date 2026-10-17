//! Secret-free requirements projected from the actual compiled Snapshot.
//!
//! This is onboarding data, not target authentication, a provider-request
//! decision, canary permission, credential material, or packet-signing power.
//! Arbitrary adapter/constraint/JIT values and identity header/authentication
//! values stay behind their existing runtime commitments. The caller retains
//! the Snapshot and original request/session lifetime around this operation.

use super::{canonical_cidr_strings, canonical_json_ensure_ascii,
    digest_json_ensure_ascii, MtlsIdentityPolicy, PathSegment, Principal,
    ProxyAuthorizationPolicy, ResolvedAddressPolicy, ResponseObservationRouteVersion,
    Route, Snapshot};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(super) const MAX_BYTES: usize = 64 * 1024;
const MAX_PRINCIPALS: usize = 4096;
const MAX_ROUTES: usize = 8192;
const MAX_ENTITLED_ROUTES: usize = 128;
const MAX_GRAPH_BYTES: usize = 2 * 1024 * 1024;
const MAX_NODES: usize = 65_536;
const MAX_DEPTH: usize = 64;

fn invalid() -> String { "native enrollment policy requirements are invalid or exceed bounds".into() }
fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err(invalid()) }
}

struct Work {
    deadline: u64,
    pid: u32,
    last_boot: u64,
    nodes: usize,
    bytes: usize,
}

impl Work {
    fn check(&mut self) -> Result<(), String> {
        let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
        require(self.pid == std::process::id()
            && unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } == 0
            && clock.tv_sec >= 0 && (0..1_000_000_000).contains(&clock.tv_nsec))?;
        let now = (clock.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(clock.tv_nsec as u64)).ok_or_else(invalid)?;
        require(now >= self.last_boot && now < self.deadline)?;
        self.last_boot = now;
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), String> {
        self.check()?;
        self.nodes = self.nodes.checked_add(1).ok_or_else(invalid)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(invalid)?;
        require(self.nodes <= MAX_NODES && self.bytes <= MAX_GRAPH_BYTES)
    }

    fn text(&mut self, value: &str) -> Result<(), String> { self.charge(value.len()) }

    fn strings(&mut self, values: &[String]) -> Result<(), String> {
        self.charge(values.len())?;
        require(values.len() <= MAX_NODES)?;
        for value in values { self.text(value)?; }
        Ok(())
    }

    fn value(&mut self, value: &Value, depth: usize) -> Result<(), String> {
        require(depth <= MAX_DEPTH)?;
        self.charge(1)?;
        match value {
            Value::String(text) => self.text(text)?,
            Value::Array(values) => {
                require(values.len() <= MAX_NODES)?;
                for item in values { self.value(item, depth + 1)?; }
            }
            Value::Object(values) => {
                require(values.len() <= MAX_NODES)?;
                for (name, item) in values {
                    self.text(name)?;
                    self.value(item, depth + 1)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {},
        }
        Ok(())
    }

    fn digest(&mut self, value: &Value) -> Result<String, String> {
        // Preflight before the existing helper makes a bounded canonical copy.
        // Its commitment profile is intentionally unchanged, including DEL.
        self.value(value, 0)?;
        let digest = digest_json_ensure_ascii(value);
        self.check()?;
        Ok(digest)
    }
}

fn mtls_preflight(value: &MtlsIdentityPolicy, work: &mut Work) -> Result<(), String> {
    work.strings(&value.san_spiffe_ids)?;
    work.strings(&value.san_dns_names)?;
    work.strings(&value.san_uris)?;
    for value in [&value.certificate_sha256, &value.spki_sha256, &value.issuer_spki_sha256] {
        if let Some(value) = value { work.text(value)?; }
    }
    Ok(())
}

fn principal_value(principal: &Principal, work: &mut Work) -> Result<Value, String> {
    work.text(&principal.id)?;
    work.charge(principal.source_cidrs.len().checked_mul(64).ok_or_else(invalid)?)?;
    for (name, value) in &principal.required_headers {
        work.text(name)?;
        work.text(value)?;
    }
    if let Some(mtls) = &principal.mtls { mtls_preflight(mtls, work)?; }
    let proxy_authorization = match &principal.proxy_authorization {
        None => Value::Null,
        Some(ProxyAuthorizationPolicy::LegacyExact(secret)) => {
            work.text(secret)?;
            json!({"type":"legacyExact", "externallyProvisioned":true,
                "sourceCidrs":[], "expiresAtEpochMs":null})
        }
        Some(ProxyAuthorizationPolicy::BearerToken { token_sha256, source_cidrs, expires_at_ms, basic_transport, managed_renewal }) => {
            if basic_transport.is_some() || managed_renewal.is_some() { return Err(invalid()); }
            work.text(token_sha256)?;
            work.charge(source_cidrs.len().checked_mul(64).ok_or_else(invalid)?)?;
            json!({"type":"bearerToken", "externallyProvisioned":true,
                "sourceCidrs":canonical_cidr_strings(source_cidrs),
                "expiresAtEpochMs":expires_at_ms.map(|value| value.to_string())})
        }
    };
    // Reuse the actual identity-policy commitment rather than inventing a
    // weakened identity from this deliberately redacted requirements record.
    work.check()?;
    let identity = principal.identity_policy_digest();
    work.check()?;
    let mtls = principal.mtls.as_ref().map(|value| json!({
        "sanSpiffeIds":value.san_spiffe_ids, "sanDnsNames":value.san_dns_names,
        "sanUris":value.san_uris, "certificateSha256":value.certificate_sha256,
        "spkiSha256":value.spki_sha256, "issuerSpkiSha256":value.issuer_spki_sha256,
    }));
    Ok(json!({"id":principal.id, "identityPolicySha256":identity,
        "sourceCidrs":canonical_cidr_strings(&principal.source_cidrs), "mtls":mtls,
        "requiredHeaderNames":principal.required_headers.keys().collect::<Vec<_>>(),
        "requiredHeaderValues":"externally-provisioned", "proxyAuthorization":proxy_authorization}))
}

fn route_value(snapshot: &Snapshot, route: &Route, work: &mut Work) -> Result<Value, String> {
    for value in [&route.id, &route.scheme, &route.host, &route.adapter_type] { work.text(value)?; }
    work.strings(&route.discard_headers)?;
    work.charge(route.methods.len())?;
    for method in &route.methods { work.text(method)?; }
    if let Some(reference) = &route.credential_ref {
        work.text(reference)?;
        require(snapshot.credentials.contains_key(reference))?;
    }
    let resolved = match &route.resolved_address_policy {
        ResolvedAddressPolicy::PublicOnly => json!({"type":"public-only"}),
        ResolvedAddressPolicy::ExplicitCidrs(cidrs) => {
            work.charge(cidrs.len().checked_mul(64).ok_or_else(invalid)?)?;
            json!({"type":"explicit-cidrs", "cidrs":canonical_cidr_strings(cidrs)})
        }
    };
    work.charge(route.paths.len())?;
    require(route.paths.len() <= MAX_NODES)?;
    let mut paths = Vec::new();
    for path in &route.paths {
        work.charge(path.segments.len())?;
        require(path.segments.len() <= MAX_NODES)?;
        let mut segments = Vec::new();
        for segment in &path.segments {
            let segment = match segment {
                PathSegment::Literal(value) => { work.text(value)?; json!({"literal":value}) }
                PathSegment::Variable(value) => { work.text(value)?; json!({"variable":value}) }
                PathSegment::Wildcard => { work.charge(1)?; json!({"wildcard":true}) }
                PathSegment::Glob => { work.charge(1)?; json!({"glob":true}) }
            };
            segments.push(segment);
        }
        paths.push(segments);
    }
    let adapter_digest = work.digest(&route.adapter_config)?;
    let request = route.adapter_config.get("request").filter(|value| value.is_object()).ok_or_else(invalid)?;
    let request_digest = work.digest(request)?;
    let response_digest = route.adapter_config.get("response").map(|value| work.digest(value)).transpose()?;
    let required_provider_headers = match request.get("requiredHeaders") {
        None => Vec::new(),
        Some(Value::Object(headers)) => {
            let mut names = headers.keys().cloned().collect::<Vec<_>>();
            names.sort();
            names
        }
        Some(_) => return Err(invalid()),
    };
    // Constraints can also contain secrets. Only their exact runtime digest
    // leaves this function; preflight every item before making the array copy.
    work.charge(route.constraints.len())?;
    for value in &route.constraints { work.value(value, 1)?; }
    work.check()?;
    let constraints_digest = digest_json_ensure_ascii(&Value::Array(route.constraints.clone()));
    work.check()?;
    let jit_digest = work.digest(&route.jit)?;
    let jit_required = route.jit.get("required").and_then(Value::as_bool).unwrap_or(false);
    let observation = match &route.response_observation {
        None => Value::Null,
        Some(value) => {
            if let Some(id) = &value.publication_target_id { work.text(id)?; }
            if let Some(digest) = &value.publication_target_policy_sha256 { work.text(digest)?; }
            json!({"version":match value.version {
                    ResponseObservationRouteVersion::V1 => "v1", ResponseObservationRouteVersion::V2 => "v2" },
                "lifecycleTimeoutNanos":value.lifecycle_timeout.as_nanos().to_string(),
                "publicationTargetId":value.publication_target_id,
                "publicationTargetPolicySha256":value.publication_target_policy_sha256})
        }
    };
    let mut methods = route.methods.iter().collect::<Vec<_>>();
    methods.sort();
    Ok(json!({"id":route.id, "scheme":route.scheme, "host":route.host, "port":route.port,
        "resolvedAddressPolicy":resolved, "methods":methods, "paths":paths,
        "credentialRef":route.credential_ref, "adapterType":route.adapter_type,
        "discardHeaders":route.discard_headers, "adapterConfigSha256":adapter_digest,
        "requestPolicySha256":request_digest, "responsePolicySha256":response_digest,
        "requiredProviderHeaderNames":required_provider_headers,
        "constraintsSha256":constraints_digest, "jitSha256":jit_digest,
        "jitRequired":jit_required, "responseObservation":observation}))
}

fn public_string_size(value: &str, work: &mut Work) -> Result<usize, String> {
    work.check()?;
    let mut size = 2usize;
    for character in value.chars() {
        let width = match character {
            '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
            '\u{20}'..='\u{7e}' => 1,
            '\u{0}'..='\u{ffff}' => 6,
            _ => 12,
        };
        size = size.checked_add(width).ok_or_else(invalid)?;
        require(size <= MAX_BYTES)?;
    }
    work.check()?;
    Ok(size)
}

// Exact ASCII-JSON representation bound before the public encoder allocates
// its String, including DEL and supplementary Unicode. This measures only the
// public graph; it neither emits JSON nor processes hidden policy values.
fn public_size(value: &Value, depth: usize, work: &mut Work) -> Result<usize, String> {
    require(depth <= MAX_DEPTH)?;
    work.check()?;
    let size = match value {
        Value::String(value) => public_string_size(value, work)?,
        Value::Null => 4,
        Value::Bool(value) => if *value { 4 } else { 5 },
        Value::Number(value) => value.to_string().len(),
        Value::Array(values) => {
            let mut size = 2usize;
            for (index, value) in values.iter().enumerate() {
                let child = public_size(value, depth + 1, work)?;
                size = size.checked_add(child).and_then(|size| size.checked_add(usize::from(index != 0)))
                    .ok_or_else(invalid)?;
                require(size <= MAX_BYTES)?;
            }
            size
        }
        Value::Object(values) => {
            let mut size = 2usize;
            for (index, (name, value)) in values.iter().enumerate() {
                let child = public_size(value, depth + 1, work)?;
                size = size.checked_add(public_string_size(name, work)?).and_then(|size| size.checked_add(child))
                    .and_then(|size| size.checked_add(1 + usize::from(index != 0))).ok_or_else(invalid)?;
                require(size <= MAX_BYTES)?;
            }
            size
        }
    };
    require(size <= MAX_BYTES)?;
    Ok(size)
}

/// Complete current target requirements, not proof that the target satisfies
/// them. The native caller must recheck its actual admission before and after
/// consuming these bytes. No clock allowance or packet authority is created.
pub(super) fn project(snapshot: &Snapshot, principal_id: &str, deadline: u64) -> Result<Vec<u8>, String> {
    require(!principal_id.is_empty() && principal_id.len() <= 1024
        && snapshot.principals.len() <= MAX_PRINCIPALS && snapshot.routes.len() <= MAX_ROUTES)?;
    let mut work = Work { deadline, pid: std::process::id(), last_boot: 0, nodes: 0, bytes: 0 };
    work.check()?;
    let mut selected = None;
    for principal in &snapshot.principals {
        work.text(&principal.id)?;
        if principal.id == principal_id {
            require(selected.is_none())?;
            selected = Some(principal);
        }
    }
    let principal = selected.ok_or_else(invalid)?;
    let principal = principal_value(principal, &mut work)?;
    let mut selected_routes = Vec::new();
    let mut route_ids = BTreeSet::new();
    for route in &snapshot.routes {
        let mut entitled = false;
        work.charge(route.principals.len())?;
        for id in &route.principals {
            work.text(id)?;
            entitled |= id == principal_id || id == "*";
        }
        if entitled {
            work.text(&route.id)?;
            require(selected_routes.len() < MAX_ENTITLED_ROUTES && route_ids.insert(route.id.as_str()))?;
            selected_routes.push(route);
        }
    }
    selected_routes.sort_by(|left, right| left.id.cmp(&right.id));
    let mut routes = Vec::new();
    for route in selected_routes { routes.push(route_value(snapshot, route, &mut work)?); }
    for value in [&snapshot.hash, &snapshot.policy_id, &snapshot.compiled_behavior_sha256,
        &snapshot.policy_signing_key_id] { work.text(value)?; }
    let public = json!({"apiVersion":"catchplate.nativeEnrollmentPolicyRequirements/v1",
        "policy":{"hash":snapshot.hash, "id":snapshot.policy_id,
            "sequence":snapshot.policy_sequence, "rollbackEpoch":snapshot.rollback_epoch,
            "trustGeneration":snapshot.trust_generation,
            "compiledBehaviorSha256":snapshot.compiled_behavior_sha256,
            "policySigningKeyId":snapshot.policy_signing_key_id},
        "principal":principal, "routes":routes});
    let expected_bytes = public_size(&public, 0, &mut work)?;
    work.check()?;
    // Preserve existing hidden commitments. Normalize DEL only in this public
    // output to pair Python's sorted compact ensure_ascii=True wire profile.
    let original = canonical_json_ensure_ascii(&public).replace('\u{7f}', "\\u007f").into_bytes();
    require(!original.is_empty() && original.len() == expected_bytes
        && original.len() <= MAX_BYTES && original.is_ascii())?;
    work.check()?;
    Ok(original)
}
