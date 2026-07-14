use base64::{engine::general_purpose, Engine as _};
use csv::{ByteRecord, ReaderBuilder, WriterBuilder};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ipnet::IpNet;
use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use reqwest::blocking::{Body, Client};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, HOST};
use reqwest::{Method, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::{form_urlencoded, Url};

#[derive(Clone)]
struct Snapshot {
    hash: String,
    policy_signing_key_id: String,
    principals: Vec<Principal>,
    credentials: HashMap<String, Credential>,
    routes: Vec<Route>,
}

#[derive(Clone)]
struct Principal {
    id: String,
    source_cidrs: Vec<IpNet>,
    required_headers: BTreeMap<String, String>,
    proxy_authorization: Option<ProxyAuthorizationPolicy>,
}

#[derive(Clone)]
struct Credential {
    injection: Value,
}

#[derive(Clone)]
enum ProxyAuthorizationPolicy {
    LegacyExact(String),
    BearerToken {
        token_sha256: String,
        source_cidrs: Vec<IpNet>,
        expires_at_ms: Option<u128>,
    },
}

#[derive(Clone)]
struct Route {
    id: String,
    principals: Vec<String>,
    scheme: String,
    host: String,
    port: u16,
    methods: HashSet<String>,
    paths: Vec<PathTemplate>,
    credential_ref: Option<String>,
    adapter_type: String,
    adapter_config: Value,
    constraints: Vec<Value>,
    jit: Value,
}

#[derive(Clone)]
struct PathTemplate {
    segments: Vec<PathSegment>,
}

#[derive(Clone)]
enum PathSegment {
    Literal(String),
    Variable(String),
    Glob,
}

#[derive(Deserialize)]
struct DecisionRequest {
    #[serde(rename = "clientIp")]
    client_ip: Option<String>,
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
    #[serde(default, rename = "bodySha256")]
    body_sha256: Option<String>,
    #[serde(default, rename = "credentialMetadata")]
    credential_metadata: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default, rename = "gmailProofs")]
    gmail_proofs: Vec<String>,
}

struct RouteMatch<'a> {
    route: &'a Route,
    params: BTreeMap<String, String>,
}

struct IncomingRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    client_ip: Option<String>,
}

struct RequestHead {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    content_length: usize,
    has_content_length: bool,
    prefetched_body: Vec<u8>,
    client_ip: Option<String>,
}

struct ResponsePolicy {
    adapter_type: String,
    response_config: Value,
}

#[derive(Clone)]
struct StreamingRequestPolicy {
    mode: String,
    max_body_bytes: u64,
    max_line_bytes: usize,
    max_item_bytes: usize,
    max_event_bytes: usize,
    max_pair_bytes: usize,
    max_record_bytes: usize,
    max_nested_bytes: usize,
    allowed_fields: Vec<Vec<String>>,
}

struct StreamingResponsePolicy {
    adapter_type: String,
    mode: String,
    max_body_bytes: Option<u64>,
    max_line_bytes: usize,
    max_item_bytes: usize,
    max_event_bytes: usize,
    max_pair_bytes: usize,
    max_record_bytes: usize,
    max_nested_bytes: usize,
    allowed_fields: Vec<Vec<String>>,
}

enum ForwardResult {
    Buffered(Vec<u8>),
    Streamed,
}

enum RequestStreamingPreflight {
    Buffer,
    Stream(StreamingRequestPolicy),
    Reject(Vec<u8>),
}

struct GateState {
    snapshot: RwLock<Arc<Snapshot>>,
    policy_path: String,
    policy_trust_root_source: PolicyTrustRootSource,
    policy_mtime: Mutex<Option<SystemTime>>,
    policy_reload_success: AtomicU64,
    policy_reload_failed: AtomicU64,
    grants: Mutex<HashMap<String, Grant>>,
    gmail_proofs: Mutex<HashMap<(String, String, String), u128>>,
    gmail_proof_cache_max: usize,
    constraint_rate_counters: Mutex<HashMap<String, ConstraintRateCounter>>,
    credential_generations: Mutex<HashMap<String, Option<u64>>>,
    generation_mtime: Mutex<Option<SystemTime>>,
    generation_path: String,
    credential_leases: Mutex<HashMap<String, Option<SecretLease>>>,
    lease_mtime: Mutex<Option<SystemTime>>,
    lease_path: String,
    upstream_client: Client,
    audit_client: Client,
    audit_url: Option<String>,
    audit_token: Option<String>,
    grant_consume_url: Option<String>,
    rate_limit_consume_url: Option<String>,
    audit_queue: Mutex<VecDeque<AuditEvent>>,
    audit_queue_max: usize,
    audit_batch_max: usize,
    audit_enqueued: AtomicU64,
    audit_dropped: AtomicU64,
    audit_required_failed: AtomicU64,
    audit_sent: AtomicU64,
    audit_send_failed: AtomicU64,
    mitm_authority: Option<Mutex<MitmAuthority>>,
    leaf_configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
    binary_digest: String,
    release_provenance_path: Option<String>,
    image_signatures_path: Option<String>,
}

#[derive(Clone)]
struct ConstraintRateCounter {
    window_start_ms: u128,
    count: u64,
}

#[derive(Clone)]
enum PolicyTrustRootSource {
    File(String),
    AttestedControlPlane {
        url: String,
        expected_quote_key_id: Option<String>,
    },
}

impl PolicyTrustRootSource {
    fn label(&self) -> &'static str {
        match self {
            PolicyTrustRootSource::File(_) => "file",
            PolicyTrustRootSource::AttestedControlPlane { .. } => "attested-control-plane",
        }
    }
}

struct PolicyTrustRoot {
    verifying_key: VerifyingKey,
    key_id: String,
    attested_policy_hash: Option<String>,
}

#[derive(Clone, Serialize)]
struct AuditEvent {
    event_type: String,
    actor_id: String,
    event: Value,
}

struct MitmAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_der: Vec<u8>,
}

#[derive(Clone)]
struct SecretLease {
    version: u64,
    secret: String,
    metadata: BTreeMap<String, String>,
}

#[derive(Clone)]
struct Grant {
    id: String,
    approval_id: Option<String>,
    credential_ref: String,
    credential_version: u64,
    uses_remaining: u64,
    expires_at_ms: u128,
}

#[derive(Deserialize)]
struct GrantCreate {
    #[serde(default, rename = "grantId")]
    grant_id: Option<String>,
    #[serde(default, rename = "approvalId")]
    approval_id: Option<String>,
    #[serde(rename = "principalId")]
    principal_id: String,
    #[serde(rename = "routeId")]
    route_id: String,
    #[serde(rename = "credentialRef")]
    credential_ref: String,
    #[serde(rename = "credentialVersion")]
    credential_version: u64,
    #[serde(rename = "policyHash")]
    policy_hash: String,
    #[serde(rename = "requestDigest")]
    request_digest: String,
    #[serde(rename = "operationDigest")]
    operation_digest: String,
    #[serde(default = "default_grant_uses", rename = "maxUses")]
    max_uses: u64,
    #[serde(default = "default_grant_ttl", rename = "ttlSeconds")]
    ttl_seconds: u64,
}

struct ConsumedGrant {
    id: String,
    approval_id: Option<String>,
}

struct PendingApproval {
    id: String,
    expires_at: Option<String>,
}

fn default_grant_uses() -> u64 {
    1
}

fn default_grant_ttl() -> u64 {
    30
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization failed")
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn signature_payload(raw: &Value) -> Value {
    let mut copied = raw.clone();
    if let Some(metadata) = copied.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.remove("signature");
    }
    copied
}

fn compile_template(template: &str) -> Result<PathTemplate, String> {
    if !template.starts_with('/') {
        return Err(format!("path template must start with /: {template}"));
    }
    let mut segments = Vec::new();
    for segment in template.trim_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment == "**" {
            segments.push(PathSegment::Glob);
        } else if segment.starts_with('{') && segment.ends_with('}') {
            segments.push(PathSegment::Variable(
                segment[1..segment.len() - 1].to_string(),
            ));
        } else {
            segments.push(PathSegment::Literal(segment.to_string()));
        }
    }
    Ok(PathTemplate { segments })
}

impl PathTemplate {
    fn matches(&self, path: &str) -> Option<BTreeMap<String, String>> {
        let actual: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut params = BTreeMap::new();
        let mut index = 0usize;
        for segment in &self.segments {
            match segment {
                PathSegment::Glob => return Some(params),
                PathSegment::Literal(expected) => {
                    if actual.get(index).copied() != Some(expected.as_str()) {
                        return None;
                    }
                }
                PathSegment::Variable(name) => {
                    let value = actual.get(index)?;
                    params.insert(name.clone(), (*value).to_string());
                }
            }
            index += 1;
        }
        if index == actual.len() {
            Some(params)
        } else {
            None
        }
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

fn ip_in_any_network(client_ip: Option<&str>, networks: &[IpNet]) -> bool {
    if networks.is_empty() {
        return true;
    }
    let Some(raw_ip) = client_ip else {
        return false;
    };
    let Ok(ip) = raw_ip.parse::<IpAddr>() else {
        return false;
    };
    networks.iter().any(|network| network.contains(&ip))
}

fn bearer_token_from_proxy_authorization<'a>(header: &'a str, scheme: &str) -> Option<&'a str> {
    let (actual_scheme, token) = header.trim().split_once(' ')?;
    if token.is_empty() || !actual_scheme.eq_ignore_ascii_case(scheme) {
        return None;
    }
    Some(token)
}

impl ProxyAuthorizationPolicy {
    fn matches(&self, client_ip: Option<&str>, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        match self {
            ProxyAuthorizationPolicy::LegacyExact(expected) => constant_time_eq(header, expected),
            ProxyAuthorizationPolicy::BearerToken {
                token_sha256,
                source_cidrs,
                expires_at_ms,
            } => {
                if expires_at_ms.is_some_and(|expires_at_ms| now_epoch_ms() >= expires_at_ms) {
                    return false;
                }
                if !ip_in_any_network(client_ip, source_cidrs) {
                    return false;
                }
                let Some(token) = bearer_token_from_proxy_authorization(header, "Bearer") else {
                    return false;
                };
                constant_time_eq(&sha256_prefixed(token.as_bytes()), token_sha256)
            }
        }
    }
}

impl Principal {
    fn matches(&self, client_ip: Option<&str>, headers: &BTreeMap<String, String>) -> bool {
        if !ip_in_any_network(client_ip, &self.source_cidrs) {
            return false;
        }
        self.required_headers.iter().all(|(name, expected)| {
            headers.get(name).map(String::as_str) == Some(expected.as_str())
        }) && self.proxy_authorization.as_ref().is_none_or(|policy| {
            policy.matches(
                client_ip,
                headers.get("proxy-authorization").map(String::as_str),
            )
        })
    }
}

impl Snapshot {
    fn identify_principal(
        &self,
        client_ip: Option<&str>,
        headers: &BTreeMap<String, String>,
    ) -> Option<&Principal> {
        self.principals
            .iter()
            .find(|principal| principal.matches(client_ip, headers))
    }

    fn match_route(&self, principal_id: &str, method: &str, url: &Url) -> Option<RouteMatch<'_>> {
        let scheme = url.scheme().to_ascii_lowercase();
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        let normalized_method = method.to_ascii_uppercase();
        for route in &self.routes {
            if route.scheme != scheme || route.host != host || route.port != port {
                continue;
            }
            if !route.methods.contains(&normalized_method) {
                continue;
            }
            if !route
                .principals
                .iter()
                .any(|item| item == principal_id || item == "*")
            {
                continue;
            }
            for template in &route.paths {
                if let Some(params) = template.matches(url.path()) {
                    return Some(RouteMatch { route, params });
                }
            }
        }
        None
    }

    fn match_connect_routes(&self, principal_id: &str, host: &str, port: u16) -> Vec<String> {
        self.routes
            .iter()
            .filter(|route| {
                route.scheme == "https"
                    && route.host == host
                    && route.port == port
                    && route
                        .principals
                        .iter()
                        .any(|item| item == principal_id || item == "*")
            })
            .map(|route| route.id.clone())
            .collect()
    }
}

fn verifying_key_from_spki_pem_text(
    pem_text: &str,
    context: &str,
) -> Result<(VerifyingKey, String), String> {
    let body = pem_text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|err| format!("decode {context} public key PEM: {err}"))?;
    let key_hash = sha256_prefixed(&der);
    let prefix: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    if der.len() != prefix.len() + 32 || der[..prefix.len()] != prefix {
        return Err(format!(
            "{context} public key must be an Ed25519 SubjectPublicKeyInfo PEM"
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&der[prefix.len()..]);
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| format!("invalid Ed25519 public key: {err}"))?;
    Ok((verifying_key, key_hash))
}

fn public_key_from_spki_pem(path: &str) -> Result<(VerifyingKey, String), String> {
    let pem_text =
        fs::read_to_string(path).map_err(|err| format!("read policy public key: {err}"))?;
    verifying_key_from_spki_pem_text(&pem_text, "policy")
}

fn unsigned_quote(raw: &Value) -> Value {
    let mut copied = raw.clone();
    if let Some(object) = copied.as_object_mut() {
        object.remove("signature");
    }
    copied
}

fn append_nonce_query(url: &str, nonce: &str) -> Result<String, String> {
    let mut parsed =
        Url::parse(url).map_err(|err| format!("parse policy trust root attestation URL: {err}"))?;
    parsed.query_pairs_mut().append_pair("nonce", nonce);
    Ok(parsed.to_string())
}

fn verify_dev_quote_signature(
    quote: &Value,
    expected_quote_key_id: &Option<String>,
) -> Result<Map<String, Value>, String> {
    if !quote.is_object() {
        return Err("control-plane quote must be an object".to_string());
    }
    if quote.get("provider").and_then(Value::as_str) != Some("dev-signed-quote") {
        return Err(
            "built-in control-plane trust-root verifier only accepts dev-signed-quote; use a production verifier command for Nitro/vendor quotes"
                .to_string(),
        );
    }
    let public_key_pem = quote
        .get("quote_signing_public_key_pem")
        .and_then(Value::as_str)
        .ok_or("control-plane quote missing quote_signing_public_key_pem")?;
    let (verifying_key, quote_key_id) =
        verifying_key_from_spki_pem_text(public_key_pem, "control-plane quote")?;
    let declared_key_id = quote
        .get("quote_signing_key_id")
        .and_then(Value::as_str)
        .ok_or("control-plane quote missing quote_signing_key_id")?;
    if declared_key_id != quote_key_id {
        return Err(format!(
            "control-plane quote key hash mismatch: quote has {declared_key_id}, public key is {quote_key_id}"
        ));
    }
    if let Some(expected) = expected_quote_key_id.as_ref() {
        if expected != &quote_key_id {
            return Err(format!(
                "control-plane quote signing key is not trusted: expected {expected}, quote has {quote_key_id}"
            ));
        }
    }
    let signature_value = quote
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("control-plane quote missing signature")?;
    let signature_b64 = signature_value
        .strip_prefix("ed25519:")
        .ok_or("control-plane quote signature must use ed25519")?;
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|err| format!("decode control-plane quote signature: {err}"))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "control-plane quote Ed25519 signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(
            canonical_json(&unsigned_quote(quote)).as_bytes(),
            &signature,
        )
        .map_err(|err| format!("control-plane quote signature verification failed: {err}"))?;
    quote
        .get("claims")
        .and_then(Value::as_object)
        .cloned()
        .ok_or("control-plane quote missing claims".to_string())
}

fn fetch_attested_policy_trust_root(
    url: &str,
    expected_quote_key_id: &Option<String>,
) -> Result<PolicyTrustRoot, String> {
    let nonce = format!(
        "decision-gate-policy-trust-{}-{}",
        std::process::id(),
        now_epoch_ms()
    );
    let request_url = append_nonce_query(url, &nonce)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| format!("build policy trust root client: {err}"))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let attestation_text = loop {
        let attempt_error = match client.get(&request_url).send() {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.text() {
                    Ok(text) => break text,
                    Err(err) => format!("read control-plane attestation: {err}"),
                },
                Err(err) => format!("control-plane attestation HTTP error: {err}"),
            },
            Err(err) => format!("fetch control-plane attestation: {err}"),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "control-plane policy trust root was not available after retry: {attempt_error}"
            ));
        }
        thread::sleep(Duration::from_millis(250));
    };
    let attestation: Value = serde_json::from_str(&attestation_text)
        .map_err(|err| format!("parse control-plane attestation: {err}"))?;
    if attestation.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
        return Err("control-plane attestation nonce mismatch".to_string());
    }
    let quote = attestation
        .get("quote")
        .ok_or("control-plane attestation missing quote")?;
    let claims = verify_dev_quote_signature(quote, expected_quote_key_id)?;
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
        return Err("control-plane quote nonce mismatch".to_string());
    }
    let policy_public_key_pem = attestation
        .get("policy_signing_public_key_pem")
        .and_then(Value::as_str)
        .ok_or("control-plane attestation missing policy_signing_public_key_pem")?;
    let (verifying_key, key_id) =
        verifying_key_from_spki_pem_text(policy_public_key_pem, "attested policy")?;
    let attested_key_id = claims
        .get("policy_signing_key_id")
        .and_then(Value::as_str)
        .or_else(|| {
            attestation
                .get("policy_signing_key_id")
                .and_then(Value::as_str)
        })
        .ok_or("control-plane attestation missing policy_signing_key_id")?;
    if attested_key_id != key_id {
        return Err(format!(
            "attested policy key hash mismatch: attestation has {attested_key_id}, public key is {key_id}"
        ));
    }
    let attestation_key_id = attestation
        .get("policy_signing_key_id")
        .and_then(Value::as_str)
        .ok_or("control-plane attestation missing policy_signing_key_id")?;
    if attestation_key_id != key_id {
        return Err(format!(
            "control-plane policy key mismatch: attestation has {attestation_key_id}, public key is {key_id}"
        ));
    }
    let attested_policy_hash = claims
        .get("policy_bundle_digest")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:"))
        .map(str::to_string);
    let top_level_policy_hash = attestation
        .get("policy_bundle_digest")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:"));
    if let (Some(claimed), Some(top_level)) =
        (attested_policy_hash.as_deref(), top_level_policy_hash)
    {
        if claimed != top_level {
            return Err(format!(
                "control-plane policy digest mismatch: quote has {claimed}, attestation has {top_level}"
            ));
        }
    }
    Ok(PolicyTrustRoot {
        verifying_key,
        key_id,
        attested_policy_hash,
    })
}

fn load_policy_trust_root(source: &PolicyTrustRootSource) -> Result<PolicyTrustRoot, String> {
    match source {
        PolicyTrustRootSource::File(path) => {
            let (verifying_key, key_id) = public_key_from_spki_pem(path)?;
            Ok(PolicyTrustRoot {
                verifying_key,
                key_id,
                attested_policy_hash: None,
            })
        }
        PolicyTrustRootSource::AttestedControlPlane {
            url,
            expected_quote_key_id,
        } => fetch_attested_policy_trust_root(url, expected_quote_key_id),
    }
}

fn verify_policy_signature(raw: &Value, trust_root: &PolicyTrustRoot) -> Result<(), String> {
    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or("policy metadata missing")?;
    let signing_key_id = metadata
        .get("signingKeyId")
        .and_then(Value::as_str)
        .ok_or("policy metadata.signingKeyId missing")?;
    let signature_value = metadata
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("policy metadata.signature missing")?;
    let signature_b64 = signature_value
        .strip_prefix("ed25519:")
        .ok_or("policy metadata.signature must use ed25519")?;
    if signing_key_id != trust_root.key_id {
        return Err(format!(
            "policy signing key hash mismatch: bundle has {signing_key_id}, trust root is {}",
            trust_root.key_id
        ));
    }
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|err| format!("decode policy signature: {err}"))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "policy Ed25519 signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&signature_array);
    let payload = canonical_json(&signature_payload(raw));
    trust_root
        .verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|err| format!("policy signature verification failed: {err}"))
}

fn validate_policy_capabilities(raw: &Value) -> Result<(), String> {
    const DEFAULTS: [(&str, &str); 5] = [
        ("action", "deny"),
        ("failMode", "closed"),
        ("unknownHosts", "block"),
        ("unknownPaths", "block"),
        ("validationFailure", "block"),
    ];
    const ADAPTER_TYPES: [&str; 4] = ["generic.rest", "gmail.v1", "x.v2", "npm.registry"];
    const JIT_BINDING_FIELDS: [&str; 15] = [
        "principal",
        "routeId",
        "credentialRef",
        "credentialVersion",
        "policyHash",
        "method",
        "authority",
        "path",
        "query",
        "selectedHeaders",
        "bodySha256",
        "packageName",
        "packageVersion",
        "tarballIntegrity",
        "operation",
    ];
    const REQUIRED_JIT_BINDING_FIELDS: [&str; 9] = [
        "principal",
        "routeId",
        "credentialRef",
        "credentialVersion",
        "policyHash",
        "method",
        "authority",
        "path",
        "bodySha256",
    ];

    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or("policy metadata missing")?;
    if metadata.contains_key("validFrom") {
        return Err("policy metadata.validFrom is not supported by the Rust runtime".to_string());
    }

    let defaults = raw
        .get("defaults")
        .and_then(Value::as_object)
        .ok_or("policy defaults missing")?;
    for (key, expected) in DEFAULTS {
        let actual = defaults.get(key).and_then(Value::as_str);
        if actual != Some(expected) {
            return Err(format!(
                "policy defaults.{key} must be {expected}, got {}",
                actual.unwrap_or("missing or non-string")
            ));
        }
    }
    for key in defaults.keys() {
        if !DEFAULTS.iter().any(|(supported, _)| key == supported) {
            return Err(format!(
                "policy defaults.{key} is not supported by the Rust runtime"
            ));
        }
    }

    let principals = raw
        .get("principals")
        .and_then(Value::as_array)
        .ok_or("principals missing")?;
    for (index, item) in principals.iter().enumerate() {
        let principal = item
            .as_object()
            .ok_or_else(|| format!("principal {index} must be an object"))?;
        let principal_id = principal
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("principal {index} id missing"))?;

        if principal.contains_key("spiffeIds") {
            return Err(format!(
                "principal {principal_id} uses spiffeIds, which the Rust runtime does not enforce"
            ));
        }

        let has_source_cidrs = match principal.get("sourceCidrs") {
            Some(Value::Array(cidrs)) => {
                if cidrs.iter().any(|cidr| !cidr.is_string()) {
                    return Err(format!(
                        "principal {principal_id} sourceCidrs must contain only strings"
                    ));
                }
                !cidrs.is_empty()
            }
            None => false,
            Some(_) => {
                return Err(format!(
                    "principal {principal_id} sourceCidrs must be an array"
                ));
            }
        };
        let has_required_headers = match principal.get("requiredHeaders") {
            Some(Value::Object(headers)) => {
                if headers.values().any(|value| !value.is_string()) {
                    return Err(format!(
                        "principal {principal_id} requiredHeaders values must be strings"
                    ));
                }
                !headers.is_empty()
            }
            None => false,
            Some(_) => {
                return Err(format!(
                    "principal {principal_id} requiredHeaders must be an object"
                ));
            }
        };
        let has_proxy_authorization = principal.get("proxyAuthorization").is_some();
        if !has_source_cidrs && !has_required_headers && !has_proxy_authorization {
            return Err(format!(
                "principal {principal_id} has no identity selector enforced by the Rust runtime"
            ));
        }
    }

    let routes = raw
        .get("routes")
        .and_then(Value::as_array)
        .ok_or("routes missing")?;
    for (index, item) in routes.iter().enumerate() {
        let route = item
            .as_object()
            .ok_or_else(|| format!("route {index} must be an object"))?;
        let route_id = route
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("route {index} id missing"))?;
        let adapter_type = route
            .get("adapter")
            .and_then(Value::as_object)
            .and_then(|adapter| adapter.get("type"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("route {route_id} adapter type missing"))?;
        if !ADAPTER_TYPES.contains(&adapter_type) {
            return Err(format!(
                "route {route_id} adapter type {adapter_type} is not supported by the Rust runtime"
            ));
        }

        let constraints: &[Value] = match route.get("constraints") {
            Some(Value::Array(constraints)) => constraints,
            None => &[],
            Some(_) => {
                return Err(format!("route {route_id} constraints must be an array"));
            }
        };
        for (constraint_index, constraint) in constraints.iter().enumerate() {
            let constraint = constraint.as_object().ok_or_else(|| {
                format!("route {route_id} constraint {constraint_index} must be an object")
            })?;
            let constraint_id = constraint
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unnamed");
            let constraint_type =
                constraint
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        format!("route {route_id} constraint {constraint_id} type missing")
                    })?;
            let supported_phase = match constraint_type {
                "rateLimit" | "operationPolicy" | "queryDateWindow" | "queryNumericBounds"
                | "jsonBody" => "request",
                "responseDateWindow" => "response",
                _ => {
                    return Err(format!(
                        "route {route_id} constraint {constraint_id} type {constraint_type} is not supported by the Rust runtime"
                    ));
                }
            };
            let phase = match constraint.get("phase") {
                Some(Value::String(phase)) => phase.as_str(),
                None => "request",
                Some(_) => {
                    return Err(format!(
                        "route {route_id} constraint {constraint_id} phase must be a string"
                    ));
                }
            };
            if phase != supported_phase {
                return Err(format!(
                    "route {route_id} constraint {constraint_id} type {constraint_type} is enforceable only in the {supported_phase} phase, not {phase}"
                ));
            }
        }

        let Some(jit_value) = route.get("jit") else {
            continue;
        };
        let jit = jit_value
            .as_object()
            .ok_or_else(|| format!("route {route_id} JIT policy must be an object"))?;
        jit.get("required")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("route {route_id} JIT required must be a boolean"))?;
        let mode = jit
            .get("mode")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("route {route_id} JIT mode missing"))?;
        if mode != "perOperation" {
            return Err(format!(
                "route {route_id} JIT mode {mode} is not supported by the Rust runtime"
            ));
        }
        let consume_on = jit
            .get("consumeOn")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("route {route_id} JIT consumeOn missing"))?;
        if consume_on != "forwardStart" {
            return Err(format!(
                "route {route_id} JIT consumeOn must be forwardStart, got {consume_on}"
            ));
        }
        let binding = jit
            .get("binding")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("route {route_id} JIT binding missing"))?;
        let binding_type = binding
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("route {route_id} JIT binding type missing"))?;
        if !matches!(binding_type, "requestDigest" | "operationDigest") {
            return Err(format!(
                "route {route_id} JIT binding type {binding_type} is not supported by the Rust runtime"
            ));
        }
        let binding_fields = binding
            .get("fields")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("route {route_id} JIT binding fields missing"))?;
        if binding_fields.is_empty() {
            return Err(format!(
                "route {route_id} JIT binding fields must not be empty"
            ));
        }
        for field in binding_fields {
            let field = field
                .as_str()
                .ok_or_else(|| format!("route {route_id} JIT binding fields must be strings"))?;
            if !JIT_BINDING_FIELDS.contains(&field) {
                return Err(format!(
                    "route {route_id} JIT binding field {field} is not supported by the Rust runtime"
                ));
            }
        }
        for required_field in REQUIRED_JIT_BINDING_FIELDS {
            if !binding_fields
                .iter()
                .any(|field| field.as_str() == Some(required_field))
            {
                return Err(format!(
                    "route {route_id} JIT binding is missing required field {required_field}"
                ));
            }
        }
        let quorum = jit
            .get("approvers")
            .and_then(Value::as_object)
            .and_then(|approvers| approvers.get("quorum"))
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("route {route_id} JIT approver quorum missing"))?;
        if quorum != 1 {
            return Err(format!(
                "route {route_id} JIT approver quorum must be 1, got {quorum}"
            ));
        }
    }

    Ok(())
}

fn parse_cidrs(value: Option<&Value>, context: &str) -> Result<Vec<IpNet>, String> {
    let mut networks = Vec::new();
    for cidr in value.and_then(Value::as_array).into_iter().flatten() {
        if let Some(value) = cidr.as_str() {
            networks.push(
                value
                    .parse::<IpNet>()
                    .map_err(|err| format!("invalid CIDR {value} in {context}: {err}"))?,
            );
        }
    }
    Ok(networks)
}

fn parse_proxy_authorization(
    value: Option<&Value>,
    principal_id: &str,
) -> Result<Option<ProxyAuthorizationPolicy>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(exact) = value.as_str() {
        if exact.is_empty() {
            return Err(format!(
                "principal {principal_id} proxyAuthorization must not be empty"
            ));
        }
        return Ok(Some(ProxyAuthorizationPolicy::LegacyExact(
            exact.to_string(),
        )));
    }
    let Some(config) = value.as_object() else {
        return Err(format!(
            "principal {principal_id} proxyAuthorization must be a string or object"
        ));
    };
    let scheme = config
        .get("scheme")
        .and_then(Value::as_str)
        .unwrap_or("Bearer");
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(format!(
            "principal {principal_id} proxyAuthorization scheme must be Bearer"
        ));
    }
    let token_sha256 = config
        .get("tokenSha256")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:") && value.len() == 71)
        .ok_or_else(|| {
            format!("principal {principal_id} proxyAuthorization.tokenSha256 is required")
        })?
        .to_string();
    let expires_at_ms = config
        .get("expiresAtEpochMs")
        .and_then(Value::as_u64)
        .map(u128::from);
    let source_cidrs = parse_cidrs(
        config.get("sourceCidrs"),
        &format!("principal {principal_id} proxyAuthorization.sourceCidrs"),
    )?;
    Ok(Some(ProxyAuthorizationPolicy::BearerToken {
        token_sha256,
        source_cidrs,
        expires_at_ms,
    }))
}

fn load_snapshot(
    path: &str,
    trust_root_source: &PolicyTrustRootSource,
) -> Result<Snapshot, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read policy bundle: {err}"))?;
    let raw: Value =
        serde_json::from_str(&text).map_err(|err| format!("parse policy bundle: {err}"))?;
    if raw.get("apiVersion").and_then(Value::as_str) != Some("serverware.policy/v1") {
        return Err("apiVersion must be serverware.policy/v1".to_string());
    }
    if raw.get("kind").and_then(Value::as_str) != Some("PolicyBundle") {
        return Err("kind must be PolicyBundle".to_string());
    }
    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or("policy metadata missing")?;
    if !metadata
        .get("signature")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("ed25519:"))
    {
        return Err("policy metadata.signature must be present for data-plane load".to_string());
    }
    let signing_key_id = metadata
        .get("signingKeyId")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:"))
        .ok_or("policy metadata.signingKeyId must be present for data-plane load")?
        .to_string();
    if signing_key_id.is_empty() {
        return Err("policy metadata.signingKeyId must be present for data-plane load".to_string());
    }
    let trust_root = load_policy_trust_root(trust_root_source)?;
    if let Some(expected_key_id) = env::var("SERVERWARE_EXPECTED_POLICY_SIGNING_KEY_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        if signing_key_id != expected_key_id {
            return Err(format!(
                "policy signing key is not trusted: expected {expected_key_id}, bundle has {signing_key_id}"
            ));
        }
    }
    verify_policy_signature(&raw, &trust_root)?;

    let hash = sha256_prefixed(canonical_json(&signature_payload(&raw)).as_bytes());
    if let Some(attested_hash) = trust_root.attested_policy_hash.as_ref() {
        if attested_hash != &hash {
            return Err(format!(
                "policy bundle digest is not the attested control-plane policy: attestation has {attested_hash}, bundle has {hash}"
            ));
        }
    }
    validate_policy_capabilities(&raw)?;

    let mut principals = Vec::new();
    for item in raw
        .get("principals")
        .and_then(Value::as_array)
        .ok_or("principals missing")?
    {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or("principal id missing")?
            .to_string();
        let source_cidrs = parse_cidrs(
            item.get("sourceCidrs"),
            &format!("principal {id} sourceCidrs"),
        )?;
        let mut required_headers = BTreeMap::new();
        if let Some(headers) = item.get("requiredHeaders").and_then(Value::as_object) {
            for (name, value) in headers {
                required_headers.insert(
                    name.to_ascii_lowercase(),
                    value.as_str().unwrap_or_default().to_string(),
                );
            }
        }
        principals.push(Principal {
            proxy_authorization: parse_proxy_authorization(item.get("proxyAuthorization"), &id)?,
            id,
            source_cidrs,
            required_headers,
        });
    }

    let mut credentials = HashMap::new();
    for item in raw
        .get("credentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or("credential id missing")?
            .to_string();
        credentials.insert(
            id,
            Credential {
                injection: item
                    .get("injection")
                    .cloned()
                    .unwrap_or_else(|| json!({"type":"bearer"})),
            },
        );
    }

    let mut routes = Vec::new();
    for item in raw
        .get("routes")
        .and_then(Value::as_array)
        .ok_or("routes missing")?
    {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or("route id missing")?
            .to_string();
        let route_match = item
            .get("match")
            .and_then(Value::as_object)
            .ok_or("route match missing")?;
        let methods = route_match
            .get("methods")
            .and_then(Value::as_array)
            .ok_or("route methods missing")?
            .iter()
            .filter_map(Value::as_str)
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();
        let mut paths = Vec::new();
        for path in route_match
            .get("paths")
            .and_then(Value::as_array)
            .ok_or("route paths missing")?
            .iter()
            .filter_map(Value::as_str)
        {
            paths.push(compile_template(path)?);
        }
        let adapter = item
            .get("adapter")
            .and_then(Value::as_object)
            .ok_or("route adapter missing")?;
        routes.push(Route {
            id,
            principals: item
                .get("principals")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect(),
            scheme: route_match
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("https")
                .to_ascii_lowercase(),
            host: route_match
                .get("host")
                .and_then(Value::as_str)
                .ok_or("route host missing")?
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            port: route_match
                .get("port")
                .and_then(Value::as_u64)
                .unwrap_or(443) as u16,
            methods,
            paths,
            credential_ref: item
                .get("credentialRef")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            adapter_type: adapter
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("generic.rest")
                .to_string(),
            adapter_config: adapter.get("config").cloned().unwrap_or_else(|| json!({})),
            constraints: item
                .get("constraints")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            jit: item.get("jit").cloned().unwrap_or_else(|| json!({})),
        });
    }
    routes.sort_by_key(|route| {
        std::cmp::Reverse(
            route
                .paths
                .iter()
                .map(|path| path.segments.len())
                .max()
                .unwrap_or(0),
        )
    });

    Ok(Snapshot {
        hash,
        policy_signing_key_id: signing_key_id,
        principals,
        credentials,
        routes,
    })
}

fn current_snapshot(state: &GateState) -> Arc<Snapshot> {
    state
        .snapshot
        .read()
        .expect("policy snapshot lock poisoned")
        .clone()
}

fn file_mtime(path: &str) -> Option<SystemTime> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn refresh_policy_snapshot(state: &GateState, force: bool) -> Result<bool, String> {
    let mtime = file_mtime(&state.policy_path);
    {
        let mut seen = state
            .policy_mtime
            .lock()
            .expect("policy mtime mutex poisoned");
        if !force && *seen == mtime {
            return Ok(false);
        }
        *seen = mtime;
    }
    match load_snapshot(&state.policy_path, &state.policy_trust_root_source) {
        Ok(snapshot) => {
            let next = Arc::new(snapshot);
            let previous = current_snapshot(state);
            if previous.hash == next.hash {
                return Ok(false);
            }
            {
                let mut current = state
                    .snapshot
                    .write()
                    .expect("policy snapshot lock poisoned");
                *current = Arc::clone(&next);
            }
            state
                .grants
                .lock()
                .expect("grant cache mutex poisoned")
                .clear();
            state
                .gmail_proofs
                .lock()
                .expect("gmail proof cache mutex poisoned")
                .clear();
            state.policy_reload_success.fetch_add(1, Ordering::Relaxed);
            enqueue_audit(
                state,
                "data_plane.policy.reloaded",
                json!({
                    "component":"serverware-decision-gate-rs",
                    "previous_policy_hash":previous.hash.clone(),
                    "policy_hash":next.hash.clone(),
                    "policy_signing_key_id":next.policy_signing_key_id.clone(),
                    "routes":next.routes.len(),
                    "grants_cleared":true,
                    "gmail_proofs_cleared":true,
                }),
            );
            Ok(true)
        }
        Err(err) => {
            state.policy_reload_failed.fetch_add(1, Ordering::Relaxed);
            enqueue_audit(
                state,
                "data_plane.policy.reload_failed",
                json!({
                    "component":"serverware-decision-gate-rs",
                    "active_policy_hash":current_snapshot(state).hash.clone(),
                    "error":err.clone(),
                }),
            );
            Err(err)
        }
    }
}

fn policy_worker(state: Arc<GateState>, interval: Duration) {
    loop {
        if let Err(err) = refresh_policy_snapshot(&state, false) {
            eprintln!("policy reload failed; retaining last good snapshot: {err}");
        }
        thread::sleep(interval);
    }
}

fn lower_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}

fn query_pairs(url: &Url) -> Vec<(String, String)> {
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
}

fn selected_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let volatile = [
        "date",
        "user-agent",
        "content-length",
        "connection",
        "authorization",
        "proxy-authorization",
    ];
    let selected = ["content-type", "npm-command", "x-serverware-agent"];
    headers
        .iter()
        .filter(|(name, _)| {
            !volatile.contains(&name.as_str())
                && !name.starts_with("proxy-")
                && selected.contains(&name.as_str())
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn body_sha(req: &DecisionRequest) -> String {
    req.body_sha256
        .clone()
        .unwrap_or_else(|| sha256_prefixed(req.body.as_bytes()))
}

fn digest_json(value: &Value) -> String {
    sha256_prefixed(canonical_json(value).as_bytes())
}

fn load_generation_map(path: &str) -> Result<HashMap<String, Option<u64>>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => return Err(format!("read credential generations: {err}")),
    };
    let payload: Value = serde_json::from_str(&text)
        .map_err(|err| format!("parse credential generations: {err}"))?;
    let mut generations = HashMap::new();
    for (credential_id, entry) in payload
        .get("credentials")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if entry
            .get("deleted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            generations.insert(credential_id.clone(), None);
            continue;
        }
        if let Some(version) = entry.get("credential_version").and_then(Value::as_u64) {
            generations.insert(credential_id.clone(), Some(version));
        }
    }
    Ok(generations)
}

fn refresh_generation_cache(state: &GateState, force: bool) -> Result<(), String> {
    let mtime = match fs::metadata(&state.generation_path).and_then(|metadata| metadata.modified())
    {
        Ok(mtime) => Some(mtime),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("stat credential generations: {err}")),
    };
    {
        let mut cached = state
            .generation_mtime
            .lock()
            .expect("generation mtime mutex poisoned");
        if !force && *cached == mtime {
            return Ok(());
        }
        *cached = mtime;
    }
    let generations = load_generation_map(&state.generation_path)?;
    {
        let mut cached = state
            .credential_generations
            .lock()
            .expect("credential generation mutex poisoned");
        *cached = generations.clone();
    }
    let mut grants = state.grants.lock().expect("grant cache mutex poisoned");
    grants.retain(|_, grant| {
        matches!(
            generations.get(&grant.credential_ref),
            Some(Some(active_version)) if *active_version == grant.credential_version
        )
    });
    Ok(())
}

fn generation_worker(state: Arc<GateState>, poll_interval: Duration) {
    loop {
        if let Err(err) = refresh_generation_cache(&state, false) {
            eprintln!("credential generation refresh failed: {err}");
        }
        thread::sleep(poll_interval);
    }
}

fn credential_generation(state: &GateState, credential_ref: &str) -> Option<Option<u64>> {
    state
        .credential_generations
        .lock()
        .expect("credential generation mutex poisoned")
        .get(credential_ref)
        .copied()
}

fn load_lease_map(path: &str) -> Result<HashMap<String, Option<SecretLease>>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => return Err(format!("read credential leases: {err}")),
    };
    let payload: Value =
        serde_json::from_str(&text).map_err(|err| format!("parse credential leases: {err}"))?;
    let mut leases = HashMap::new();
    for (credential_id, entry) in payload
        .get("credentials")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if entry
            .get("deleted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            leases.insert(credential_id.clone(), None);
            continue;
        }
        let Some(version) = entry.get("credential_version").and_then(Value::as_u64) else {
            continue;
        };
        let Some(secret) = entry.get("secret").and_then(Value::as_str) else {
            continue;
        };
        let metadata = entry
            .get("metadata")
            .and_then(Value::as_object)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        leases.insert(
            credential_id.clone(),
            Some(SecretLease {
                version,
                secret: secret.to_string(),
                metadata,
            }),
        );
    }
    Ok(leases)
}

fn refresh_lease_cache(state: &GateState, force: bool) -> Result<(), String> {
    let mtime = match fs::metadata(&state.lease_path).and_then(|metadata| metadata.modified()) {
        Ok(mtime) => Some(mtime),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("stat credential leases: {err}")),
    };
    {
        let mut cached = state
            .lease_mtime
            .lock()
            .expect("lease mtime mutex poisoned");
        if !force && *cached == mtime {
            return Ok(());
        }
        *cached = mtime;
    }
    let leases = load_lease_map(&state.lease_path)?;
    let mut cached = state
        .credential_leases
        .lock()
        .expect("credential lease mutex poisoned");
    *cached = leases;
    Ok(())
}

fn lease_worker(state: Arc<GateState>, poll_interval: Duration) {
    loop {
        if let Err(err) = refresh_lease_cache(&state, false) {
            eprintln!("credential lease refresh failed: {err}");
        }
        thread::sleep(poll_interval);
    }
}

fn credential_lease(
    state: &GateState,
    credential_ref: &str,
    credential_version: u64,
) -> Option<SecretLease> {
    match state
        .credential_leases
        .lock()
        .expect("credential lease mutex poisoned")
        .get(credential_ref)
        .cloned()
    {
        Some(Some(lease)) if lease.version == credential_version => Some(lease),
        _ => None,
    }
}

fn current_binary_digest() -> Result<String, String> {
    let exe = env::current_exe().map_err(|err| format!("resolve current executable: {err}"))?;
    let bytes = fs::read(&exe).map_err(|err| format!("read current executable {exe:?}: {err}"))?;
    Ok(sha256_prefixed(&bytes))
}

fn pem_certificates(bundle: &str) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut current = Vec::new();
    let mut in_cert = false;
    for line in bundle.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
        }
        if in_cert {
            current.extend_from_slice(line.as_bytes());
            current.push(b'\n');
        }
        if line.contains("-----END CERTIFICATE-----") && in_cert {
            certs.push(current.clone());
            current.clear();
            in_cert = false;
        }
    }
    certs
}

fn build_upstream_client() -> Result<Client, String> {
    let mut builder = Client::builder().timeout(Duration::from_secs(10));
    if let Ok(path) = env::var("SERVERWARE_UPSTREAM_CA_BUNDLE") {
        if !path.trim().is_empty() {
            let text = fs::read_to_string(&path)
                .map_err(|err| format!("read upstream CA bundle {path}: {err}"))?;
            let certs = pem_certificates(&text);
            if certs.is_empty() {
                return Err(format!("upstream CA bundle {path} has no PEM certificates"));
            }
            for cert in certs {
                let cert = reqwest::Certificate::from_pem(&cert)
                    .map_err(|err| format!("parse upstream CA certificate {path}: {err}"))?;
                builder = builder.add_root_certificate(cert);
            }
        }
    }
    builder
        .build()
        .map_err(|err| format!("build upstream HTTP client: {err}"))
}

fn build_audit_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| format!("build audit HTTP client: {err}"))
}

fn audit_enabled(state: &GateState) -> bool {
    state.audit_url.is_some() && state.audit_token.is_some() && state.audit_queue_max > 0
}

fn enqueue_audit(state: &GateState, event_type: &str, event: Value) {
    let _ = enqueue_audit_event(state, event_type, event, false);
}

fn enqueue_required_audit(state: &GateState, event_type: &str, event: Value) -> bool {
    enqueue_audit_event(state, event_type, event, true)
}

fn audit_queue_full(state: &GateState) -> bool {
    audit_enabled(state)
        && state
            .audit_queue
            .lock()
            .expect("audit queue mutex poisoned")
            .len()
            >= state.audit_queue_max
}

fn enqueue_audit_event(state: &GateState, event_type: &str, event: Value, required: bool) -> bool {
    if !audit_enabled(state) {
        if required {
            state.audit_required_failed.fetch_add(1, Ordering::Relaxed);
        }
        return !required;
    }
    let mut queue = state
        .audit_queue
        .lock()
        .expect("audit queue mutex poisoned");
    if queue.len() >= state.audit_queue_max {
        if required {
            state.audit_required_failed.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        queue.pop_front();
        state.audit_dropped.fetch_add(1, Ordering::Relaxed);
    }
    queue.push_back(AuditEvent {
        event_type: event_type.to_string(),
        actor_id: "decision-gate-rs".to_string(),
        event,
    });
    state.audit_enqueued.fetch_add(1, Ordering::Relaxed);
    true
}

fn pop_audit_batch(state: &GateState) -> Vec<AuditEvent> {
    let mut queue = state
        .audit_queue
        .lock()
        .expect("audit queue mutex poisoned");
    let count = state.audit_batch_max.max(1).min(queue.len());
    let mut batch = Vec::with_capacity(count);
    for _ in 0..count {
        if let Some(event) = queue.pop_front() {
            batch.push(event);
        }
    }
    batch
}

fn requeue_audit_batch(state: &GateState, batch: Vec<AuditEvent>) {
    let mut queue = state
        .audit_queue
        .lock()
        .expect("audit queue mutex poisoned");
    for event in batch.into_iter().rev() {
        if queue.len() >= state.audit_queue_max {
            queue.pop_back();
            state.audit_dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_front(event);
    }
}

fn post_audit_batch(state: &GateState, batch: &[AuditEvent]) -> Result<(), String> {
    let url = state
        .audit_url
        .as_ref()
        .ok_or("audit URL is not configured")?;
    let token = state
        .audit_token
        .as_ref()
        .ok_or("audit token is not configured")?;
    let body = serde_json::to_vec(&json!({"events": batch}))
        .map_err(|err| format!("serialize audit batch: {err}"))?;
    let response = state
        .audit_client
        .post(url)
        .header("X-Serverware-Data-Plane-Token", token.as_str())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|err| format!("send audit batch: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("audit ingest returned {}", response.status()));
    }
    Ok(())
}

fn audit_worker(state: Arc<GateState>, interval: Duration) {
    loop {
        let batch = pop_audit_batch(&state);
        if batch.is_empty() {
            thread::sleep(interval);
            continue;
        }
        let count = batch.len() as u64;
        match post_audit_batch(&state, &batch) {
            Ok(()) => {
                state.audit_sent.fetch_add(count, Ordering::Relaxed);
            }
            Err(err) => {
                state.audit_send_failed.fetch_add(count, Ordering::Relaxed);
                requeue_audit_batch(&state, batch);
                eprintln!("audit batch send failed: {err}");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn audit_url_parts(url: &Url) -> Value {
    let mut query_keys = url
        .query_pairs()
        .map(|(key, _)| key.to_string())
        .collect::<Vec<_>>();
    query_keys.sort();
    query_keys.dedup();
    json!({
        "scheme": url.scheme(),
        "authority": url.host_str().map(|host| match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        }),
        "path": url.path(),
        "query_keys": query_keys,
    })
}

fn decision_audit_event(
    decision: &Value,
    method: &str,
    url: &Url,
    outcome: &str,
    extra: Value,
) -> Value {
    let mut event = Map::new();
    event.insert(
        "component".to_string(),
        Value::String("serverware-decision-gate-rs".to_string()),
    );
    event.insert(
        "method".to_string(),
        Value::String(method.to_ascii_uppercase()),
    );
    event.insert("url".to_string(), audit_url_parts(url));
    event.insert("outcome".to_string(), Value::String(outcome.to_string()));
    for key in [
        "action",
        "status_code",
        "reason",
        "principal_id",
        "route_id",
        "adapter",
        "policy_hash",
        "credential_ref",
        "credential_version",
        "request_digest",
        "operation_digest",
        "operation",
    ] {
        if let Some(value) = decision.get(key) {
            event.insert(key.to_string(), value.clone());
        }
    }
    if let Some(value) = decision.pointer("/canonical_request/client_ip") {
        event.insert("client_ip".to_string(), value.clone());
    }
    if let Some(value) = decision.pointer("/canonical_request/request/body_sha256") {
        event.insert("body_sha256".to_string(), value.clone());
    }
    if let Some(object) = extra.as_object() {
        for (key, value) in object {
            event.insert(key.clone(), value.clone());
        }
    }
    Value::Object(event)
}

fn connect_audit_event(
    decision: &Value,
    target: &str,
    client_ip: Option<&str>,
    outcome: &str,
) -> Value {
    json!({
        "component":"serverware-decision-gate-rs",
        "method":"CONNECT",
        "target":target,
        "authority":decision.get("authority").cloned().unwrap_or(Value::Null),
        "outcome":outcome,
        "action":decision.get("action").cloned().unwrap_or(Value::Null),
        "status_code":decision.get("status_code").cloned().unwrap_or(Value::Null),
        "reason":decision.get("reason").cloned().unwrap_or(Value::Null),
        "payload":decision.get("payload").cloned().unwrap_or(Value::Null),
        "principal_id":decision.get("principal_id").cloned().unwrap_or(Value::Null),
        "policy_hash":decision.get("policy_hash").cloned().unwrap_or(Value::Null),
        "route_ids":decision.get("route_ids").cloned().unwrap_or(Value::Null),
        "client_ip":client_ip,
    })
}

fn audit_status(state: &GateState) -> Value {
    json!({
        "enabled": audit_enabled(state),
        "queue_depth": state.audit_queue.lock().expect("audit queue mutex poisoned").len(),
        "queue_max": state.audit_queue_max,
        "batch_max": state.audit_batch_max,
        "enqueued": state.audit_enqueued.load(Ordering::Relaxed),
        "dropped": state.audit_dropped.load(Ordering::Relaxed),
        "required_failed": state.audit_required_failed.load(Ordering::Relaxed),
        "sent": state.audit_sent.load(Ordering::Relaxed),
        "send_failed": state.audit_send_failed.load(Ordering::Relaxed),
    })
}

fn first_certificate_der(pem_text: &str, path: &str) -> Result<Vec<u8>, String> {
    let mut reader = Cursor::new(pem_text.as_bytes());
    let mut certs = rustls_pemfile::certs(&mut reader);
    let Some(cert) = certs.next() else {
        return Err(format!(
            "CA certificate file {path} has no PEM certificates"
        ));
    };
    cert.map(|der| der.to_vec())
        .map_err(|err| format!("parse CA certificate {path}: {err}"))
}

fn build_mitm_authority() -> Result<Option<MitmAuthority>, String> {
    let cert_path = env::var("SERVERWARE_MITM_CA_CERT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let key_path = env::var("SERVERWARE_MITM_CA_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
        if env::var("SERVERWARE_MITM_CA_CERT").is_ok() || env::var("SERVERWARE_MITM_CA_KEY").is_ok()
        {
            return Err(
                "SERVERWARE_MITM_CA_CERT and SERVERWARE_MITM_CA_KEY must be set together"
                    .to_string(),
            );
        }
        return Ok(None);
    };
    let cert_pem = fs::read_to_string(&cert_path)
        .map_err(|err| format!("read MITM CA certificate {cert_path}: {err}"))?;
    let key_pem = fs::read_to_string(&key_path)
        .map_err(|err| format!("read MITM CA private key {key_path}: {err}"))?;
    let ca_cert_der = first_certificate_der(&cert_pem, &cert_path)?;
    let ca_key =
        KeyPair::from_pem(&key_pem).map_err(|err| format!("parse MITM CA private key: {err}"))?;
    let ca_params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .map_err(|err| format!("parse MITM CA certificate params: {err}"))?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|err| format!("materialize MITM CA issuer: {err}"))?;
    Ok(Some(MitmAuthority {
        ca_cert,
        ca_key,
        ca_cert_der,
    }))
}

fn authority_string(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn mitm_server_config(state: &GateState, host: &str) -> Result<Arc<ServerConfig>, String> {
    let cache_key = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(config) = state
        .leaf_configs
        .lock()
        .expect("leaf config cache mutex poisoned")
        .get(&cache_key)
        .cloned()
    {
        return Ok(config);
    }
    let authority = state
        .mitm_authority
        .as_ref()
        .ok_or("MITM CA authority is not loaded")?
        .lock()
        .expect("MITM authority mutex poisoned");
    let leaf_key = KeyPair::generate().map_err(|err| format!("generate leaf key: {err}"))?;
    let mut params =
        CertificateParams::new(vec![cache_key.clone()]).map_err(|err| err.to_string())?;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TimeDuration::minutes(5);
    params.not_after = now + TimeDuration::hours(24);
    params
        .distinguished_name
        .push(DnType::CommonName, cache_key.clone());
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf = params
        .signed_by(&leaf_key, &authority.ca_cert, &authority.ca_key)
        .map_err(|err| format!("sign intercepted leaf certificate: {err}"))?;
    let chain = vec![
        CertificateDer::from(leaf.der().to_vec()),
        CertificateDer::from(authority.ca_cert_der.clone()),
    ];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|err| format!("build intercepted TLS server config: {err}"))?;
    let config = Arc::new(config);
    state
        .leaf_configs
        .lock()
        .expect("leaf config cache mutex poisoned")
        .insert(cache_key, Arc::clone(&config));
    Ok(config)
}

fn grant_key(
    principal_id: &str,
    route_id: &str,
    credential_ref: &str,
    credential_version: u64,
    policy_hash: &str,
    request_digest: &str,
    operation_digest: &str,
) -> String {
    digest_json(&json!({
        "principal_id": principal_id,
        "route_id": route_id,
        "credential_ref": credential_ref,
        "credential_version": credential_version,
        "policy_hash": policy_hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
    }))
}

fn create_grant(state: &GateState, payload: GrantCreate) -> Value {
    let started = Instant::now();
    let snapshot = current_snapshot(state);
    if payload.max_uses == 0 {
        return deny(
            400,
            "grant maxUses must be positive",
            json!({"error":"invalid_grant_max_uses"}),
            started,
        );
    }
    if payload.ttl_seconds == 0 || payload.ttl_seconds > 300 {
        return deny(
            400,
            "grant ttlSeconds is outside allowed bounds",
            json!({"error":"invalid_grant_ttl_seconds","max":300}),
            started,
        );
    }
    if payload.policy_hash != snapshot.hash {
        return deny(
            409,
            "grant policy hash is not active",
            json!({"error":"grant_policy_hash_inactive","active_policy_hash":snapshot.hash}),
            started,
        );
    }
    match credential_generation(state, &payload.credential_ref) {
        Some(Some(active_version)) if active_version == payload.credential_version => {}
        Some(Some(active_version)) => {
            return deny(
                409,
                "grant credential version is stale",
                json!({
                    "error":"grant_credential_version_stale",
                    "active_credential_version":active_version,
                    "grant_credential_version":payload.credential_version,
                }),
                started,
            )
        }
        Some(None) => {
            return deny(
                410,
                "grant credential has been deleted",
                json!({"error":"grant_credential_deleted"}),
                started,
            )
        }
        None => {
            return deny(
                503,
                "credential generation is unavailable",
                json!({"error":"credential_generation_missing","credential_ref":payload.credential_ref}),
                started,
            )
        }
    }
    if !snapshot.routes.iter().any(|route| {
        route.id == payload.route_id
            && route.credential_ref.as_deref() == Some(payload.credential_ref.as_str())
    }) {
        return deny(
            404,
            "grant route or credential is not in active policy",
            json!({"error":"grant_route_or_credential_unknown"}),
            started,
        );
    }
    let key = grant_key(
        &payload.principal_id,
        &payload.route_id,
        &payload.credential_ref,
        payload.credential_version,
        &payload.policy_hash,
        &payload.request_digest,
        &payload.operation_digest,
    );
    let grant_id = payload
        .grant_id
        .clone()
        .unwrap_or_else(|| format!("grant:{}", key.trim_start_matches("sha256:")));
    let expires_at_ms = now_epoch_ms() + u128::from(payload.ttl_seconds) * 1000;
    let grant = Grant {
        id: grant_id.clone(),
        approval_id: payload.approval_id.clone(),
        credential_ref: payload.credential_ref.clone(),
        credential_version: payload.credential_version,
        uses_remaining: payload.max_uses,
        expires_at_ms,
    };
    let mut grants = state.grants.lock().expect("grant cache mutex poisoned");
    grants.insert(key.clone(), grant);
    enqueue_audit(
        state,
        "data_plane.grant.received",
        json!({
            "component":"serverware-decision-gate-rs",
            "grant_id":grant_id.clone(),
            "approval_id":payload.approval_id.clone(),
            "principal_id":payload.principal_id.clone(),
            "route_id":payload.route_id.clone(),
            "credential_ref":payload.credential_ref.clone(),
            "credential_version":payload.credential_version,
            "policy_hash":snapshot.hash.clone(),
            "request_digest":payload.request_digest.clone(),
            "operation_digest":payload.operation_digest.clone(),
            "max_uses":payload.max_uses,
            "ttl_seconds":payload.ttl_seconds,
            "expires_at_ms":expires_at_ms,
        }),
    );
    json!({
        "ok": true,
        "grant_id": grant_id,
        "approval_id": payload.approval_id,
        "key": key,
        "uses_remaining": payload.max_uses,
        "expires_at_ms": expires_at_ms,
        "policy_hash": snapshot.hash,
        "decision_us": started.elapsed().as_micros() as u64,
    })
}

fn consume_local_grant(
    state: &GateState,
    principal_id: &str,
    route_id: &str,
    credential_ref: &str,
    credential_version: u64,
    policy_hash: &str,
    request_digest: &str,
    operation_digest: &str,
) -> Option<ConsumedGrant> {
    let key = grant_key(
        principal_id,
        route_id,
        credential_ref,
        credential_version,
        policy_hash,
        request_digest,
        operation_digest,
    );
    let now = now_epoch_ms();
    let mut grants = state.grants.lock().expect("grant cache mutex poisoned");
    let grant = grants.get_mut(&key)?;
    if grant.expires_at_ms <= now || grant.uses_remaining == 0 {
        grants.remove(&key);
        return None;
    }
    grant.uses_remaining -= 1;
    let consumed = ConsumedGrant {
        id: grant.id.clone(),
        approval_id: grant.approval_id.clone(),
    };
    if grant.uses_remaining == 0 {
        grants.remove(&key);
    }
    Some(consumed)
}

fn consume_shared_grant(
    state: &GateState,
    principal_id: &str,
    route_id: &str,
    credential_ref: &str,
    credential_version: u64,
    policy_hash: &str,
    request_digest: &str,
    operation_digest: &str,
    flow_id: &str,
    method: &str,
    request_url: &str,
    canonical_request: &Value,
    redacted_display: &Value,
) -> Result<(Option<ConsumedGrant>, Option<PendingApproval>), String> {
    let grant_consume_url = state
        .grant_consume_url
        .as_ref()
        .ok_or("shared grant consume URL is not configured")?;
    let token = state
        .audit_token
        .as_ref()
        .ok_or("data-plane token is not configured")?;
    let body = serde_json::to_vec(&json!({
        "principalId":principal_id,
        "routeId":route_id,
        "credentialRef":credential_ref,
        "credentialVersion":credential_version,
        "policyHash":policy_hash,
        "requestDigest":request_digest,
        "operationDigest":operation_digest,
        "flowId":flow_id,
        "method":method,
        "url":request_url,
        "canonicalRequest":canonical_request,
        "redactedDisplay":redacted_display,
    }))
    .map_err(|err| format!("serialize shared grant consume request: {err}"))?;
    let response = state
        .audit_client
        .post(grant_consume_url)
        .header("X-Serverware-Data-Plane-Token", token.as_str())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|err| format!("send shared grant consume request: {err}"))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|err| format!("read shared grant consume response: {err}"))?;
    if !status.is_success() {
        return Err(format!("shared grant consume returned {status}: {text}"));
    }
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| format!("parse shared grant consume response: {err}: {text}"))?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("shared grant consume response was not ok: {value}"));
    }
    if value.get("consumed").and_then(Value::as_bool) != Some(true) {
        let pending = value
            .get("approval_id")
            .or_else(|| value.get("approval_request_id"))
            .and_then(Value::as_str)
            .map(|id| PendingApproval {
                id: id.to_string(),
                expires_at: value
                    .get("expires_at")
                    .or_else(|| value.get("expiresAt"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        return Ok((None, pending));
    }
    let id = value
        .get("grant_id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("shared grant consume response missing grant_id: {value}"))?
        .to_string();
    let approval_id = value
        .get("approval_id")
        .or_else(|| value.get("approval_request_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok((Some(ConsumedGrant { id, approval_id }), None))
}

fn consume_grant(
    state: &GateState,
    principal_id: &str,
    route_id: &str,
    credential_ref: &str,
    credential_version: u64,
    policy_hash: &str,
    request_digest: &str,
    operation_digest: &str,
    flow_id: &str,
    method: &str,
    url: &str,
    canonical_request: &Value,
    redacted_display: &Value,
) -> Result<(Option<ConsumedGrant>, &'static str, Option<PendingApproval>), String> {
    if state.grant_consume_url.is_some() {
        let (consumed, pending) = consume_shared_grant(
            state,
            principal_id,
            route_id,
            credential_ref,
            credential_version,
            policy_hash,
            request_digest,
            operation_digest,
            flow_id,
            method,
            url,
            canonical_request,
            redacted_display,
        )?;
        return Ok((consumed, "shared", pending));
    }
    Ok((
        consume_local_grant(
            state,
            principal_id,
            route_id,
            credential_ref,
            credential_version,
            policy_hash,
            request_digest,
            operation_digest,
        ),
        "local",
        None,
    ))
}

fn canonical_request(
    req: &DecisionRequest,
    headers: &BTreeMap<String, String>,
    url: &Url,
    principal: &Principal,
    route: &Route,
    credential_version: u64,
    policy_hash: &str,
    operation: &Value,
) -> Value {
    json!({
        "v": 1,
        "principal": principal.id,
        "client_ip": req.client_ip,
        "route_id": route.id,
        "credential_ref": route.credential_ref,
        "credential_version": credential_version.to_string(),
        "policy_hash": policy_hash,
        "request": {
            "method": req.method.to_ascii_uppercase(),
            "scheme": url.scheme(),
            "authority": url.host_str().map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            }).unwrap_or_default().to_ascii_lowercase(),
            "path": url.path(),
            "query": query_pairs(url),
            "headers": selected_headers(headers),
            "body_sha256": body_sha(req),
        },
        "operation": operation,
    })
}

fn operation_digest(canonical: &Value) -> String {
    digest_json(&json!({
        "principal": canonical["principal"],
        "route_id": canonical["route_id"],
        "credential_ref": canonical["credential_ref"],
        "credential_version": canonical["credential_version"],
        "policy_hash": canonical["policy_hash"],
        "request": canonical["request"],
        "operation": canonical["operation"],
    }))
}

fn deny(status: u16, reason: &str, payload: Value, started: Instant) -> Value {
    json!({
        "action": "deny",
        "allowed": false,
        "status_code": status,
        "reason": reason,
        "payload": payload,
        "decision_us": started.elapsed().as_micros() as u64,
        "hot_path": {"sqlite_calls": 0, "filesystem_calls": 0},
    })
}

fn connect_authority(target: &str) -> Result<(String, u16), String> {
    let authority = target.trim();
    if authority.is_empty() || authority.contains('/') {
        return Err("CONNECT target must be host:port authority".to_string());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, port_text)) = rest.split_once("]:") else {
            return Err("CONNECT IPv6 target must be [host]:port".to_string());
        };
        let port = port_text
            .parse::<u16>()
            .map_err(|err| format!("invalid CONNECT port: {err}"))?;
        return Ok((host.trim_end_matches('.').to_ascii_lowercase(), port));
    }
    let Some((host, port_text)) = authority.rsplit_once(':') else {
        return Err("CONNECT target must include an explicit port".to_string());
    };
    if host.is_empty() {
        return Err("CONNECT target host is empty".to_string());
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|err| format!("invalid CONNECT port: {err}"))?;
    Ok((host.trim_end_matches('.').to_ascii_lowercase(), port))
}

fn connect_preflight(
    state: &GateState,
    client_ip: Option<&str>,
    target: &str,
    headers: &BTreeMap<String, String>,
) -> Value {
    let started = Instant::now();
    let headers = lower_headers(headers);
    let snapshot = current_snapshot(state);
    let (host, port) = match connect_authority(target) {
        Ok(parsed) => parsed,
        Err(err) => {
            return deny(
                400,
                "invalid CONNECT target",
                json!({"error":"invalid_connect_target","detail":err}),
                started,
            )
        }
    };
    let authority = format!("{host}:{port}");
    let Some(principal) = snapshot.identify_principal(client_ip, &headers) else {
        return deny(
            403,
            "client principal denied",
            json!({"error":"client_principal_denied","authority":authority,"client_ip":client_ip}),
            started,
        );
    };
    let route_ids = snapshot.match_connect_routes(&principal.id, &host, port);
    if route_ids.is_empty() {
        return deny(
            403,
            "unknown CONNECT authority denied",
            json!({"error":"unknown_connect_denied","authority":authority}),
            started,
        );
    }
    json!({
        "action":"allow",
        "allowed":true,
        "status_code":200,
        "principal_id":principal.id,
        "policy_hash":snapshot.hash,
        "authority":authority,
        "route_ids":route_ids,
        "decision_us":started.elapsed().as_micros() as u64,
        "hot_path":{"sqlite_calls":0,"filesystem_calls":0},
    })
}

fn get_object<'a>(value: &'a Value, key: &str) -> Option<&'a Map<String, Value>> {
    value.get(key).and_then(Value::as_object)
}

fn config_u64(config: &Value, key: &str, default: u64) -> u64 {
    config.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn path_segments(url: &Url) -> HashSet<String> {
    url.path()
        .split('/')
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect()
}

fn newer_than_days(value: &str) -> Option<u64> {
    let marker = "newer_than:";
    let start = value.to_ascii_lowercase().find(marker)? + marker.len();
    let suffix = &value[start..];
    let digits = suffix
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    let unit = suffix.chars().nth(digits.len())?;
    let count = digits.parse::<u64>().ok()?;
    Some(match unit {
        'd' => count,
        'm' => count * 30,
        'y' => count * 365,
        _ => return None,
    })
}

fn older_than_days(value: &str) -> Option<u64> {
    let marker = "older_than:";
    let start = value.to_ascii_lowercase().find(marker)? + marker.len();
    let suffix = &value[start..];
    let digits = suffix
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    let unit = suffix.chars().nth(digits.len())?;
    let count = digits.parse::<u64>().ok()?;
    Some(match unit {
        'd' => count,
        'm' => count * 30,
        'y' => count * 365,
        _ => return None,
    })
}

fn tighten_gmail_query(query: &str, days: u64) -> String {
    if query.trim().is_empty() {
        return format!("newer_than:{days}d");
    }
    if let Some(existing_days) = newer_than_days(query) {
        if existing_days <= days {
            return query.to_string();
        }
        return "newer_than:30d".to_string();
    }
    format!("({query}) newer_than:{days}d")
}

fn x_operation(url: &Url, method: &str) -> Option<String> {
    let path = url.path().trim_end_matches('/');
    let read = method.eq_ignore_ascii_case("GET");
    if path.starts_with("/2/tweets/search") {
        return Some(if read { "search.read" } else { "search.write" }.to_string());
    }
    if path == "/2/tweets" || path.starts_with("/2/tweets/") {
        return Some(if read { "tweets.read" } else { "tweets.write" }.to_string());
    }
    if path == "/2/users" || path.starts_with("/2/users/") {
        return Some(if read { "users.read" } else { "users.write" }.to_string());
    }
    None
}

fn npm_registry_path(url: &Url) -> String {
    let path = url.path().trim_end_matches('/');
    if let Some(rest) = path.strip_prefix("/npm/") {
        return format!("/{rest}");
    }
    if path == "/npm" || path.is_empty() {
        return "/".to_string();
    }
    path.to_string()
}

fn npm_operation(url: &Url, method: &str) -> String {
    let method = method.to_ascii_uppercase();
    let path = npm_registry_path(url);
    if method == "GET" || method == "HEAD" {
        "read".to_string()
    } else if path.starts_with("/-/package/") && path.contains("/dist-tags/") {
        "distTagWrite".to_string()
    } else if path.starts_with("/-/npm/v1/tokens") || path.starts_with("/-/user/token") {
        "tokenWrite".to_string()
    } else if method == "PATCH" {
        "metadataWrite".to_string()
    } else if method == "PUT" || method == "POST" {
        "publish".to_string()
    } else {
        "metadataWrite".to_string()
    }
}

fn npm_operation_fields(
    url: &Url,
    method: &str,
    params: &BTreeMap<String, String>,
    body: &str,
) -> Value {
    let operation = npm_operation(url, method);
    let mut fields = Map::new();
    fields.insert(
        "operation".to_string(),
        Value::String(format!("npm.{operation}")),
    );
    if let Some(package) = params.get("package") {
        fields.insert("packageName".to_string(), Value::String(package.clone()));
    }
    if let Ok(Value::Object(body_json)) = serde_json::from_str::<Value>(body) {
        if let Some(value) = body_json.get("name").and_then(Value::as_str) {
            fields.insert("packageName".to_string(), Value::String(value.to_string()));
        }
        if let Some(value) = body_json.get("version").and_then(Value::as_str) {
            fields.insert(
                "packageVersion".to_string(),
                Value::String(value.to_string()),
            );
        }
        if let Some(value) = body_json.get("tarball_integrity").and_then(Value::as_str) {
            fields.insert(
                "tarballIntegrity".to_string(),
                Value::String(value.to_string()),
            );
        }
    }
    Value::Object(fields)
}

fn validate_adapter(
    req: &DecisionRequest,
    _headers: &BTreeMap<String, String>,
    url: &Url,
    route_match: &RouteMatch<'_>,
) -> Result<(Value, Value), Value> {
    let route = route_match.route;
    let config = &route.adapter_config;
    match route.adapter_type.as_str() {
        "generic.rest" => {
            if let Some(request_config) = get_object(config, "request") {
                let allowed_query = request_config
                    .get("allowedQueryKeys")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<HashSet<_>>()
                    })
                    .unwrap_or_default();
                if !allowed_query.is_empty() || url.query().is_some() {
                    for (key, _) in url.query_pairs() {
                        if !allowed_query.contains(key.as_ref()) {
                            return Err(json!({"error":"generic_query_key_not_allowed","key":key}));
                        }
                    }
                }
                let max_body = request_config
                    .get("maxBodyBytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if max_body > 0 && req.body.len() as u64 > max_body {
                    return Err(json!({"error":"generic_body_too_large","maxBodyBytes":max_body}));
                }
            }
            Ok((json!({}), json!({})))
        }
        "gmail.v1" => {
            let denied = config
                .get("denyEquivalentEndpoints")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|item| item.to_ascii_lowercase())
                .collect::<HashSet<_>>();
            if let Some(blocked) = path_segments(url).intersection(&denied).next() {
                return Err(
                    json!({"error":"gmail_equivalent_endpoint_blocked","endpoint":blocked}),
                );
            }
            let days = config_u64(config, "maxAgeDays", 30);
            if route_match.params.contains_key("message_id") {
                if config
                    .get("allowMessageGetOnlyFromPriorSearch")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
                {
                    let message_id = route_match
                        .params
                        .get("message_id")
                        .cloned()
                        .unwrap_or_default();
                    if !req.gmail_proofs.iter().any(|proof| proof == &message_id) {
                        return Err(
                            json!({"error":"gmail_message_age_not_proven","message_id":message_id}),
                        );
                    }
                }
                Ok((json!({"operation":"gmail.message.get"}), json!({})))
            } else {
                let query = url
                    .query_pairs()
                    .find(|(key, _)| key == "q")
                    .map(|(_, value)| value.to_string())
                    .unwrap_or_default();
                if older_than_days(&query).is_some_and(|age| age > days) {
                    return Err(json!({"error":"gmail_recent_policy","max_days":days}));
                }
                let max_results = config.get("maxResults").and_then(Value::as_u64);
                let rewritten_q = tighten_gmail_query(&query, days);
                Ok((
                    json!({"operation":"gmail.messages.list"}),
                    json!({"query":{"q":rewritten_q,"maxResults":max_results}}),
                ))
            }
        }
        "x.v2" => {
            let operation = x_operation(url, &req.method)
                .ok_or_else(|| json!({"error":"x_unknown_operation_blocked"}))?;
            let allowed_app_ids = config
                .get("appIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<HashSet<_>>();
            if !allowed_app_ids.is_empty() {
                let credential_id = route.credential_ref.as_deref().unwrap_or_default();
                let app_id = req
                    .credential_metadata
                    .get(credential_id)
                    .and_then(|metadata| {
                        metadata.get("x_app_id").or_else(|| metadata.get("app_id"))
                    });
                if !app_id.is_some_and(|value| allowed_app_ids.contains(value.as_str())) {
                    return Err(json!({"error":"x_app_id_denied"}));
                }
            }
            if config
                .get("blockWrites")
                .and_then(Value::as_bool)
                .unwrap_or(true)
                && !operation.ends_with(".read")
            {
                return Err(
                    json!({"error":"x_write_blocked","mode":config.get("mode").and_then(Value::as_str).unwrap_or("readOnly")}),
                );
            }
            let allowed_reads = config
                .get("allowedReadOperations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<HashSet<_>>();
            if operation.ends_with(".read") && !allowed_reads.contains(operation.as_str()) {
                return Err(json!({"error":"x_read_operation_not_allowed","operation":operation}));
            }
            Ok((json!({"operation":operation}), json!({})))
        }
        "npm.registry" => {
            let operation = npm_operation(url, &req.method);
            let allowed = config
                .get("operations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<HashSet<_>>();
            if !allowed.contains(operation.as_str()) {
                return Err(json!({"error":"npm_operation_not_allowed","operation":operation}));
            }
            let fields = npm_operation_fields(url, &req.method, &route_match.params, &req.body);
            if operation == "publish" {
                let missing = ["packageName", "packageVersion", "tarballIntegrity"]
                    .iter()
                    .filter(|field| {
                        !fields
                            .get(**field)
                            .and_then(Value::as_str)
                            .is_some_and(|v| !v.is_empty())
                    })
                    .copied()
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    return Err(json!({"error":"npm_publish_missing_fields","missing":missing}));
                }
            }
            Ok((fields, json!({})))
        }
        other => Err(json!({"error":"unsupported_adapter","adapter":other})),
    }
}

fn constraint_phase_includes(constraint: &Value, phase: &str) -> bool {
    let configured = constraint
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("request");
    configured == phase || configured == "both"
}

fn constraint_payload(
    constraint: &Value,
    error: &str,
    reason: &str,
    mut extra: Map<String, Value>,
) -> Value {
    extra.insert("error".to_string(), Value::String(error.to_string()));
    extra.insert("reason".to_string(), Value::String(reason.to_string()));
    extra.insert(
        "constraint_id".to_string(),
        Value::String(
            constraint
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_string(),
        ),
    );
    if let Some(kind) = constraint.get("type").and_then(Value::as_str) {
        extra.insert(
            "constraint_type".to_string(),
            Value::String(kind.to_string()),
        );
    }
    if let Some(status) = constraint.get("statusCode").and_then(Value::as_u64) {
        extra
            .entry("status_code".to_string())
            .or_insert(json!(status));
    }
    Value::Object(extra)
}

fn constraint_error(constraint: &Value, error: &str, reason: &str) -> Value {
    constraint_payload(constraint, error, reason, Map::new())
}

fn operation_name(operation: &Value) -> &str {
    operation
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn rate_limit_key(
    constraint: &Value,
    route: &Route,
    principal_id: &str,
    credential_ref: Option<&str>,
    credential_version: u64,
    operation: &Value,
) -> String {
    let scope = constraint
        .get("key")
        .and_then(|key| key.get("scope"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            vec![
                Value::String("principal".to_string()),
                Value::String("credential".to_string()),
                Value::String("route".to_string()),
                Value::String("operation".to_string()),
            ]
        });
    let mut material = Map::new();
    material.insert(
        "constraint".to_string(),
        Value::String(
            constraint
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_string(),
        ),
    );
    for item in scope {
        let Some(item) = item.as_str() else {
            continue;
        };
        match item {
            "principal" => {
                material.insert(item.to_string(), Value::String(principal_id.to_string()));
            }
            "credential" => {
                material.insert(
                    item.to_string(),
                    Value::String(credential_ref.unwrap_or_default().to_string()),
                );
            }
            "credentialVersion" => {
                material.insert(item.to_string(), json!(credential_version));
            }
            "route" => {
                material.insert(item.to_string(), Value::String(route.id.clone()));
            }
            "operation" => {
                material.insert(
                    item.to_string(),
                    Value::String(operation_name(operation).to_string()),
                );
            }
            item if item.starts_with("operation.") => {
                let field = item.trim_start_matches("operation.");
                material.insert(
                    item.to_string(),
                    Value::String(
                        operation
                            .get(field)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    ),
                );
            }
            _ => {}
        }
    }
    if let Some(fields) = constraint
        .get("key")
        .and_then(|key| key.get("operationFields"))
        .and_then(Value::as_array)
    {
        for field in fields.iter().filter_map(Value::as_str) {
            material.insert(
                format!("operation.{field}"),
                Value::String(
                    operation
                        .get(field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                ),
            );
        }
    }
    sha256_prefixed(canonical_json(&Value::Object(material)).as_bytes())
}

fn enforce_rate_limit(
    state: &GateState,
    constraint: &Value,
    route: &Route,
    principal_id: &str,
    credential_ref: Option<&str>,
    credential_version: u64,
    policy_hash: &str,
    operation: &Value,
    consume: bool,
) -> Result<(), Value> {
    let max = constraint.get("max").and_then(Value::as_u64).unwrap_or(0);
    let window_seconds = constraint
        .get("windowSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if max == 0 || window_seconds == 0 {
        return Err(constraint_error(
            constraint,
            "constraint_invalid_rate_limit",
            "rate limit constraint is invalid",
        ));
    }
    let now = now_epoch_ms();
    let window_ms = window_seconds as u128 * 1000;
    let key = rate_limit_key(
        constraint,
        route,
        principal_id,
        credential_ref,
        credential_version,
        operation,
    );
    let store = constraint
        .get("store")
        .and_then(Value::as_str)
        .unwrap_or("local");
    if store == "shared" {
        return enforce_shared_rate_limit(
            state,
            constraint,
            route,
            principal_id,
            credential_ref,
            credential_version,
            policy_hash,
            operation,
            consume,
            &key,
            max,
            window_seconds,
        );
    }
    if store != "local" {
        let mut extra = Map::new();
        extra.insert("store".to_string(), Value::String(store.to_string()));
        return Err(constraint_payload(
            constraint,
            "constraint_invalid_rate_limit_store",
            "rate limit constraint has an unsupported store",
            extra,
        ));
    }
    let mut counters = state
        .constraint_rate_counters
        .lock()
        .expect("constraint rate counter lock poisoned");
    let counter = counters.entry(key).or_insert(ConstraintRateCounter {
        window_start_ms: now,
        count: 0,
    });
    if now >= counter.window_start_ms + window_ms {
        counter.window_start_ms = now;
        counter.count = 0;
    }
    if counter.count >= max {
        let retry_after = ((counter.window_start_ms + window_ms).saturating_sub(now) / 1000).max(1);
        let mut extra = Map::new();
        extra.insert("max".to_string(), json!(max));
        extra.insert("windowSeconds".to_string(), json!(window_seconds));
        extra.insert("retry_after_seconds".to_string(), json!(retry_after));
        extra.insert(
            "store".to_string(),
            Value::String(
                constraint
                    .get("store")
                    .and_then(Value::as_str)
                    .unwrap_or("local")
                    .to_string(),
            ),
        );
        return Err(constraint_payload(
            constraint,
            "credential_rate_limit_exceeded",
            "credential use rate limit exceeded",
            extra,
        ));
    }
    if consume {
        counter.count += 1;
    }
    Ok(())
}

fn enforce_shared_rate_limit(
    state: &GateState,
    constraint: &Value,
    route: &Route,
    principal_id: &str,
    credential_ref: Option<&str>,
    credential_version: u64,
    policy_hash: &str,
    operation: &Value,
    consume: bool,
    key: &str,
    max: u64,
    window_seconds: u64,
) -> Result<(), Value> {
    let mut unavailable = Map::new();
    unavailable.insert("status_code".to_string(), json!(503));
    unavailable.insert("store".to_string(), Value::String("shared".to_string()));
    let Some(url) = state.rate_limit_consume_url.as_ref() else {
        unavailable.insert(
            "detail".to_string(),
            Value::String("shared rate-limit consume URL is not configured".to_string()),
        );
        return Err(constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            unavailable,
        ));
    };
    let Some(token) = state.audit_token.as_ref() else {
        unavailable.insert(
            "detail".to_string(),
            Value::String("data-plane token is not configured".to_string()),
        );
        return Err(constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            unavailable,
        ));
    };
    let body = serde_json::to_vec(&json!({
        "counterKey": key,
        "principalId": principal_id,
        "routeId": route.id,
        "credentialRef": credential_ref.unwrap_or_default(),
        "credentialVersion": credential_version,
        "policyHash": policy_hash,
        "constraintId": constraint.get("id").and_then(Value::as_str).unwrap_or("unnamed"),
        "operation": operation_name(operation),
        "max": max,
        "windowSeconds": window_seconds,
        "consume": consume,
        "actorId": "decision-gate-rs",
    }))
    .map_err(|err| {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(503));
        extra.insert("store".to_string(), Value::String("shared".to_string()));
        extra.insert(
            "detail".to_string(),
            Value::String(format!("serialize shared rate-limit request: {err}")),
        );
        constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            extra,
        )
    })?;
    let response = state
        .audit_client
        .post(url)
        .header("X-Serverware-Data-Plane-Token", token.as_str())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|err| {
            let mut extra = Map::new();
            extra.insert("status_code".to_string(), json!(503));
            extra.insert("store".to_string(), Value::String("shared".to_string()));
            extra.insert(
                "detail".to_string(),
                Value::String(format!("send shared rate-limit request: {err}")),
            );
            constraint_payload(
                constraint,
                "shared_rate_limit_store_unavailable",
                "shared rate-limit store is unavailable",
                extra,
            )
        })?;
    let status = response.status();
    let text = response.text().map_err(|err| {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(503));
        extra.insert("store".to_string(), Value::String("shared".to_string()));
        extra.insert(
            "detail".to_string(),
            Value::String(format!("read shared rate-limit response: {err}")),
        );
        constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            extra,
        )
    })?;
    if !status.is_success() {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(503));
        extra.insert("store".to_string(), Value::String("shared".to_string()));
        extra.insert(
            "detail".to_string(),
            Value::String(format!(
                "shared rate-limit endpoint returned {status}: {text}"
            )),
        );
        return Err(constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            extra,
        ));
    }
    let value: Value = serde_json::from_str(&text).map_err(|err| {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(503));
        extra.insert("store".to_string(), Value::String("shared".to_string()));
        extra.insert(
            "detail".to_string(),
            Value::String(format!("parse shared rate-limit response: {err}: {text}")),
        );
        constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            extra,
        )
    })?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(503));
        extra.insert("store".to_string(), Value::String("shared".to_string()));
        extra.insert(
            "detail".to_string(),
            Value::String(format!("shared rate-limit response was not ok: {value}")),
        );
        return Err(constraint_payload(
            constraint,
            "shared_rate_limit_store_unavailable",
            "shared rate-limit store is unavailable",
            extra,
        ));
    }
    if value.get("allowed").and_then(Value::as_bool) != Some(true) {
        let mut extra = Map::new();
        extra.insert("max".to_string(), json!(max));
        extra.insert("windowSeconds".to_string(), json!(window_seconds));
        extra.insert(
            "retry_after_seconds".to_string(),
            value
                .get("retry_after_seconds")
                .cloned()
                .unwrap_or_else(|| json!(1)),
        );
        extra.insert(
            "remaining".to_string(),
            value.get("remaining").cloned().unwrap_or_else(|| json!(0)),
        );
        if let Some(count) = value.get("count").cloned() {
            extra.insert("count".to_string(), count);
        }
        extra.insert("store".to_string(), Value::String("shared".to_string()));
        return Err(constraint_payload(
            constraint,
            "credential_rate_limit_exceeded",
            "credential use rate limit exceeded",
            extra,
        ));
    }
    Ok(())
}

fn enforce_operation_policy(constraint: &Value, operation: &Value) -> Result<(), Value> {
    let operation_name = operation_name(operation);
    let denied = constraint
        .get("deniedOperations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    let allowed = constraint
        .get("allowedOperations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    if denied.contains(operation_name) {
        let mut extra = Map::new();
        extra.insert(
            "operation".to_string(),
            Value::String(operation_name.to_string()),
        );
        return Err(constraint_payload(
            constraint,
            "credential_operation_denied",
            "credential operation denied by policy",
            extra,
        ));
    }
    if !allowed.is_empty() && !allowed.contains(operation_name) {
        let mut extra = Map::new();
        extra.insert(
            "operation".to_string(),
            Value::String(operation_name.to_string()),
        );
        return Err(constraint_payload(
            constraint,
            "credential_operation_not_allowed",
            "credential operation is not allowed by policy",
            extra,
        ));
    }
    Ok(())
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i64;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn parse_datetime_ms(value: &Value) -> Option<i128> {
    if let Some(number) = value.as_i64() {
        return Some(if number > 10_000_000_000 {
            number as i128
        } else {
            number as i128 * 1000
        });
    }
    if let Some(number) = value.as_u64() {
        return Some(if number > 10_000_000_000 {
            number as i128
        } else {
            number as i128 * 1000
        });
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    if text.chars().all(|ch| ch.is_ascii_digit()) {
        let number = text.parse::<i128>().ok()?;
        return Some(if number > 10_000_000_000 {
            number
        } else {
            number * 1000
        });
    }
    parse_datetime_text_ms(text)
}

fn parse_datetime_text_ms(text: &str) -> Option<i128> {
    if text.len() < 10 {
        return None;
    }
    let year = text.get(0..4)?.parse::<i64>().ok()?;
    let month = text.get(5..7)?.parse::<u32>().ok()?;
    let day = text.get(8..10)?.parse::<u32>().ok()?;
    if text.as_bytes().get(4) != Some(&b'-') || text.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let mut hour = 0_i128;
    let mut minute = 0_i128;
    let mut second = 0_i128;
    if text.len() >= 19 && matches!(text.as_bytes().get(10), Some(b'T') | Some(b' ')) {
        hour = text.get(11..13)?.parse::<i128>().ok()?;
        minute = text.get(14..16)?.parse::<i128>().ok()?;
        second = text.get(17..19)?.parse::<i128>().ok()?;
    }
    let days = days_from_civil(year, month, day) as i128;
    Some((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000)
}

fn query_values(url: &Url, parameter: &str) -> Vec<String> {
    url.query_pairs()
        .filter(|(key, _)| key == parameter)
        .map(|(_, value)| value.to_string())
        .collect()
}

fn enforce_query_date_window(constraint: &Value, url: &Url) -> Result<(), Value> {
    let parameters = constraint
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let max_age_days = constraint
        .get("maxAgeDays")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if parameters.is_empty() || max_age_days == 0 {
        return Err(constraint_error(
            constraint,
            "constraint_invalid_query_date_window",
            "query date-window constraint is invalid",
        ));
    }
    let now = now_epoch_ms() as i128;
    let cutoff = now - max_age_days as i128 * 86_400_000;
    let future_skew = constraint
        .get("allowFutureSkewSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(300) as i128
        * 1000;
    let required = constraint
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    for parameter in parameters {
        let values = query_values(url, parameter);
        if values.is_empty() {
            if required {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                return Err(constraint_payload(
                    constraint,
                    "query_date_parameter_missing",
                    "required query date parameter is missing",
                    extra,
                ));
            }
            continue;
        }
        for value in values {
            let Some(parsed) = parse_datetime_ms(&Value::String(value.clone())) else {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                return Err(constraint_payload(
                    constraint,
                    "query_date_parameter_invalid",
                    "query date parameter is invalid",
                    extra,
                ));
            };
            if parsed < cutoff {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                extra.insert("maxAgeDays".to_string(), json!(max_age_days));
                return Err(constraint_payload(
                    constraint,
                    "query_date_window_exceeded",
                    "query asks for data outside the allowed age window",
                    extra,
                ));
            }
            if parsed > now + future_skew {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                return Err(constraint_payload(
                    constraint,
                    "query_date_future_denied",
                    "query date parameter is too far in the future",
                    extra,
                ));
            }
        }
    }
    Ok(())
}

fn enforce_query_numeric_bounds(constraint: &Value, url: &Url) -> Result<(), Value> {
    let parameters = constraint
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let required = constraint
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let integer = constraint
        .get("integer")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let minimum = constraint.get("min").and_then(Value::as_f64);
    let maximum = constraint.get("max").and_then(Value::as_f64);
    for parameter in parameters {
        let values = query_values(url, parameter);
        if values.is_empty() {
            if required {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                return Err(constraint_payload(
                    constraint,
                    "query_numeric_parameter_missing",
                    "required numeric query parameter is missing",
                    extra,
                ));
            }
            continue;
        }
        for value in values {
            if integer && value.parse::<i64>().is_err() {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                return Err(constraint_payload(
                    constraint,
                    "query_numeric_parameter_invalid",
                    "numeric query parameter is invalid",
                    extra,
                ));
            }
            let Ok(parsed) = value.parse::<f64>() else {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                return Err(constraint_payload(
                    constraint,
                    "query_numeric_parameter_invalid",
                    "numeric query parameter is invalid",
                    extra,
                ));
            };
            if minimum.is_some_and(|min| parsed < min) {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                return Err(constraint_payload(
                    constraint,
                    "query_numeric_min_exceeded",
                    "numeric query parameter is below policy minimum",
                    extra,
                ));
            }
            if maximum.is_some_and(|max| parsed > max) {
                let mut extra = Map::new();
                extra.insert(
                    "parameter".to_string(),
                    Value::String(parameter.to_string()),
                );
                extra.insert("value".to_string(), Value::String(value));
                return Err(constraint_payload(
                    constraint,
                    "query_numeric_max_exceeded",
                    "numeric query parameter exceeds policy maximum",
                    extra,
                ));
            }
        }
    }
    Ok(())
}

fn values_at_path<'a>(value: &'a Value, path: &str) -> Vec<&'a Value> {
    let parts = path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    values_at_parts(value, &parts, &mut out);
    out
}

fn values_at_parts<'a>(value: &'a Value, parts: &[&str], out: &mut Vec<&'a Value>) {
    if parts.is_empty() {
        out.push(value);
        return;
    }
    if let Some(items) = value.as_array() {
        for item in items {
            values_at_parts(item, parts, out);
        }
        return;
    }
    let Some(object) = value.as_object() else {
        return;
    };
    if parts[0] == "*" {
        for child in object.values() {
            values_at_parts(child, &parts[1..], out);
        }
        return;
    }
    if let Some(child) = object.get(parts[0]) {
        values_at_parts(child, &parts[1..], out);
    }
}

fn json_leaf_paths(value: &Value, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    if let Some(object) = value.as_object() {
        for (key, child) in object {
            prefix.push(key.clone());
            json_leaf_paths(child, prefix, out);
            prefix.pop();
        }
        return;
    }
    if let Some(items) = value.as_array() {
        for item in items {
            json_leaf_paths(item, prefix, out);
        }
        return;
    }
    out.push(prefix.clone());
}

fn path_allowed(path: &[String], allowed: &[Vec<String>]) -> bool {
    allowed.iter().any(|candidate| {
        path == candidate.as_slice()
            || (path.len() >= candidate.len() && path[..candidate.len()] == candidate[..])
    })
}

fn matches_json_type(value: &Value, expected: &str) -> bool {
    match expected {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => false,
    }
}

fn enforce_json_field_rule(
    constraint: &Value,
    payload: &Value,
    field: &str,
    rule: &Value,
) -> Result<(), Value> {
    let values = values_at_path(payload, field);
    if rule
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && values.is_empty()
    {
        let mut extra = Map::new();
        extra.insert("field".to_string(), Value::String(field.to_string()));
        return Err(constraint_payload(
            constraint,
            "json_body_required_field_missing",
            "JSON body is missing a required field",
            extra,
        ));
    }
    for value in values {
        if let Some(expected) = rule.get("type").and_then(Value::as_str) {
            if !matches_json_type(value, expected) {
                let mut extra = Map::new();
                extra.insert("field".to_string(), Value::String(field.to_string()));
                extra.insert(
                    "expectedType".to_string(),
                    Value::String(expected.to_string()),
                );
                return Err(constraint_payload(
                    constraint,
                    "json_body_field_type_denied",
                    "JSON body field has the wrong type",
                    extra,
                ));
            }
        }
        if let Some(allowed) = rule.get("enum").and_then(Value::as_array) {
            if !allowed.iter().any(|item| item == value) {
                let mut extra = Map::new();
                extra.insert("field".to_string(), Value::String(field.to_string()));
                return Err(constraint_payload(
                    constraint,
                    "json_body_field_enum_denied",
                    "JSON body field value is not in the allowed set",
                    extra,
                ));
            }
        }
        if let Some(expected) = rule.get("equals") {
            if expected != value {
                let mut extra = Map::new();
                extra.insert("field".to_string(), Value::String(field.to_string()));
                return Err(constraint_payload(
                    constraint,
                    "json_body_field_equals_denied",
                    "JSON body field does not match required value",
                    extra,
                ));
            }
        }
        if let Some(text) = value.as_str() {
            if let Some(min) = rule.get("minLength").and_then(Value::as_u64) {
                if text.chars().count() < min as usize {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String(field.to_string()));
                    return Err(constraint_payload(
                        constraint,
                        "json_body_field_min_length",
                        "JSON body field is too short",
                        extra,
                    ));
                }
            }
            if let Some(max) = rule.get("maxLength").and_then(Value::as_u64) {
                if text.chars().count() > max as usize {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String(field.to_string()));
                    return Err(constraint_payload(
                        constraint,
                        "json_body_field_max_length",
                        "JSON body field is too long",
                        extra,
                    ));
                }
            }
        }
        if let Some(number) = value.as_f64() {
            if rule
                .get("min")
                .and_then(Value::as_f64)
                .is_some_and(|min| number < min)
            {
                let mut extra = Map::new();
                extra.insert("field".to_string(), Value::String(field.to_string()));
                return Err(constraint_payload(
                    constraint,
                    "json_body_field_min",
                    "JSON body field is below policy minimum",
                    extra,
                ));
            }
            if rule
                .get("max")
                .and_then(Value::as_f64)
                .is_some_and(|max| number > max)
            {
                let mut extra = Map::new();
                extra.insert("field".to_string(), Value::String(field.to_string()));
                return Err(constraint_payload(
                    constraint,
                    "json_body_field_max",
                    "JSON body field exceeds policy maximum",
                    extra,
                ));
            }
        }
        if let Some(items) = value.as_array() {
            if let Some(min) = rule.get("minItems").and_then(Value::as_u64) {
                if items.len() < min as usize {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String(field.to_string()));
                    return Err(constraint_payload(
                        constraint,
                        "json_body_field_min_items",
                        "JSON body array has too few items",
                        extra,
                    ));
                }
            }
            if let Some(max) = rule.get("maxItems").and_then(Value::as_u64) {
                if items.len() > max as usize {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String(field.to_string()));
                    return Err(constraint_payload(
                        constraint,
                        "json_body_field_max_items",
                        "JSON body array has too many items",
                        extra,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn enforce_json_body(
    constraint: &Value,
    req: &DecisionRequest,
    headers: &BTreeMap<String, String>,
) -> Result<(), Value> {
    let required_fields = constraint
        .get("requiredFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if req.body.is_empty() {
        if required_fields.is_empty() {
            return Ok(());
        }
        return Err(constraint_error(
            constraint,
            "json_body_missing",
            "JSON body is required",
        ));
    }
    if let Some(content_types) = constraint.get("contentTypes").and_then(Value::as_array) {
        let allowed = content_types
            .iter()
            .filter_map(Value::as_str)
            .map(|item| item.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let content_type = headers
            .get("content-type")
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        if !allowed.is_empty() && !allowed.contains(content_type.as_str()) {
            let mut extra = Map::new();
            extra.insert("contentType".to_string(), Value::String(content_type));
            return Err(constraint_payload(
                constraint,
                "json_body_content_type_denied",
                "request content type is not allowed for JSON body policy",
                extra,
            ));
        }
    }
    let payload = serde_json::from_str::<Value>(&req.body).map_err(|_| {
        constraint_error(
            constraint,
            "json_body_invalid",
            "request body is not valid JSON",
        )
    })?;
    if let Some(allowed_fields) = constraint.get("allowedFields").and_then(Value::as_array) {
        let allowed = allowed_fields
            .iter()
            .filter_map(Value::as_str)
            .map(|path| path.split('.').map(ToString::to_string).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        if !allowed.is_empty() {
            let mut leaves = Vec::new();
            json_leaf_paths(&payload, &mut Vec::new(), &mut leaves);
            for leaf in leaves {
                if !path_allowed(&leaf, &allowed) {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String(leaf.join(".")));
                    return Err(constraint_payload(
                        constraint,
                        "json_body_field_not_allowed",
                        "JSON body contains a field outside the allowlist",
                        extra,
                    ));
                }
            }
        }
    }
    if let Some(denied_fields) = constraint.get("deniedFields").and_then(Value::as_array) {
        for field in denied_fields.iter().filter_map(Value::as_str) {
            if !values_at_path(&payload, field).is_empty() {
                let mut extra = Map::new();
                extra.insert("field".to_string(), Value::String(field.to_string()));
                return Err(constraint_payload(
                    constraint,
                    "json_body_field_denied",
                    "JSON body contains a denied field",
                    extra,
                ));
            }
        }
    }
    for field in required_fields {
        if values_at_path(&payload, field).is_empty() {
            let mut extra = Map::new();
            extra.insert("field".to_string(), Value::String(field.to_string()));
            return Err(constraint_payload(
                constraint,
                "json_body_required_field_missing",
                "JSON body is missing a required field",
                extra,
            ));
        }
    }
    if let Some(fields) = constraint.get("fields").and_then(Value::as_object) {
        for (field, rule) in fields {
            enforce_json_field_rule(constraint, &payload, field, rule)?;
        }
    }
    Ok(())
}

fn evaluate_request_constraints(
    state: &GateState,
    route: &Route,
    req: &DecisionRequest,
    headers: &BTreeMap<String, String>,
    url: &Url,
    principal_id: &str,
    credential_ref: Option<&str>,
    credential_version: u64,
    policy_hash: &str,
    operation: &Value,
    consume_rate_limits: bool,
    rate_limits_only: bool,
) -> Result<(), Value> {
    for constraint in &route.constraints {
        let Some(kind) = constraint.get("type").and_then(Value::as_str) else {
            continue;
        };
        if !constraint_phase_includes(constraint, "request") {
            continue;
        }
        if rate_limits_only && kind != "rateLimit" {
            continue;
        }
        match kind {
            "rateLimit" => enforce_rate_limit(
                state,
                constraint,
                route,
                principal_id,
                credential_ref,
                credential_version,
                policy_hash,
                operation,
                consume_rate_limits,
            )?,
            "operationPolicy" => enforce_operation_policy(constraint, operation)?,
            "queryDateWindow" => enforce_query_date_window(constraint, url)?,
            "queryNumericBounds" => enforce_query_numeric_bounds(constraint, url)?,
            "jsonBody" => enforce_json_body(constraint, req, headers)?,
            _ => {}
        }
    }
    Ok(())
}

fn enforce_response_date_window(constraint: &Value, body: &[u8]) -> Result<(), Value> {
    let payload = serde_json::from_slice::<Value>(body).map_err(|_| {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(502));
        constraint_payload(
            constraint,
            "response_json_invalid",
            "response body is not valid JSON",
            extra,
        )
    })?;
    let max_age_days = constraint
        .get("maxAgeDays")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if max_age_days == 0 {
        return Err(constraint_error(
            constraint,
            "constraint_invalid_response_date_window",
            "response date-window constraint is invalid",
        ));
    }
    let now = now_epoch_ms() as i128;
    let cutoff = now - max_age_days as i128 * 86_400_000;
    let future_skew = constraint
        .get("allowFutureSkewSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(300) as i128
        * 1000;
    let required = constraint
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut items = Vec::new();
    if let Some(item_paths) = constraint.get("items").and_then(Value::as_array) {
        for item_path in item_paths.iter().filter_map(Value::as_str) {
            items.extend(values_at_path(&payload, item_path));
        }
    } else {
        items.push(&payload);
    }
    if required && items.is_empty() {
        let mut extra = Map::new();
        extra.insert("status_code".to_string(), json!(502));
        return Err(constraint_payload(
            constraint,
            "response_items_missing",
            "response does not contain required items",
            extra,
        ));
    }
    let date_fields = constraint
        .get("dateFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if date_fields.is_empty() {
        return Err(constraint_error(
            constraint,
            "constraint_invalid_response_date_window",
            "response date fields are missing",
        ));
    }
    for item in items {
        for field in &date_fields {
            let values = values_at_path(item, field);
            if values.is_empty() {
                if required {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String((*field).to_string()));
                    extra.insert("status_code".to_string(), json!(502));
                    return Err(constraint_payload(
                        constraint,
                        "response_date_field_missing",
                        "response item is missing a required date field",
                        extra,
                    ));
                }
                continue;
            }
            for value in values {
                let Some(parsed) = parse_datetime_ms(value) else {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String((*field).to_string()));
                    extra.insert("value".to_string(), value.clone());
                    extra.insert("status_code".to_string(), json!(502));
                    return Err(constraint_payload(
                        constraint,
                        "response_date_field_invalid",
                        "response date field is invalid",
                        extra,
                    ));
                };
                if parsed < cutoff {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String((*field).to_string()));
                    extra.insert("value".to_string(), value.clone());
                    extra.insert("maxAgeDays".to_string(), json!(max_age_days));
                    extra.insert("status_code".to_string(), json!(502));
                    return Err(constraint_payload(
                        constraint,
                        "response_date_window_exceeded",
                        "response contains data outside the allowed age window",
                        extra,
                    ));
                }
                if parsed > now + future_skew {
                    let mut extra = Map::new();
                    extra.insert("field".to_string(), Value::String((*field).to_string()));
                    extra.insert("value".to_string(), value.clone());
                    extra.insert("status_code".to_string(), json!(502));
                    return Err(constraint_payload(
                        constraint,
                        "response_date_future_denied",
                        "response date field is too far in the future",
                        extra,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_response_constraints(route: &Route, body: &[u8]) -> Result<(), Value> {
    for constraint in &route.constraints {
        let Some(kind) = constraint.get("type").and_then(Value::as_str) else {
            continue;
        };
        if !constraint_phase_includes(constraint, "response") {
            continue;
        }
        if kind == "responseDateWindow" {
            enforce_response_date_window(constraint, body)?;
        }
    }
    Ok(())
}

fn decide(state: &GateState, req: DecisionRequest) -> Value {
    decide_internal(state, req, None)
}

fn decide_internal(
    state: &GateState,
    req: DecisionRequest,
    authenticated_principal_id: Option<&str>,
) -> Value {
    let started = Instant::now();
    let mut req = req;
    let snapshot = current_snapshot(state);
    let headers = lower_headers(&req.headers);
    let url = match Url::parse(&req.url) {
        Ok(url) => url,
        Err(err) => {
            return deny(
                400,
                "invalid url",
                json!({"error":"invalid_url","detail":err.to_string()}),
                started,
            )
        }
    };
    let principal = if let Some(principal_id) = authenticated_principal_id {
        snapshot
            .principals
            .iter()
            .find(|item| item.id == principal_id)
    } else {
        snapshot.identify_principal(req.client_ip.as_deref(), &headers)
    };
    let Some(principal) = principal else {
        return deny(
            403,
            "client principal denied",
            json!({"error":"client_principal_denied"}),
            started,
        );
    };
    let Some(route_match) = snapshot.match_route(&principal.id, &req.method, &url) else {
        return deny(
            403,
            "unknown route denied",
            json!({"error":"unknown_route_denied"}),
            started,
        );
    };
    let route = route_match.route;
    if route.adapter_type == "gmail.v1" {
        merge_gmail_proofs(state, &mut req, &principal.id, &route.id);
    }
    let credential_ref = route.credential_ref.clone();
    let injection = if let Some(credential_id) = credential_ref.as_ref() {
        let Some(credential) = snapshot.credentials.get(credential_id) else {
            return deny(
                500,
                "credential missing",
                json!({"error":"credential_missing"}),
                started,
            );
        };
        credential.injection.clone()
    } else {
        json!(null)
    };
    let credential_version = if let Some(credential_id) = credential_ref.as_ref() {
        match credential_generation(state, credential_id) {
            Some(Some(version)) => version,
            Some(None) => {
                return deny(
                    410,
                    "credential has been deleted",
                    json!({"error":"credential_deleted","credential_ref":credential_id}),
                    started,
                )
            }
            None => {
                return deny(
                    503,
                    "credential generation is unavailable",
                    json!({"error":"credential_generation_missing","credential_ref":credential_id}),
                    started,
                )
            }
        }
    } else {
        0
    };
    let secret_lease = if let Some(credential_id) = credential_ref.as_ref() {
        match credential_lease(state, credential_id, credential_version) {
            Some(lease) => {
                req.credential_metadata
                    .insert(credential_id.clone(), lease.metadata.clone());
                Some(lease)
            }
            None => {
                return deny(
                    503,
                    "credential lease is unavailable",
                    json!({
                        "error":"credential_lease_missing",
                        "credential_ref":credential_id,
                        "credential_version":credential_version,
                    }),
                    started,
                )
            }
        }
    } else {
        None
    };

    let (operation, rewrite) = match validate_adapter(&req, &headers, &url, &route_match) {
        Ok(value) => value,
        Err(payload) => {
            let status = payload
                .get("status_code")
                .and_then(Value::as_u64)
                .unwrap_or(403) as u16;
            let reason = payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("adapter denied")
                .to_string();
            return deny(status, &reason, payload, started);
        }
    };
    if let Err(payload) = evaluate_request_constraints(
        state,
        route,
        &req,
        &headers,
        &url,
        &principal.id,
        credential_ref.as_deref(),
        credential_version,
        &snapshot.hash,
        &operation,
        false,
        false,
    ) {
        let status = payload
            .get("status_code")
            .and_then(Value::as_u64)
            .unwrap_or(403) as u16;
        let reason = payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("credential_constraint_denied")
            .to_string();
        return deny(status, &reason, payload, started);
    }

    let canonical = canonical_request(
        &req,
        &headers,
        &url,
        principal,
        route,
        credential_version,
        &snapshot.hash,
        &operation,
    );
    let request_digest = digest_json(&canonical);
    let operation_digest = operation_digest(&canonical);
    let flow_id = digest_json(&json!({
        "route_id":route.id,
        "principal_id":principal.id,
        "request_digest":request_digest,
        "operation_digest":operation_digest,
        "now_ms":now_epoch_ms(),
    }));
    let redacted_display = json!({
        "method": req.method.clone(),
        "url": url.as_str(),
        "route_id": route.id.clone(),
        "principal": principal.id.clone(),
        "operation": operation.clone(),
        "body_sha256": canonical
            .get("request")
            .and_then(|request| request.get("body_sha256"))
            .cloned()
            .unwrap_or(Value::Null),
    });
    let jit_required = route
        .jit
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if jit_required && audit_queue_full(state) {
        return deny(
            503,
            "required audit spool is full",
            json!({"error":"audit_spool_full","required_event":"data_plane.jit.grant_consumed"}),
            started,
        );
    }
    let (consumed_grant, grant_store, pending_approval) = if jit_required {
        match consume_grant(
            state,
            &principal.id,
            &route.id,
            credential_ref.as_deref().unwrap_or_default(),
            credential_version,
            &snapshot.hash,
            &request_digest,
            &operation_digest,
            &flow_id,
            &req.method,
            url.as_str(),
            &canonical,
            &redacted_display,
        ) {
            Ok(result) => result,
            Err(err) => {
                return deny(
                    503,
                    "shared JIT grant store unavailable",
                    json!({"error":"shared_jit_grant_store_unavailable","detail":err}),
                    started,
                )
            }
        }
    } else {
        (None, "none", None)
    };
    let allowed = !jit_required || consumed_grant.is_some();
    let action = if allowed { "allow" } else { "jit_required" };
    if let Some(ref grant) = consumed_grant {
        if !enqueue_required_audit(
            state,
            "data_plane.jit.grant_consumed",
            json!({
                "component":"serverware-decision-gate-rs",
                "grant_id":grant.id.clone(),
                "approval_id":grant.approval_id.clone(),
                "principal_id":principal.id.clone(),
                "route_id":route.id.clone(),
                "adapter":route.adapter_type.clone(),
                "policy_hash":snapshot.hash.clone(),
                "credential_ref":credential_ref.clone(),
                "credential_version":credential_version,
                "request_digest":request_digest.clone(),
                "operation_digest":operation_digest.clone(),
                "flow_id":flow_id.clone(),
                "grant_store":grant_store,
            }),
        ) {
            return deny(
                503,
                "required audit event could not be queued",
                json!({"error":"audit_required_event_failed","required_event":"data_plane.jit.grant_consumed"}),
                started,
            );
        }
    }
    if allowed {
        if let Err(payload) = evaluate_request_constraints(
            state,
            route,
            &req,
            &headers,
            &url,
            &principal.id,
            credential_ref.as_deref(),
            credential_version,
            &snapshot.hash,
            &operation,
            true,
            true,
        ) {
            let status = payload
                .get("status_code")
                .and_then(Value::as_u64)
                .unwrap_or(403) as u16;
            let reason = payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("credential_constraint_denied")
                .to_string();
            return deny(status, &reason, payload, started);
        }
    }
    json!({
        "action": action,
        "allowed": allowed,
        "status_code": if allowed {200} else {428},
        "principal_id": principal.id,
        "route_id": route.id,
        "adapter": route.adapter_type,
        "policy_hash": snapshot.hash,
        "credential_ref": credential_ref,
        "credential_version": credential_version,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "operation": operation,
        "rewrite": rewrite,
        "jit": if jit_required {
            match consumed_grant {
                Some(ref grant) => json!({"required":true,"grant_consumed":true,"grant_id":grant.id,"approval_id":grant.approval_id,"grant_store":grant_store}),
                None => json!({
                    "required":true,
                    "grant_consumed":false,
                    "grant_store":grant_store,
                    "approval_id":pending_approval.as_ref().map(|approval| approval.id.clone()),
                    "expires_at":pending_approval.as_ref().and_then(|approval| approval.expires_at.clone()),
                    "retry_after_seconds":3
                }),
            }
        } else {
            json!({"required":false})
        },
        "approval_id": pending_approval.as_ref().map(|approval| approval.id.clone()),
        "expires_at": pending_approval.as_ref().and_then(|approval| approval.expires_at.clone()),
        "injection": if allowed {
            json!({
                "credential_ref":route.credential_ref,
                "credential_version":credential_version,
                "secret_available":secret_lease.as_ref().is_some_and(|lease| !lease.secret.is_empty()),
                "plan":injection,
            })
        } else {
            json!(null)
        },
        "canonical_request": canonical,
        "decision_us": started.elapsed().as_micros() as u64,
        "hot_path": {"sqlite_calls": 0, "filesystem_calls": 0},
    })
}

fn http_response(status: &str, body: Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(&body).expect("response serialization failed");
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .into_bytes();
    response.extend_from_slice(&bytes);
    response
}

fn http_binary_response_with_headers(
    status: StatusCode,
    content_type: Option<&str>,
    body: Vec<u8>,
    headers: &[(&str, String)],
) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("Status");
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status.as_u16(),
        reason,
        body.len()
    )
    .into_bytes();
    if let Some(content_type) = content_type {
        response.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    for (name, value) in headers {
        response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(&body);
    response
}

fn response_connection_value(keep_alive: bool) -> &'static str {
    if keep_alive {
        "keep-alive"
    } else {
        "close"
    }
}

fn write_stream_response_headers(
    writer: &mut dyn Write,
    status: StatusCode,
    content_type: Option<&str>,
    content_length: Option<u64>,
    keep_alive: bool,
) -> Result<bool, String> {
    let reason = status.canonical_reason().unwrap_or("Status");
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\nConnection: {}\r\n",
        status.as_u16(),
        reason,
        response_connection_value(keep_alive)
    );
    if let Some(content_type) = content_type {
        headers.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    let chunked = content_length.is_none();
    if let Some(content_length) = content_length {
        headers.push_str(&format!("Content-Length: {content_length}\r\n"));
    } else {
        headers.push_str("Transfer-Encoding: chunked\r\n");
    }
    headers.push_str("\r\n");
    writer
        .write_all(headers.as_bytes())
        .map_err(|err| format!("write response headers: {err}"))?;
    Ok(chunked)
}

fn headers_want_close(headers: &BTreeMap<String, String>) -> bool {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .is_some_and(|(_, value)| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
}

fn request_head_wants_close(request: &RequestHead) -> bool {
    headers_want_close(&request.headers)
}

fn override_response_connection(mut response: Vec<u8>, keep_alive: bool) -> Vec<u8> {
    let Some(header_end) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
    else {
        return response;
    };
    let needle = b"Connection: close\r\n";
    let replacement = if keep_alive {
        b"Connection: keep-alive\r\n".as_slice()
    } else {
        needle.as_slice()
    };
    if let Some(index) = response[..header_end]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        response.splice(index..index + needle.len(), replacement.iter().copied());
    }
    response
}

fn json_status_response(status: StatusCode, body: Value) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("Status");
    http_response(&format!("{} {}", status.as_u16(), reason), body)
}

fn absolute_form_target(target: &str) -> bool {
    target.starts_with("https://") || target.starts_with("http://")
}

fn body_sha_bytes(body: &[u8]) -> String {
    sha256_prefixed(body)
}

struct RequestBodyStreamStats {
    hasher: Sha256,
    bytes: u64,
}

impl RequestBodyStreamStats {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes: 0,
        }
    }
}

struct RequestBodyStream {
    prefetched: Cursor<Vec<u8>>,
    source: Box<dyn Read + Send>,
    remaining: usize,
    stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl RequestBodyStream {
    fn new(
        source: Box<dyn Read + Send>,
        prefetched: Vec<u8>,
        content_length: usize,
        stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            prefetched: Cursor::new(prefetched),
            source,
            remaining: content_length,
            stats,
        }
    }
}

impl Read for RequestBodyStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let max_read = out.len().min(self.remaining);
        let prefetched_len = self.prefetched.get_ref().len() as u64;
        let read = if self.prefetched.position() < prefetched_len {
            self.prefetched.read(&mut out[..max_read])?
        } else {
            self.source.read(&mut out[..max_read])?
        };
        if read > 0 {
            self.remaining -= read;
            let mut stats = self
                .stats
                .lock()
                .expect("request stream stats mutex poisoned");
            stats.hasher.update(&out[..read]);
            stats.bytes += read as u64;
        }
        Ok(read)
    }
}

struct ChannelBodyReader {
    receiver: Receiver<Vec<u8>>,
    current: Cursor<Vec<u8>>,
}

impl ChannelBodyReader {
    fn new(receiver: Receiver<Vec<u8>>) -> Self {
        Self {
            receiver,
            current: Cursor::new(Vec::new()),
        }
    }
}

impl Read for ChannelBodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current.position() < self.current.get_ref().len() as u64 {
                return self.current.read(out);
            }
            match self.receiver.recv() {
                Ok(chunk) => self.current = Cursor::new(chunk),
                Err(_) => return Ok(0),
            }
        }
    }
}

fn update_request_stream_stats(stats: &Arc<Mutex<RequestBodyStreamStats>>, chunk: &[u8]) {
    if chunk.is_empty() {
        return;
    }
    let mut stats = stats.lock().expect("request stream stats mutex poisoned");
    stats.hasher.update(chunk);
    stats.bytes += chunk.len() as u64;
}

fn request_stream_stats_snapshot(stats: &Arc<Mutex<RequestBodyStreamStats>>) -> (String, u64) {
    let stats = stats.lock().expect("request stream stats mutex poisoned");
    (
        format!("sha256:{}", hex::encode(stats.hasher.clone().finalize())),
        stats.bytes,
    )
}

fn send_body_chunk(sender: &SyncSender<Vec<u8>>, chunk: Vec<u8>) -> Result<(), String> {
    if chunk.is_empty() {
        return Ok(());
    }
    sender
        .send(chunk)
        .map_err(|_| "upstream request body reader closed".to_string())
}

fn pump_request_body_to_channel<R: Read>(
    reader: &mut R,
    prefetched: Vec<u8>,
    content_length: usize,
    sender: SyncSender<Vec<u8>>,
    stats: Arc<Mutex<RequestBodyStreamStats>>,
) -> Result<(), String> {
    if prefetched.len() > content_length {
        return Err("request pipelining is not supported".to_string());
    }
    let mut remaining = content_length;
    if !prefetched.is_empty() {
        update_request_stream_stats(&stats, &prefetched);
        remaining -= prefetched.len();
        send_body_chunk(&sender, prefetched)?;
    }
    let mut buffer = [0u8; 16 * 1024];
    while remaining > 0 {
        let max_read = buffer.len().min(remaining);
        let read = reader
            .read(&mut buffer[..max_read])
            .map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("connection closed before body".to_string());
        }
        update_request_stream_stats(&stats, &buffer[..read]);
        send_body_chunk(&sender, buffer[..read].to_vec())?;
        remaining -= read;
    }
    Ok(())
}

fn error_chain(error: &dyn Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        parts.push(error.to_string());
        source = error.source();
    }
    parts.join(": ")
}

fn status_from_decision(decision: &Value) -> StatusCode {
    let code = decision
        .get("status_code")
        .and_then(Value::as_u64)
        .unwrap_or(500) as u16;
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

fn apply_rewrite(url: &mut Url, rewrite: &Value) {
    if let Some(query) = rewrite.get("query").and_then(Value::as_object) {
        let mut existing = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        for (key, value) in query {
            if value.is_null() {
                existing.remove(key);
            } else if let Some(value) = value.as_str() {
                existing.insert(key.clone(), value.to_string());
            } else {
                existing.insert(key.clone(), value.to_string());
            }
        }
        url.query_pairs_mut().clear().extend_pairs(existing.iter());
    }
}

fn filtered_forward_headers(headers: &BTreeMap<String, String>) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "connection"
            || lower == "proxy-connection"
            || lower == "proxy-authorization"
            || lower == "authorization"
            || lower == "x-serverware-agent"
            || lower.starts_with("proxy-")
            || lower == HOST.as_str()
            || lower == CONTENT_LENGTH.as_str()
        {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(lower.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            continue;
        };
        forwarded.insert(name, value);
    }
    forwarded
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: String) -> Result<(), String> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| format!("invalid injection header {name}: {err}"))?;
    let value =
        HeaderValue::from_str(&value).map_err(|err| format!("invalid injection value: {err}"))?;
    headers.insert(name, value);
    Ok(())
}

fn secret_field_path_parts(field: &str) -> Result<Vec<&str>, String> {
    let parts = field.split('.').collect::<Vec<_>>();
    if parts.is_empty() {
        return Err("credential injection field must be a dotted object path".to_string());
    }
    for part in &parts {
        let mut bytes = part.bytes();
        let Some(first) = bytes.next() else {
            return Err("credential injection field must be a dotted object path".to_string());
        };
        if !(first == b'_' || first.is_ascii_alphabetic()) {
            return Err("credential injection field must be a dotted object path".to_string());
        }
        if !bytes.all(|item| item == b'_' || item.is_ascii_alphanumeric()) {
            return Err("credential injection field must be a dotted object path".to_string());
        }
    }
    Ok(parts)
}

fn secret_for_injection(lease: &SecretLease, injection: &Value) -> Result<String, String> {
    let Some(field) = injection.get("field").and_then(Value::as_str) else {
        return Ok(lease.secret.clone());
    };
    let payload: Value = serde_json::from_str(&lease.secret)
        .map_err(|err| format!("credential secret is not JSON for field {field}: {err}"))?;
    let mut value = &payload;
    for part in secret_field_path_parts(field)? {
        let Some(object) = value.as_object() else {
            return Err(format!("credential secret missing field {field}"));
        };
        let Some(next) = object.get(part) else {
            return Err(format!("credential secret missing field {field}"));
        };
        value = next;
    }
    let Some(value) = value.as_str() else {
        return Err(format!(
            "credential secret field {field} is not a non-empty string"
        ));
    };
    if value.is_empty() {
        return Err(format!(
            "credential secret field {field} is not a non-empty string"
        ));
    }
    Ok(value.to_string())
}

fn apply_credential_injection(
    headers: &mut HeaderMap,
    url: &mut Url,
    injection: &Value,
    lease: &SecretLease,
) -> Result<(), String> {
    let injection_type = injection
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("bearer");
    let secret = secret_for_injection(lease, injection)?;
    match injection_type {
        "bearer" => {
            let header = injection
                .get("header")
                .and_then(Value::as_str)
                .unwrap_or("authorization");
            let prefix = injection
                .get("prefix")
                .and_then(Value::as_str)
                .unwrap_or("Bearer ");
            insert_header(headers, header, format!("{prefix}{secret}"))
        }
        "header" => {
            let header = injection
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("x-api-key");
            let prefix = injection
                .get("prefix")
                .and_then(Value::as_str)
                .unwrap_or("");
            insert_header(headers, header, format!("{prefix}{secret}"))
        }
        "query" => {
            let name = injection
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("access_token");
            url.query_pairs_mut().append_pair(name, &secret);
            Ok(())
        }
        "cookie" => {
            let name = injection
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("serverware_token");
            let mut value = headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            if !value.is_empty() {
                value.push_str("; ");
            }
            value.push_str(name);
            value.push('=');
            value.push_str(&secret);
            insert_header(headers, "cookie", value)
        }
        "basic" => {
            let username = injection
                .get("username")
                .and_then(Value::as_str)
                .or_else(|| lease.metadata.get("username").map(String::as_str))
                .ok_or("basic credential missing username")?;
            let token = general_purpose::STANDARD.encode(format!("{username}:{secret}"));
            insert_header(headers, "authorization", format!("Basic {token}"))
        }
        other => Err(format!("unknown injection type {other}")),
    }
}

fn internal_date_ms(value: &Value) -> Option<i128> {
    if let Some(number) = value.as_i64() {
        return Some(number as i128);
    }
    value.as_str()?.parse::<i128>().ok()
}

fn gmail_cutoff_ms(days: u64) -> i128 {
    now_epoch_ms() as i128 - (days as i128 * 86_400_000)
}

fn validate_gmail_internal_date(item: &Value, days: u64) -> Result<(), Value> {
    validate_gmail_internal_date_value(item.get("internalDate"), days)
}

fn validate_gmail_internal_date_value(raw_value: Option<&Value>, days: u64) -> Result<(), Value> {
    let Some(raw_value) = raw_value else {
        return Err(json!({"error":"gmail_response_missing_internal_date"}));
    };
    let Some(value) = internal_date_ms(raw_value) else {
        return Err(json!({"error":"gmail_response_invalid_internal_date"}));
    };
    if value < gmail_cutoff_ms(days) {
        return Err(json!({"error":"gmail_response_too_old","max_days":days}));
    }
    Ok(())
}

fn prune_gmail_proofs(cache: &mut HashMap<(String, String, String), u128>, now: u128) {
    cache.retain(|_, expires_at_ms| *expires_at_ms > now);
}

fn active_gmail_proofs(state: &GateState, principal_id: &str, route_id: &str) -> Vec<String> {
    let now = now_epoch_ms();
    let mut cache = state
        .gmail_proofs
        .lock()
        .expect("gmail proof cache mutex poisoned");
    prune_gmail_proofs(&mut cache, now);
    cache
        .iter()
        .filter_map(|((principal, route, message_id), expires_at_ms)| {
            if principal == principal_id && route == route_id && *expires_at_ms > now {
                Some(message_id.clone())
            } else {
                None
            }
        })
        .collect()
}

fn merge_gmail_proofs(
    state: &GateState,
    req: &mut DecisionRequest,
    principal_id: &str,
    route_id: &str,
) {
    let mut proofs = active_gmail_proofs(state, principal_id, route_id);
    proofs.extend(req.gmail_proofs.iter().cloned());
    proofs.sort();
    proofs.dedup();
    req.gmail_proofs = proofs;
}

fn gmail_proof_ttl_ms(route: &Route) -> u128 {
    config_u64(&route.adapter_config, "cacheTtlSeconds", 1800).clamp(1, 86_400) as u128 * 1000
}

fn remember_gmail_proofs(
    state: &GateState,
    principal_id: &str,
    route_id: &str,
    route: &Route,
    message_ids: Vec<String>,
) {
    if message_ids.is_empty() {
        return;
    }
    let now = now_epoch_ms();
    let expires_at_ms = now.saturating_add(gmail_proof_ttl_ms(route));
    let mut cache = state
        .gmail_proofs
        .lock()
        .expect("gmail proof cache mutex poisoned");
    prune_gmail_proofs(&mut cache, now);
    for message_id in message_ids {
        if message_id.is_empty() || message_id.len() > 512 {
            continue;
        }
        while cache.len() >= state.gmail_proof_cache_max {
            let Some(key) = cache.keys().next().cloned() else {
                break;
            };
            cache.remove(&key);
        }
        cache.insert(
            (principal_id.to_string(), route_id.to_string(), message_id),
            expires_at_ms,
        );
    }
}

fn allowed_field_paths(response_config: &Value) -> Vec<Vec<String>> {
    response_config
        .get("allowedFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|field| {
            field
                .split('.')
                .filter(|segment| !segment.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|path| !path.is_empty())
        .collect()
}

fn redact_json_value(source: &Value, paths: &[Vec<String>]) -> Value {
    if paths.is_empty() {
        return source.clone();
    }
    match source {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_json_value(item, paths))
                .collect(),
        ),
        Value::Object(object) => {
            let mut grouped: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
            for path in paths {
                let Some((head, tail)) = path.split_first() else {
                    continue;
                };
                grouped.entry(head.clone()).or_default().push(tail.to_vec());
            }
            let mut redacted = Map::new();
            for (key, tails) in grouped {
                let Some(value) = object.get(&key) else {
                    continue;
                };
                if tails.iter().any(Vec::is_empty) {
                    redacted.insert(key, value.clone());
                    continue;
                }
                let nested_paths = tails
                    .into_iter()
                    .filter(|path| !path.is_empty())
                    .collect::<Vec<_>>();
                let nested = redact_json_value(value, &nested_paths);
                match &nested {
                    Value::Null => {}
                    Value::Object(map) if map.is_empty() => {}
                    _ => {
                        redacted.insert(key, nested);
                    }
                }
            }
            Value::Object(redacted)
        }
        _ => Value::Null,
    }
}

fn json_lines_max_line_bytes(config: &Value) -> usize {
    config
        .get("maxLineBytes")
        .and_then(Value::as_u64)
        .unwrap_or(64 * 1024)
        .min(1024 * 1024) as usize
}

fn json_array_max_item_bytes(config: &Value) -> usize {
    config
        .get("maxItemBytes")
        .or_else(|| config.get("maxLineBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(64 * 1024)
        .min(1024 * 1024) as usize
}

fn json_sse_max_event_bytes(config: &Value) -> usize {
    config
        .get("maxEventBytes")
        .or_else(|| config.get("maxItemBytes"))
        .or_else(|| config.get("maxLineBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(64 * 1024)
        .min(1024 * 1024) as usize
}

fn form_urlencoded_max_pair_bytes(config: &Value) -> usize {
    config
        .get("maxPairBytes")
        .or_else(|| config.get("maxLineBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(64 * 1024)
        .min(1024 * 1024) as usize
}

fn csv_max_record_bytes(config: &Value) -> usize {
    config
        .get("maxRecordBytes")
        .or_else(|| config.get("maxLineBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(64 * 1024)
        .min(1024 * 1024) as usize
}

fn json_nested_max_nested_bytes(config: &Value) -> usize {
    config
        .get("maxNestedBytes")
        .or_else(|| config.get("maxItemBytes"))
        .or_else(|| config.get("maxLineBytes"))
        .and_then(Value::as_u64)
        .unwrap_or(256 * 1024)
        .min(1024 * 1024) as usize
}

fn json_stream_redacts_body(mode: &str) -> bool {
    mode == "jsonlStream"
        || mode == "jsonArrayStream"
        || mode == "jsonSseStream"
        || mode == "jsonNestedStream"
        || mode == "formUrlencodedStream"
        || mode == "csvStream"
}

fn json_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

fn trim_json_ws_bytes(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !json_ws(*byte))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !json_ws(*byte))
        .map(|index| index + 1)
        .unwrap_or(start);
    &value[start..end]
}

fn form_allowed_field_names(paths: &[Vec<String>]) -> HashSet<String> {
    paths
        .iter()
        .map(|path| path.join("."))
        .filter(|field| !field.is_empty())
        .collect()
}

fn form_urlencoded_pair_key(pair: &[u8]) -> String {
    let key = pair
        .iter()
        .position(|byte| *byte == b'=')
        .map(|index| &pair[..index])
        .unwrap_or(pair);
    form_urlencoded::parse(key)
        .next()
        .map(|(decoded, _)| decoded.into_owned())
        .unwrap_or_default()
}

fn csv_record_bytes(record: &ByteRecord) -> usize {
    record.iter().map(|field| field.len()).sum::<usize>() + record.len().saturating_sub(1)
}

fn write_csv_record(record: &ByteRecord) -> Result<Vec<u8>, String> {
    let mut writer = WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    writer
        .write_byte_record(record)
        .map_err(|err| format!("csv_record_write_failed: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("csv_record_flush_failed: {err}"))?;
    writer
        .into_inner()
        .map_err(|err| format!("csv_record_finish_failed: {}", err.into_error()))
}

fn csv_select_record(record: &ByteRecord, indexes: &[usize]) -> Result<ByteRecord, String> {
    let mut selected = ByteRecord::new();
    for index in indexes {
        let Some(field) = record.get(*index) else {
            return Err("csv_record_missing_allowed_field".to_string());
        };
        selected.push_field(field);
    }
    Ok(selected)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RedactedJsonKind {
    Null,
    EmptyObject,
    Other,
}

struct LimitedVecWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl LimitedVecWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedVecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "json_nested_value_too_large",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_json_bytes<W: Write>(out: &mut W, bytes: &[u8]) -> Result<(), io::Error> {
    out.write_all(bytes)
}

fn write_json_value<W: Write, T: Serialize>(out: &mut W, value: &T) -> Result<(), io::Error> {
    serde_json::to_writer(out, value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

struct JsonCopySeed<'a, W: Write> {
    out: &'a mut W,
}

impl<'de, 'a, W: Write> DeserializeSeed<'de> for JsonCopySeed<'a, W> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonCopyVisitor { out: self.out })
    }
}

struct JsonCopyVisitor<'a, W: Write> {
    out: &'a mut W,
}

impl<'de, 'a, W: Write> Visitor<'de> for JsonCopyVisitor<'a, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_value(self.out, &value).map_err(E::custom)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_value(self.out, &value).map_err(E::custom)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_value(self.out, &value).map_err(E::custom)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_value(self.out, &value).map_err(E::custom)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_value(self.out, &value).map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_value(self.out, &value).map_err(E::custom)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        JsonCopySeed { out: self.out }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        write_json_bytes(self.out, b"[").map_err(de::Error::custom)?;
        let mut first = true;
        while seq
            .next_element_seed(JsonCopySeqElementSeed {
                out: self.out,
                first: &mut first,
            })?
            .is_some()
        {}
        write_json_bytes(self.out, b"]").map_err(de::Error::custom)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        write_json_bytes(self.out, b"{").map_err(de::Error::custom)?;
        let mut first = true;
        while let Some(key) = map.next_key::<String>()? {
            if first {
                first = false;
            } else {
                write_json_bytes(self.out, b",").map_err(de::Error::custom)?;
            }
            write_json_value(self.out, &key).map_err(de::Error::custom)?;
            write_json_bytes(self.out, b":").map_err(de::Error::custom)?;
            map.next_value_seed(JsonCopySeed { out: self.out })?;
        }
        write_json_bytes(self.out, b"}").map_err(de::Error::custom)
    }
}

struct JsonCopySeqElementSeed<'a, W: Write> {
    out: &'a mut W,
    first: &'a mut bool,
}

impl<'de, 'a, W: Write> DeserializeSeed<'de> for JsonCopySeqElementSeed<'a, W> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if *self.first {
            *self.first = false;
        } else {
            write_json_bytes(self.out, b",").map_err(de::Error::custom)?;
        }
        JsonCopySeed { out: self.out }.deserialize(deserializer)
    }
}

struct JsonRedactSeed<'a, W: Write> {
    paths: &'a [Vec<String>],
    out: &'a mut W,
    max_nested_bytes: usize,
}

impl<'de, 'a, W: Write> DeserializeSeed<'de> for JsonRedactSeed<'a, W> {
    type Value = RedactedJsonKind;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.paths.is_empty() {
            JsonCopySeed { out: self.out }.deserialize(deserializer)?;
            return Ok(RedactedJsonKind::Other);
        }
        deserializer.deserialize_any(JsonRedactVisitor {
            paths: self.paths,
            out: self.out,
            max_nested_bytes: self.max_nested_bytes,
        })
    }
}

struct JsonRedactVisitor<'a, W: Write> {
    paths: &'a [Vec<String>],
    out: &'a mut W,
    max_nested_bytes: usize,
}

impl<'de, 'a, W: Write> Visitor<'de> for JsonRedactVisitor<'a, W> {
    type Value = RedactedJsonKind;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value to redact")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        write_json_bytes(self.out, b"null").map_err(E::custom)?;
        Ok(RedactedJsonKind::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        JsonRedactSeed {
            paths: self.paths,
            out: self.out,
            max_nested_bytes: self.max_nested_bytes,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        write_json_bytes(self.out, b"[").map_err(de::Error::custom)?;
        let mut first = true;
        while seq
            .next_element_seed(JsonRedactSeqElementSeed {
                paths: self.paths,
                out: self.out,
                max_nested_bytes: self.max_nested_bytes,
                first: &mut first,
            })?
            .is_some()
        {}
        write_json_bytes(self.out, b"]").map_err(de::Error::custom)?;
        Ok(RedactedJsonKind::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        write_json_bytes(self.out, b"{").map_err(de::Error::custom)?;
        let mut wrote_field = false;
        while let Some(key) = map.next_key::<String>()? {
            let tails = self
                .paths
                .iter()
                .filter_map(|path| {
                    let (head, tail) = path.split_first()?;
                    if *head == key {
                        Some(tail.to_vec())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if tails.is_empty() {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if tails.iter().any(Vec::is_empty) {
                if wrote_field {
                    write_json_bytes(self.out, b",").map_err(de::Error::custom)?;
                }
                wrote_field = true;
                write_json_value(self.out, &key).map_err(de::Error::custom)?;
                write_json_bytes(self.out, b":").map_err(de::Error::custom)?;
                map.next_value_seed(JsonCopySeed { out: self.out })?;
                continue;
            }
            let nested_paths = tails
                .into_iter()
                .filter(|path| !path.is_empty())
                .collect::<Vec<_>>();
            let mut nested = LimitedVecWriter::new(self.max_nested_bytes);
            let kind = map.next_value_seed(JsonRedactSeed {
                paths: &nested_paths,
                out: &mut nested,
                max_nested_bytes: self.max_nested_bytes,
            })?;
            if !matches!(kind, RedactedJsonKind::Null | RedactedJsonKind::EmptyObject) {
                if wrote_field {
                    write_json_bytes(self.out, b",").map_err(de::Error::custom)?;
                }
                wrote_field = true;
                write_json_value(self.out, &key).map_err(de::Error::custom)?;
                write_json_bytes(self.out, b":").map_err(de::Error::custom)?;
                write_json_bytes(self.out, &nested.into_inner()).map_err(de::Error::custom)?;
            }
        }
        write_json_bytes(self.out, b"}").map_err(de::Error::custom)?;
        Ok(if wrote_field {
            RedactedJsonKind::Other
        } else {
            RedactedJsonKind::EmptyObject
        })
    }
}

struct JsonRedactSeqElementSeed<'a, W: Write> {
    paths: &'a [Vec<String>],
    out: &'a mut W,
    max_nested_bytes: usize,
    first: &'a mut bool,
}

impl<'de, 'a, W: Write> DeserializeSeed<'de> for JsonRedactSeqElementSeed<'a, W> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if *self.first {
            *self.first = false;
        } else {
            write_json_bytes(self.out, b",").map_err(de::Error::custom)?;
        }
        JsonRedactSeed {
            paths: self.paths,
            out: self.out,
            max_nested_bytes: self.max_nested_bytes,
        }
        .deserialize(deserializer)?;
        Ok(())
    }
}

fn redact_json_nested_to_writer<R: Read, W: Write>(
    reader: R,
    writer: &mut W,
    allowed_fields: &[Vec<String>],
    max_nested_bytes: usize,
) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    JsonRedactSeed {
        paths: allowed_fields,
        out: writer,
        max_nested_bytes,
    }
    .deserialize(&mut deserializer)
    .map_err(|err| format!("json_nested_invalid_json: {err}"))?;
    deserializer
        .end()
        .map_err(|err| format!("json_nested_trailing_data: {err}"))?;
    Ok(())
}

fn redact_json_line(line: &[u8], paths: &[Vec<String>]) -> Result<Vec<u8>, String> {
    let trimmed = if line.ends_with(b"\r\n") {
        &line[..line.len().saturating_sub(2)]
    } else if line.ends_with(b"\n") {
        &line[..line.len().saturating_sub(1)]
    } else {
        line
    };
    if trimmed.is_empty() {
        return Ok(b"\n".to_vec());
    }
    let payload = serde_json::from_slice::<Value>(trimmed)
        .map_err(|err| format!("json_lines_invalid_json: {err}"))?;
    let redacted = redact_json_value(&payload, paths);
    let mut out =
        serde_json::to_vec(&redacted).map_err(|err| format!("json_lines_serialize: {err}"))?;
    out.push(b'\n');
    Ok(out)
}

struct JsonLinesRedactorReader {
    source: Box<dyn Read + Send>,
    pending: Vec<u8>,
    output: Cursor<Vec<u8>>,
    source_done: bool,
    max_line_bytes: usize,
    allowed_fields: Vec<Vec<String>>,
    output_stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl JsonLinesRedactorReader {
    fn new(
        source: Box<dyn Read + Send>,
        max_line_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
        output_stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            source,
            pending: Vec::new(),
            output: Cursor::new(Vec::new()),
            source_done: false,
            max_line_bytes,
            allowed_fields,
            output_stats,
        }
    }

    fn fill_output(&mut self) -> io::Result<bool> {
        loop {
            if let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line = self.pending.drain(..=newline).collect::<Vec<_>>();
                if line.len() > self.max_line_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "json_lines_line_too_large",
                    ));
                }
                let out = redact_json_line(&line, &self.allowed_fields)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                update_request_stream_stats(&self.output_stats, &out);
                self.output = Cursor::new(out);
                return Ok(true);
            }
            if self.source_done {
                if self.pending.is_empty() {
                    return Ok(false);
                }
                let line = std::mem::take(&mut self.pending);
                if line.len() > self.max_line_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "json_lines_line_too_large",
                    ));
                }
                let out = redact_json_line(&line, &self.allowed_fields)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                update_request_stream_stats(&self.output_stats, &out);
                self.output = Cursor::new(out);
                return Ok(true);
            }
            if self.pending.len() > self.max_line_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "json_lines_line_too_large",
                ));
            }
            let mut buffer = [0u8; 16 * 1024];
            let read = self.source.read(&mut buffer)?;
            if read == 0 {
                self.source_done = true;
                continue;
            }
            self.pending.extend_from_slice(&buffer[..read]);
        }
    }
}

impl Read for JsonLinesRedactorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.output.position() < self.output.get_ref().len() as u64 {
                return self.output.read(out);
            }
            if !self.fill_output()? {
                return Ok(0);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonArrayRedactorState {
    BeforeArray,
    BeforeValueOrEnd,
    BeforeValue,
    InValue,
    AfterValue,
    Done,
}

struct JsonArrayRedactorCore {
    pending: Vec<u8>,
    state: JsonArrayRedactorState,
    first_item: bool,
    in_string: bool,
    escaped: bool,
    depth: usize,
    scan_pos: usize,
    max_item_bytes: usize,
    allowed_fields: Vec<Vec<String>>,
}

impl JsonArrayRedactorCore {
    fn new(max_item_bytes: usize, allowed_fields: Vec<Vec<String>>) -> Self {
        Self {
            pending: Vec::new(),
            state: JsonArrayRedactorState::BeforeArray,
            first_item: true,
            in_string: false,
            escaped: false,
            depth: 0,
            scan_pos: 0,
            max_item_bytes,
            allowed_fields,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.pending.extend_from_slice(chunk);
        self.process(false)
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.process(true)
    }

    fn drain_ws(&mut self) {
        let count = self
            .pending
            .iter()
            .take_while(|byte| json_ws(**byte))
            .count();
        if count > 0 {
            self.pending.drain(..count);
        }
    }

    fn begin_value(&mut self) -> Result<bool, String> {
        self.drain_ws();
        if self.pending.is_empty() {
            return Ok(false);
        }
        if self.pending[0] != b'{' {
            return Err("json_array_item_expected_object".to_string());
        }
        self.state = JsonArrayRedactorState::InValue;
        self.in_string = false;
        self.escaped = false;
        self.depth = 0;
        self.scan_pos = 0;
        Ok(true)
    }

    fn redact_item(&self, item: &[u8]) -> Result<Vec<u8>, String> {
        if item.len() > self.max_item_bytes {
            return Err("json_array_item_too_large".to_string());
        }
        let start = item
            .iter()
            .position(|byte| !json_ws(*byte))
            .unwrap_or(item.len());
        let end = item
            .iter()
            .rposition(|byte| !json_ws(*byte))
            .map(|index| index + 1)
            .unwrap_or(start);
        let trimmed = &item[start..end];
        if trimmed.is_empty() {
            return Err("json_array_empty_item".to_string());
        }
        let payload = serde_json::from_slice::<Value>(trimmed)
            .map_err(|err| format!("json_array_invalid_json: {err}"))?;
        let redacted = redact_json_value(&payload, &self.allowed_fields);
        serde_json::to_vec(&redacted).map_err(|err| format!("json_array_serialize: {err}"))
    }

    fn process(&mut self, source_done: bool) -> Result<Vec<Vec<u8>>, String> {
        let mut output = Vec::new();
        loop {
            match self.state {
                JsonArrayRedactorState::BeforeArray => {
                    self.drain_ws();
                    if self.pending.is_empty() {
                        if source_done {
                            return Err("json_array_missing_open".to_string());
                        }
                        break;
                    }
                    if self.pending[0] != b'[' {
                        return Err("json_array_expected_array".to_string());
                    }
                    self.pending.drain(..1);
                    output.push(b"[".to_vec());
                    self.state = JsonArrayRedactorState::BeforeValueOrEnd;
                }
                JsonArrayRedactorState::BeforeValueOrEnd => {
                    self.drain_ws();
                    if self.pending.is_empty() {
                        if source_done {
                            return Err("json_array_unclosed".to_string());
                        }
                        break;
                    }
                    if self.pending[0] == b']' {
                        self.pending.drain(..1);
                        output.push(b"]".to_vec());
                        self.state = JsonArrayRedactorState::Done;
                        continue;
                    }
                    if !self.begin_value()? {
                        break;
                    }
                }
                JsonArrayRedactorState::BeforeValue => {
                    if !self.begin_value()? {
                        if source_done {
                            return Err("json_array_trailing_comma".to_string());
                        }
                        break;
                    }
                }
                JsonArrayRedactorState::InValue => {
                    let mut complete_end = None;
                    let mut index = self.scan_pos;
                    while index < self.pending.len() {
                        let byte = self.pending[index];
                        if self.in_string {
                            if self.escaped {
                                self.escaped = false;
                            } else if byte == b'\\' {
                                self.escaped = true;
                            } else if byte == b'"' {
                                self.in_string = false;
                            }
                            index += 1;
                            continue;
                        }
                        match byte {
                            b'"' => self.in_string = true,
                            b'{' | b'[' => self.depth += 1,
                            b'}' | b']' => {
                                if self.depth == 0 {
                                    return Err("json_array_depth_underflow".to_string());
                                }
                                self.depth -= 1;
                                if self.depth == 0 {
                                    complete_end = Some(index + 1);
                                    break;
                                }
                            }
                            _ => {}
                        }
                        index += 1;
                    }
                    if let Some(end) = complete_end {
                        let item = self.pending.drain(..end).collect::<Vec<_>>();
                        let mut redacted = self.redact_item(&item)?;
                        let mut chunk = Vec::new();
                        if self.first_item {
                            self.first_item = false;
                        } else {
                            chunk.push(b',');
                        }
                        chunk.append(&mut redacted);
                        output.push(chunk);
                        self.state = JsonArrayRedactorState::AfterValue;
                        self.in_string = false;
                        self.escaped = false;
                        self.depth = 0;
                        self.scan_pos = 0;
                        continue;
                    }
                    self.scan_pos = self.pending.len();
                    if self.pending.len() > self.max_item_bytes {
                        return Err("json_array_item_too_large".to_string());
                    }
                    if source_done {
                        return Err("json_array_unclosed_item".to_string());
                    }
                    break;
                }
                JsonArrayRedactorState::AfterValue => {
                    self.drain_ws();
                    if self.pending.is_empty() {
                        if source_done {
                            return Err("json_array_unclosed".to_string());
                        }
                        break;
                    }
                    match self.pending[0] {
                        b',' => {
                            self.pending.drain(..1);
                            self.state = JsonArrayRedactorState::BeforeValue;
                        }
                        b']' => {
                            self.pending.drain(..1);
                            output.push(b"]".to_vec());
                            self.state = JsonArrayRedactorState::Done;
                        }
                        _ => return Err("json_array_expected_separator".to_string()),
                    }
                }
                JsonArrayRedactorState::Done => {
                    self.drain_ws();
                    if !self.pending.is_empty() {
                        return Err("json_array_trailing_data".to_string());
                    }
                    break;
                }
            }
        }
        Ok(output)
    }
}

struct JsonArrayRedactorReader {
    source: Box<dyn Read + Send>,
    core: JsonArrayRedactorCore,
    output: Cursor<Vec<u8>>,
    queued: VecDeque<Vec<u8>>,
    source_done: bool,
    output_stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl JsonArrayRedactorReader {
    fn new(
        source: Box<dyn Read + Send>,
        max_item_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
        output_stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            source,
            core: JsonArrayRedactorCore::new(max_item_bytes, allowed_fields),
            output: Cursor::new(Vec::new()),
            queued: VecDeque::new(),
            source_done: false,
            output_stats,
        }
    }

    fn enqueue_chunks(&mut self, chunks: Vec<Vec<u8>>) {
        for chunk in chunks {
            update_request_stream_stats(&self.output_stats, &chunk);
            self.queued.push_back(chunk);
        }
    }

    fn fill_output(&mut self) -> io::Result<bool> {
        loop {
            if let Some(chunk) = self.queued.pop_front() {
                self.output = Cursor::new(chunk);
                return Ok(true);
            }
            if self.source_done {
                let chunks = self
                    .core
                    .finish()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                if chunks.is_empty() {
                    return Ok(false);
                }
                self.enqueue_chunks(chunks);
                continue;
            }
            let mut buffer = [0u8; 16 * 1024];
            let read = self.source.read(&mut buffer)?;
            if read == 0 {
                self.source_done = true;
                continue;
            }
            let chunks = self
                .core
                .push(&buffer[..read])
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.enqueue_chunks(chunks);
        }
    }
}

impl Read for JsonArrayRedactorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.output.position() < self.output.get_ref().len() as u64 {
                return self.output.read(out);
            }
            if !self.fill_output()? {
                return Ok(0);
            }
        }
    }
}

struct JsonSseRedactorCore {
    pending: Vec<u8>,
    event_lines: Vec<Vec<u8>>,
    event_bytes: usize,
    max_line_bytes: usize,
    max_event_bytes: usize,
    allowed_fields: Vec<Vec<String>>,
}

impl JsonSseRedactorCore {
    fn new(
        max_line_bytes: usize,
        max_event_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
    ) -> Self {
        Self {
            pending: Vec::new(),
            event_lines: Vec::new(),
            event_bytes: 0,
            max_line_bytes,
            max_event_bytes,
            allowed_fields,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.pending.extend_from_slice(chunk);
        self.process(false)
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.process(true)
    }

    fn process(&mut self, source_done: bool) -> Result<Vec<Vec<u8>>, String> {
        let mut output = Vec::new();
        loop {
            let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') else {
                break;
            };
            let raw_line = self.pending.drain(..=newline).collect::<Vec<_>>();
            output.extend(self.process_line(trim_sse_line(&raw_line))?);
        }
        if self.pending.len() > self.max_line_bytes {
            return Err("json_sse_line_too_large".to_string());
        }
        if source_done {
            if !self.pending.is_empty() {
                let raw_line = std::mem::take(&mut self.pending);
                output.extend(self.process_line(trim_sse_line(&raw_line))?);
            }
            if !self.event_lines.is_empty() {
                output.extend(self.flush_event()?);
            }
        }
        Ok(output)
    }

    fn process_line(&mut self, line: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if line.len() > self.max_line_bytes {
            return Err("json_sse_line_too_large".to_string());
        }
        if line.is_empty() {
            return self.flush_event();
        }
        self.event_bytes = self
            .event_bytes
            .checked_add(line.len() + 1)
            .unwrap_or(self.max_event_bytes + 1);
        if self.event_bytes > self.max_event_bytes {
            return Err("json_sse_event_too_large".to_string());
        }
        self.event_lines.push(line.to_vec());
        Ok(Vec::new())
    }

    fn flush_event(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let lines = std::mem::take(&mut self.event_lines);
        self.event_bytes = 0;
        let mut data_parts = Vec::<Vec<u8>>::new();
        for line in lines {
            if line.starts_with(b":") {
                continue;
            }
            let Some(rest) = line.strip_prefix(b"data:") else {
                continue;
            };
            let value = rest.strip_prefix(b" ").unwrap_or(rest);
            data_parts.push(value.to_vec());
        }
        if data_parts.is_empty() {
            return Ok(Vec::new());
        }
        let mut data = Vec::new();
        for (index, part) in data_parts.iter().enumerate() {
            if index > 0 {
                data.push(b'\n');
            }
            data.extend_from_slice(part);
        }
        let trimmed = trim_json_ws_bytes(&data);
        if trimmed == b"[DONE]" {
            return Ok(vec![b"data: [DONE]\n\n".to_vec()]);
        }
        if trimmed.is_empty() {
            return Err("json_sse_empty_data".to_string());
        }
        let payload = serde_json::from_slice::<Value>(trimmed)
            .map_err(|err| format!("json_sse_invalid_json: {err}"))?;
        let redacted = redact_json_value(&payload, &self.allowed_fields);
        let redacted =
            serde_json::to_vec(&redacted).map_err(|err| format!("json_sse_serialize: {err}"))?;
        let mut out = b"data: ".to_vec();
        out.extend_from_slice(&redacted);
        out.extend_from_slice(b"\n\n");
        Ok(vec![out])
    }
}

fn trim_sse_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

struct JsonSseRedactorReader {
    source: Box<dyn Read + Send>,
    core: JsonSseRedactorCore,
    output: Cursor<Vec<u8>>,
    queued: VecDeque<Vec<u8>>,
    source_done: bool,
    output_stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl JsonSseRedactorReader {
    fn new(
        source: Box<dyn Read + Send>,
        max_line_bytes: usize,
        max_event_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
        output_stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            source,
            core: JsonSseRedactorCore::new(max_line_bytes, max_event_bytes, allowed_fields),
            output: Cursor::new(Vec::new()),
            queued: VecDeque::new(),
            source_done: false,
            output_stats,
        }
    }

    fn enqueue_chunks(&mut self, chunks: Vec<Vec<u8>>) {
        for chunk in chunks {
            update_request_stream_stats(&self.output_stats, &chunk);
            self.queued.push_back(chunk);
        }
    }

    fn fill_output(&mut self) -> io::Result<bool> {
        loop {
            if let Some(chunk) = self.queued.pop_front() {
                self.output = Cursor::new(chunk);
                return Ok(true);
            }
            if self.source_done {
                let chunks = self
                    .core
                    .finish()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                if chunks.is_empty() {
                    return Ok(false);
                }
                self.enqueue_chunks(chunks);
                continue;
            }
            let mut buffer = [0u8; 16 * 1024];
            let read = self.source.read(&mut buffer)?;
            if read == 0 {
                self.source_done = true;
                continue;
            }
            let chunks = self
                .core
                .push(&buffer[..read])
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.enqueue_chunks(chunks);
        }
    }
}

impl Read for JsonSseRedactorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.output.position() < self.output.get_ref().len() as u64 {
                return self.output.read(out);
            }
            if !self.fill_output()? {
                return Ok(0);
            }
        }
    }
}

struct FormUrlencodedRedactorCore {
    pending: Vec<u8>,
    first_output_pair: bool,
    max_pair_bytes: usize,
    allowed_fields: HashSet<String>,
}

impl FormUrlencodedRedactorCore {
    fn new(max_pair_bytes: usize, allowed_fields: Vec<Vec<String>>) -> Self {
        Self {
            pending: Vec::new(),
            first_output_pair: true,
            max_pair_bytes,
            allowed_fields: form_allowed_field_names(&allowed_fields),
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.pending.extend_from_slice(chunk);
        self.process(false)
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, String> {
        self.process(true)
    }

    fn process(&mut self, source_done: bool) -> Result<Vec<Vec<u8>>, String> {
        let mut output = Vec::new();
        loop {
            let Some(separator) = self.pending.iter().position(|byte| *byte == b'&') else {
                break;
            };
            let pair = self.pending.drain(..separator).collect::<Vec<_>>();
            self.pending.drain(..1);
            if let Some(chunk) = self.redact_pair(&pair)? {
                output.push(chunk);
            }
        }
        if self.pending.len() > self.max_pair_bytes {
            return Err("form_urlencoded_pair_too_large".to_string());
        }
        if source_done && !self.pending.is_empty() {
            let pair = std::mem::take(&mut self.pending);
            if let Some(chunk) = self.redact_pair(&pair)? {
                output.push(chunk);
            }
        }
        Ok(output)
    }

    fn redact_pair(&mut self, pair: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if pair.is_empty() {
            return Ok(None);
        }
        if pair.len() > self.max_pair_bytes {
            return Err("form_urlencoded_pair_too_large".to_string());
        }
        let key = form_urlencoded_pair_key(pair);
        if !self.allowed_fields.contains(&key) {
            return Ok(None);
        }
        let mut out = Vec::new();
        if self.first_output_pair {
            self.first_output_pair = false;
        } else {
            out.push(b'&');
        }
        out.extend_from_slice(pair);
        Ok(Some(out))
    }
}

struct FormUrlencodedRedactorReader {
    source: Box<dyn Read + Send>,
    core: FormUrlencodedRedactorCore,
    output: Cursor<Vec<u8>>,
    queued: VecDeque<Vec<u8>>,
    source_done: bool,
    output_stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl FormUrlencodedRedactorReader {
    fn new(
        source: Box<dyn Read + Send>,
        max_pair_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
        output_stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            source,
            core: FormUrlencodedRedactorCore::new(max_pair_bytes, allowed_fields),
            output: Cursor::new(Vec::new()),
            queued: VecDeque::new(),
            source_done: false,
            output_stats,
        }
    }

    fn enqueue_chunks(&mut self, chunks: Vec<Vec<u8>>) {
        for chunk in chunks {
            update_request_stream_stats(&self.output_stats, &chunk);
            self.queued.push_back(chunk);
        }
    }

    fn fill_output(&mut self) -> io::Result<bool> {
        loop {
            if let Some(chunk) = self.queued.pop_front() {
                self.output = Cursor::new(chunk);
                return Ok(true);
            }
            if self.source_done {
                let chunks = self
                    .core
                    .finish()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                if chunks.is_empty() {
                    return Ok(false);
                }
                self.enqueue_chunks(chunks);
                continue;
            }
            let mut buffer = [0u8; 16 * 1024];
            let read = self.source.read(&mut buffer)?;
            if read == 0 {
                self.source_done = true;
                continue;
            }
            let chunks = self
                .core
                .push(&buffer[..read])
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.enqueue_chunks(chunks);
        }
    }
}

impl Read for FormUrlencodedRedactorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.output.position() < self.output.get_ref().len() as u64 {
                return self.output.read(out);
            }
            if !self.fill_output()? {
                return Ok(0);
            }
        }
    }
}

struct StatsLimitReader<R: Read> {
    source: R,
    stats: Arc<Mutex<RequestBodyStreamStats>>,
    max_body_bytes: Option<u64>,
    error_label: &'static str,
}

impl<R: Read> StatsLimitReader<R> {
    fn new(
        source: R,
        stats: Arc<Mutex<RequestBodyStreamStats>>,
        max_body_bytes: Option<u64>,
        error_label: &'static str,
    ) -> Self {
        Self {
            source,
            stats,
            max_body_bytes,
            error_label,
        }
    }
}

impl<R: Read> Read for StatsLimitReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.source.read(out)?;
        if read == 0 {
            return Ok(0);
        }
        let mut stats = self.stats.lock().expect("stream stats mutex poisoned");
        stats.hasher.update(&out[..read]);
        stats.bytes += read as u64;
        if let Some(max_body) = self.max_body_bytes {
            if stats.bytes > max_body {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} exceeded maxBodyBytes {max_body}", self.error_label),
                ));
            }
        }
        Ok(read)
    }
}

struct CsvRedactorReader {
    reader: csv::Reader<Box<dyn Read + Send>>,
    output: Cursor<Vec<u8>>,
    initialized: bool,
    done: bool,
    selected_indexes: Vec<usize>,
    max_record_bytes: usize,
    allowed_fields: HashSet<String>,
    output_stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl CsvRedactorReader {
    fn new(
        source: Box<dyn Read + Send>,
        max_record_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
        output_stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            reader: ReaderBuilder::new()
                .has_headers(true)
                .flexible(false)
                .from_reader(source),
            output: Cursor::new(Vec::new()),
            initialized: false,
            done: false,
            selected_indexes: Vec::new(),
            max_record_bytes,
            allowed_fields: form_allowed_field_names(&allowed_fields),
            output_stats,
        }
    }

    fn initialize(&mut self) -> Result<Vec<u8>, String> {
        let headers = self
            .reader
            .byte_headers()
            .map_err(|err| format!("csv_header_invalid: {err}"))?
            .clone();
        if headers.is_empty() {
            return Err("csv_header_missing".to_string());
        }
        if csv_record_bytes(&headers) > self.max_record_bytes {
            return Err("csv_header_too_large".to_string());
        }
        let mut seen = HashSet::<String>::new();
        for (index, field) in headers.iter().enumerate() {
            let name = std::str::from_utf8(field)
                .map_err(|_| "csv_header_invalid_utf8".to_string())?
                .to_string();
            if !seen.insert(name.clone()) {
                return Err(format!("csv_duplicate_header:{name}"));
            }
            if self.allowed_fields.contains(&name) {
                self.selected_indexes.push(index);
            }
        }
        if self.selected_indexes.is_empty() {
            return Err("csv_allowed_fields_missing_from_header".to_string());
        }
        let selected = csv_select_record(&headers, &self.selected_indexes)?;
        write_csv_record(&selected)
    }

    fn fill_output(&mut self) -> io::Result<bool> {
        if self.done {
            return Ok(false);
        }
        if !self.initialized {
            self.initialized = true;
            let out = self
                .initialize()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            update_request_stream_stats(&self.output_stats, &out);
            self.output = Cursor::new(out);
            return Ok(true);
        }
        let mut record = ByteRecord::new();
        let has_record = self.reader.read_byte_record(&mut record).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("csv_record_invalid: {err}"),
            )
        })?;
        if !has_record {
            self.done = true;
            return Ok(false);
        }
        if csv_record_bytes(&record) > self.max_record_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "csv_record_too_large",
            ));
        }
        let selected = csv_select_record(&record, &self.selected_indexes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let out = write_csv_record(&selected)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        update_request_stream_stats(&self.output_stats, &out);
        self.output = Cursor::new(out);
        Ok(true)
    }
}

impl Read for CsvRedactorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.output.position() < self.output.get_ref().len() as u64 {
                return self.output.read(out);
            }
            if !self.fill_output()? {
                return Ok(0);
            }
        }
    }
}

struct JsonNestedRedactorReader {
    source: Option<Box<dyn Read + Send>>,
    output: Cursor<Vec<u8>>,
    transformed: bool,
    max_nested_bytes: usize,
    allowed_fields: Vec<Vec<String>>,
    output_stats: Arc<Mutex<RequestBodyStreamStats>>,
}

impl JsonNestedRedactorReader {
    fn new(
        source: Box<dyn Read + Send>,
        max_nested_bytes: usize,
        allowed_fields: Vec<Vec<String>>,
        output_stats: Arc<Mutex<RequestBodyStreamStats>>,
    ) -> Self {
        Self {
            source: Some(source),
            output: Cursor::new(Vec::new()),
            transformed: false,
            max_nested_bytes,
            allowed_fields,
            output_stats,
        }
    }

    fn fill_output(&mut self) -> io::Result<bool> {
        if self.transformed {
            return Ok(false);
        }
        self.transformed = true;
        let Some(mut source) = self.source.take() else {
            return Ok(false);
        };
        let mut output = Vec::new();
        redact_json_nested_to_writer(
            &mut source,
            &mut output,
            &self.allowed_fields,
            self.max_nested_bytes,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        update_request_stream_stats(&self.output_stats, &output);
        self.output = Cursor::new(output);
        Ok(true)
    }
}

impl Read for JsonNestedRedactorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.output.position() < self.output.get_ref().len() as u64 {
                return self.output.read(out);
            }
            if !self.fill_output()? {
                return Ok(0);
            }
        }
    }
}

fn filter_gmail_message_fields(message: &Value, paths: &[Vec<String>]) -> Value {
    let mut filtered = match redact_json_value(message, paths) {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    if let Some(proof) = message.get("serverwareAgeProof") {
        filtered.insert("serverwareAgeProof".to_string(), proof.clone());
    }
    Value::Object(filtered)
}

fn apply_gmail_allowed_fields(payload: &mut Value, response_config: &Value, is_list: bool) -> bool {
    let paths = allowed_field_paths(response_config);
    if paths.is_empty() {
        return false;
    }
    if is_list {
        let messages = payload
            .get("messages")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        if item.is_object() {
                            filter_gmail_message_fields(item, &paths)
                        } else {
                            item.clone()
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut filtered = Map::new();
        filtered.insert("messages".to_string(), Value::Array(messages));
        if let Some(pending) = payload.get("serverwarePendingAgeProof") {
            filtered.insert("serverwarePendingAgeProof".to_string(), pending.clone());
        }
        *payload = Value::Object(filtered);
        true
    } else {
        *payload = filter_gmail_message_fields(payload, &paths);
        true
    }
}

fn response_violation(payload: Value) -> Vec<u8> {
    json_status_response(StatusCode::BAD_GATEWAY, payload)
}

fn release_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    content_type: Option<&str>,
    body: Vec<u8>,
    validation: Value,
) -> Vec<u8> {
    enqueue_audit(
        state,
        "data_plane.response.released",
        decision_audit_event(
            decision,
            method,
            url,
            "released",
            json!({
                "upstream_status":status.as_u16(),
                "response_body_sha256":sha256_prefixed(&body),
                "response_body_bytes":body.len(),
                "response_validation":validation,
            }),
        ),
    );
    let response_body_sha256 = sha256_prefixed(&body);
    http_binary_response_with_headers(
        status,
        content_type,
        body,
        &[
            (
                "X-Serverware-Policy-Hash",
                decision
                    .get("policy_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ),
            (
                "X-Serverware-Request-Digest",
                decision
                    .get("request_digest")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ),
            (
                "X-Serverware-Operation-Digest",
                decision
                    .get("operation_digest")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ),
            ("X-Serverware-Response-Body-SHA256", response_body_sha256),
        ],
    )
}

fn block_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    payload: Value,
) -> Vec<u8> {
    enqueue_audit(
        state,
        "data_plane.response.blocked",
        decision_audit_event(
            decision,
            method,
            url,
            "blocked",
            json!({
                "upstream_status":status.as_u16(),
                "response_validation":{"ok":false,"error":payload.get("error").cloned().unwrap_or(Value::Null)},
                "payload":payload.clone(),
            }),
        ),
    );
    response_violation(payload)
}

fn response_policy_for_decision(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
) -> Option<ResponsePolicy> {
    let principal_id = decision.get("principal_id").and_then(Value::as_str)?;
    let route_id = decision.get("route_id").and_then(Value::as_str)?;
    let snapshot = current_snapshot(state);
    let route_match = snapshot.match_route(principal_id, method, url)?;
    if route_match.route.id != route_id {
        return None;
    }
    Some(ResponsePolicy {
        adapter_type: route_match.route.adapter_type.clone(),
        response_config: route_match
            .route
            .adapter_config
            .get("response")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

fn streaming_response_policy(policy: &ResponsePolicy) -> Option<StreamingResponsePolicy> {
    let mode = policy
        .response_config
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("any");
    if policy.adapter_type == "gmail.v1" {
        return None;
    }
    let allowed_fields = allowed_field_paths(&policy.response_config);
    if mode == "stream" {
        if !allowed_fields.is_empty() {
            return None;
        }
    } else if mode == "jsonlStream"
        || mode == "jsonArrayStream"
        || mode == "jsonSseStream"
        || mode == "jsonNestedStream"
        || mode == "formUrlencodedStream"
        || mode == "csvStream"
    {
        if policy.adapter_type != "generic.rest" || allowed_fields.is_empty() {
            return None;
        }
    } else {
        return None;
    }
    Some(StreamingResponsePolicy {
        adapter_type: policy.adapter_type.clone(),
        mode: mode.to_string(),
        max_body_bytes: policy
            .response_config
            .get("maxBodyBytes")
            .and_then(Value::as_u64),
        max_line_bytes: json_lines_max_line_bytes(&policy.response_config),
        max_item_bytes: json_array_max_item_bytes(&policy.response_config),
        max_event_bytes: json_sse_max_event_bytes(&policy.response_config),
        max_pair_bytes: form_urlencoded_max_pair_bytes(&policy.response_config),
        max_record_bytes: csv_max_record_bytes(&policy.response_config),
        max_nested_bytes: json_nested_max_nested_bytes(&policy.response_config),
        allowed_fields,
    })
}

fn response_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn release_streamed_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    body_sha256: String,
    body_bytes: u64,
    validation: Value,
) {
    enqueue_audit(
        state,
        "data_plane.response.released",
        decision_audit_event(
            decision,
            method,
            url,
            "released",
            json!({
                "upstream_status":status.as_u16(),
                "response_body_sha256":body_sha256,
                "response_body_bytes":body_bytes,
                "response_validation":validation,
            }),
        ),
    );
}

fn write_chunked_bytes(writer: &mut dyn Write, body: &[u8]) -> Result<(), String> {
    if body.is_empty() {
        return Ok(());
    }
    writer
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .map_err(|err| format!("write chunk header: {err}"))?;
    writer
        .write_all(body)
        .map_err(|err| format!("write chunk body: {err}"))?;
    writer
        .write_all(b"\r\n")
        .map_err(|err| format!("write chunk trailer: {err}"))?;
    Ok(())
}

struct HashingLimitResponseReader {
    response: reqwest::blocking::Response,
    hasher: Sha256,
    body_bytes: u64,
    max_body_bytes: Option<u64>,
}

impl HashingLimitResponseReader {
    fn new(response: reqwest::blocking::Response, max_body_bytes: Option<u64>) -> Self {
        Self {
            response,
            hasher: Sha256::new(),
            body_bytes: 0,
            max_body_bytes,
        }
    }

    fn sha256(&self) -> String {
        format!("sha256:{}", hex::encode(self.hasher.clone().finalize()))
    }
}

impl Read for HashingLimitResponseReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.response.read(out)?;
        if read == 0 {
            return Ok(0);
        }
        self.body_bytes = self.body_bytes.saturating_add(read as u64);
        if let Some(max_body) = self.max_body_bytes {
            if self.body_bytes > max_body {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("json nested response exceeded maxBodyBytes {max_body}"),
                ));
            }
        }
        self.hasher.update(&out[..read]);
        Ok(read)
    }
}

struct ChunkedHashWriter<'a> {
    writer: &'a mut dyn Write,
    hasher: Sha256,
    body_bytes: u64,
    pending: Vec<u8>,
}

impl<'a> ChunkedHashWriter<'a> {
    fn new(writer: &'a mut dyn Write) -> Self {
        Self {
            writer,
            hasher: Sha256::new(),
            body_bytes: 0,
            pending: Vec::with_capacity(16 * 1024),
        }
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.writer
            .write_all(format!("{:x}\r\n", self.pending.len()).as_bytes())?;
        self.writer.write_all(&self.pending)?;
        self.writer.write_all(b"\r\n")?;
        self.hasher.update(&self.pending);
        self.body_bytes = self.body_bytes.saturating_add(self.pending.len() as u64);
        self.pending.clear();
        Ok(())
    }

    fn finish(mut self) -> Result<(String, u64), String> {
        self.flush_pending()
            .map_err(|err| format!("write json nested chunk: {err}"))?;
        self.writer
            .write_all(b"0\r\n\r\n")
            .map_err(|err| format!("write final chunk: {err}"))?;
        self.writer
            .flush()
            .map_err(|err| format!("flush json nested stream: {err}"))?;
        Ok((
            format!("sha256:{}", hex::encode(self.hasher.finalize())),
            self.body_bytes,
        ))
    }
}

impl Write for ChunkedHashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        if self.pending.len() >= 16 * 1024 {
            self.flush_pending()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()
    }
}

fn stream_json_nested_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    write_stream_response_headers(writer, status, Some("application/json"), None, keep_alive)?;
    let mut raw_reader = HashingLimitResponseReader::new(response, policy.max_body_bytes);
    let mut chunk_writer = ChunkedHashWriter::new(writer);
    redact_json_nested_to_writer(
        &mut raw_reader,
        &mut chunk_writer,
        &policy.allowed_fields,
        policy.max_nested_bytes,
    )
    .map_err(|err| format!("json_nested_response_redaction_failed: {err}"))?;
    let raw_body_sha256 = raw_reader.sha256();
    let raw_body_bytes = raw_reader.body_bytes;
    let (body_sha256, body_bytes) = chunk_writer.finish()?;
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        body_sha256,
        body_bytes,
        json!({
            "ok":true,
            "mode":"jsonNestedStream",
            "adapter":policy.adapter_type.clone(),
            "streamed":true,
            "allowed_fields_redacted":true,
            "raw_response_body_sha256":raw_body_sha256,
            "raw_response_body_bytes":raw_body_bytes,
        }),
    );
    Ok(())
}

fn stream_json_lines_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    mut response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    write_stream_response_headers(
        writer,
        status,
        Some("application/x-ndjson"),
        None,
        keep_alive,
    )?;
    let mut raw_hasher = Sha256::new();
    let mut out_hasher = Sha256::new();
    let mut raw_body_bytes = 0u64;
    let mut out_body_bytes = 0u64;
    let mut pending = Vec::<u8>::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| format!("read upstream json lines stream: {err}"))?;
        if read == 0 {
            break;
        }
        raw_body_bytes += read as u64;
        if let Some(max_body) = policy.max_body_bytes {
            if raw_body_bytes > max_body {
                return Err(format!(
                    "json lines response exceeded maxBodyBytes {max_body}"
                ));
            }
        }
        raw_hasher.update(&buffer[..read]);
        pending.extend_from_slice(&buffer[..read]);
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=newline).collect::<Vec<_>>();
            if line.len() > policy.max_line_bytes {
                return Err("json_lines_response_line_too_large".to_string());
            }
            let out = redact_json_line(&line, &policy.allowed_fields)
                .map_err(|err| format!("json_lines_response_redaction_failed: {err}"))?;
            out_body_bytes += out.len() as u64;
            out_hasher.update(&out);
            write_chunked_bytes(writer, &out)?;
        }
        if pending.len() > policy.max_line_bytes {
            return Err("json_lines_response_line_too_large".to_string());
        }
    }
    if !pending.is_empty() {
        if pending.len() > policy.max_line_bytes {
            return Err("json_lines_response_line_too_large".to_string());
        }
        let line = std::mem::take(&mut pending);
        let out = redact_json_line(&line, &policy.allowed_fields)
            .map_err(|err| format!("json_lines_response_redaction_failed: {err}"))?;
        out_body_bytes += out.len() as u64;
        out_hasher.update(&out);
        write_chunked_bytes(writer, &out)?;
    }
    writer
        .write_all(b"0\r\n\r\n")
        .map_err(|err| format!("write final chunk: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("flush json lines stream: {err}"))?;
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        format!("sha256:{}", hex::encode(out_hasher.finalize())),
        out_body_bytes,
        json!({
            "ok":true,
            "mode":"jsonlStream",
            "adapter":policy.adapter_type.clone(),
            "streamed":true,
            "allowed_fields_redacted":true,
            "raw_response_body_sha256":format!("sha256:{}", hex::encode(raw_hasher.finalize())),
            "raw_response_body_bytes":raw_body_bytes,
        }),
    );
    Ok(())
}

fn stream_json_array_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    mut response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    write_stream_response_headers(writer, status, Some("application/json"), None, keep_alive)?;
    let mut raw_hasher = Sha256::new();
    let mut out_hasher = Sha256::new();
    let mut raw_body_bytes = 0u64;
    let mut out_body_bytes = 0u64;
    let mut core = JsonArrayRedactorCore::new(policy.max_item_bytes, policy.allowed_fields.clone());
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| format!("read upstream json array stream: {err}"))?;
        if read == 0 {
            break;
        }
        raw_body_bytes += read as u64;
        if let Some(max_body) = policy.max_body_bytes {
            if raw_body_bytes > max_body {
                return Err(format!(
                    "json array response exceeded maxBodyBytes {max_body}"
                ));
            }
        }
        raw_hasher.update(&buffer[..read]);
        let chunks = core
            .push(&buffer[..read])
            .map_err(|err| format!("json_array_response_redaction_failed: {err}"))?;
        for chunk in chunks {
            out_body_bytes += chunk.len() as u64;
            out_hasher.update(&chunk);
            write_chunked_bytes(writer, &chunk)?;
        }
    }
    let chunks = core
        .finish()
        .map_err(|err| format!("json_array_response_redaction_failed: {err}"))?;
    for chunk in chunks {
        out_body_bytes += chunk.len() as u64;
        out_hasher.update(&chunk);
        write_chunked_bytes(writer, &chunk)?;
    }
    writer
        .write_all(b"0\r\n\r\n")
        .map_err(|err| format!("write final chunk: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("flush json array stream: {err}"))?;
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        format!("sha256:{}", hex::encode(out_hasher.finalize())),
        out_body_bytes,
        json!({
            "ok":true,
            "mode":"jsonArrayStream",
            "adapter":policy.adapter_type.clone(),
            "streamed":true,
            "allowed_fields_redacted":true,
            "raw_response_body_sha256":format!("sha256:{}", hex::encode(raw_hasher.finalize())),
            "raw_response_body_bytes":raw_body_bytes,
        }),
    );
    Ok(())
}

fn stream_json_sse_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    mut response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    write_stream_response_headers(writer, status, Some("text/event-stream"), None, keep_alive)?;
    let mut raw_hasher = Sha256::new();
    let mut out_hasher = Sha256::new();
    let mut raw_body_bytes = 0u64;
    let mut out_body_bytes = 0u64;
    let mut core = JsonSseRedactorCore::new(
        policy.max_line_bytes,
        policy.max_event_bytes,
        policy.allowed_fields.clone(),
    );
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| format!("read upstream json sse stream: {err}"))?;
        if read == 0 {
            break;
        }
        raw_body_bytes += read as u64;
        if let Some(max_body) = policy.max_body_bytes {
            if raw_body_bytes > max_body {
                return Err(format!(
                    "json sse response exceeded maxBodyBytes {max_body}"
                ));
            }
        }
        raw_hasher.update(&buffer[..read]);
        let chunks = core
            .push(&buffer[..read])
            .map_err(|err| format!("json_sse_response_redaction_failed: {err}"))?;
        for chunk in chunks {
            out_body_bytes += chunk.len() as u64;
            out_hasher.update(&chunk);
            write_chunked_bytes(writer, &chunk)?;
        }
    }
    let chunks = core
        .finish()
        .map_err(|err| format!("json_sse_response_redaction_failed: {err}"))?;
    for chunk in chunks {
        out_body_bytes += chunk.len() as u64;
        out_hasher.update(&chunk);
        write_chunked_bytes(writer, &chunk)?;
    }
    writer
        .write_all(b"0\r\n\r\n")
        .map_err(|err| format!("write final chunk: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("flush json sse stream: {err}"))?;
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        format!("sha256:{}", hex::encode(out_hasher.finalize())),
        out_body_bytes,
        json!({
            "ok":true,
            "mode":"jsonSseStream",
            "adapter":policy.adapter_type.clone(),
            "streamed":true,
            "allowed_fields_redacted":true,
            "sse_metadata_forwarded":false,
            "raw_response_body_sha256":format!("sha256:{}", hex::encode(raw_hasher.finalize())),
            "raw_response_body_bytes":raw_body_bytes,
        }),
    );
    Ok(())
}

fn stream_form_urlencoded_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    mut response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    write_stream_response_headers(
        writer,
        status,
        Some("application/x-www-form-urlencoded"),
        None,
        keep_alive,
    )?;
    let mut raw_hasher = Sha256::new();
    let mut out_hasher = Sha256::new();
    let mut raw_body_bytes = 0u64;
    let mut out_body_bytes = 0u64;
    let mut core =
        FormUrlencodedRedactorCore::new(policy.max_pair_bytes, policy.allowed_fields.clone());
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| format!("read upstream form-url-encoded stream: {err}"))?;
        if read == 0 {
            break;
        }
        raw_body_bytes += read as u64;
        if let Some(max_body) = policy.max_body_bytes {
            if raw_body_bytes > max_body {
                return Err(format!(
                    "form urlencoded response exceeded maxBodyBytes {max_body}"
                ));
            }
        }
        raw_hasher.update(&buffer[..read]);
        let chunks = core
            .push(&buffer[..read])
            .map_err(|err| format!("form_urlencoded_response_redaction_failed: {err}"))?;
        for chunk in chunks {
            out_body_bytes += chunk.len() as u64;
            out_hasher.update(&chunk);
            write_chunked_bytes(writer, &chunk)?;
        }
    }
    let chunks = core
        .finish()
        .map_err(|err| format!("form_urlencoded_response_redaction_failed: {err}"))?;
    for chunk in chunks {
        out_body_bytes += chunk.len() as u64;
        out_hasher.update(&chunk);
        write_chunked_bytes(writer, &chunk)?;
    }
    writer
        .write_all(b"0\r\n\r\n")
        .map_err(|err| format!("write final chunk: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("flush form-url-encoded stream: {err}"))?;
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        format!("sha256:{}", hex::encode(out_hasher.finalize())),
        out_body_bytes,
        json!({
            "ok":true,
            "mode":"formUrlencodedStream",
            "adapter":policy.adapter_type.clone(),
            "streamed":true,
            "allowed_fields_redacted":true,
            "raw_response_body_sha256":format!("sha256:{}", hex::encode(raw_hasher.finalize())),
            "raw_response_body_bytes":raw_body_bytes,
        }),
    );
    Ok(())
}

fn stream_csv_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    write_stream_response_headers(writer, status, Some("text/csv"), None, keep_alive)?;
    let raw_stats = Arc::new(Mutex::new(RequestBodyStreamStats::new()));
    let output_stats = Arc::new(Mutex::new(RequestBodyStreamStats::new()));
    let raw_reader = StatsLimitReader::new(
        response,
        raw_stats.clone(),
        policy.max_body_bytes,
        "csv response",
    );
    let mut reader = CsvRedactorReader::new(
        Box::new(raw_reader),
        policy.max_record_bytes,
        policy.allowed_fields.clone(),
        output_stats.clone(),
    );
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| format!("csv_response_redaction_failed: {err}"))?;
        if read == 0 {
            break;
        }
        write_chunked_bytes(writer, &buffer[..read])?;
    }
    writer
        .write_all(b"0\r\n\r\n")
        .map_err(|err| format!("write final chunk: {err}"))?;
    writer
        .flush()
        .map_err(|err| format!("flush csv stream: {err}"))?;
    let (raw_body_sha256, raw_body_bytes) = request_stream_stats_snapshot(&raw_stats);
    let (body_sha256, body_bytes) = request_stream_stats_snapshot(&output_stats);
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        body_sha256,
        body_bytes,
        json!({
            "ok":true,
            "mode":"csvStream",
            "adapter":policy.adapter_type.clone(),
            "streamed":true,
            "allowed_fields_redacted":true,
            "raw_response_body_sha256":raw_body_sha256,
            "raw_response_body_bytes":raw_body_bytes,
        }),
    );
    Ok(())
}

fn stream_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    content_type: Option<&str>,
    content_length: Option<u64>,
    mut response: reqwest::blocking::Response,
    writer: &mut dyn Write,
    keep_alive: bool,
    policy: &StreamingResponsePolicy,
) -> Result<(), String> {
    if policy.mode == "jsonlStream" {
        return stream_json_lines_forward_response(
            state, decision, method, url, status, response, writer, keep_alive, policy,
        );
    }
    if policy.mode == "jsonArrayStream" {
        return stream_json_array_forward_response(
            state, decision, method, url, status, response, writer, keep_alive, policy,
        );
    }
    if policy.mode == "jsonSseStream" {
        return stream_json_sse_forward_response(
            state, decision, method, url, status, response, writer, keep_alive, policy,
        );
    }
    if policy.mode == "jsonNestedStream" {
        return stream_json_nested_forward_response(
            state, decision, method, url, status, response, writer, keep_alive, policy,
        );
    }
    if policy.mode == "formUrlencodedStream" {
        return stream_form_urlencoded_forward_response(
            state, decision, method, url, status, response, writer, keep_alive, policy,
        );
    }
    if policy.mode == "csvStream" {
        return stream_csv_forward_response(
            state, decision, method, url, status, response, writer, keep_alive, policy,
        );
    }
    let chunked =
        write_stream_response_headers(writer, status, content_type, content_length, keep_alive)?;
    let mut hasher = Sha256::new();
    let mut body_bytes = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| format!("read upstream stream: {err}"))?;
        if read == 0 {
            break;
        }
        body_bytes += read as u64;
        if let Some(max_body) = policy.max_body_bytes {
            if body_bytes > max_body {
                return Err(format!(
                    "streamed response exceeded maxBodyBytes {max_body}"
                ));
            }
        }
        hasher.update(&buffer[..read]);
        if chunked {
            writer
                .write_all(format!("{read:x}\r\n").as_bytes())
                .map_err(|err| format!("write chunk header: {err}"))?;
            writer
                .write_all(&buffer[..read])
                .map_err(|err| format!("write chunk body: {err}"))?;
            writer
                .write_all(b"\r\n")
                .map_err(|err| format!("write chunk trailer: {err}"))?;
        } else {
            writer
                .write_all(&buffer[..read])
                .map_err(|err| format!("write streamed body: {err}"))?;
        }
    }
    if chunked {
        writer
            .write_all(b"0\r\n\r\n")
            .map_err(|err| format!("write final chunk: {err}"))?;
    }
    writer
        .flush()
        .map_err(|err| format!("flush streamed response: {err}"))?;
    release_streamed_forward_response(
        state,
        decision,
        method,
        url,
        status,
        format!("sha256:{}", hex::encode(hasher.finalize())),
        body_bytes,
        json!({"ok":true,"mode":"stream","adapter":policy.adapter_type.clone(),"streamed":true}),
    );
    Ok(())
}

fn validate_policy_json_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    content_type: Option<&str>,
    body: Vec<u8>,
    response_config: &Value,
    adapter_type: &str,
) -> Vec<u8> {
    let mode = response_config
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("any");
    if mode == "headersOnly" {
        return release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            None,
            Vec::new(),
            json!({"ok":true,"mode":"headers_only","body_redacted":true,"adapter":adapter_type}),
        );
    }
    let paths = allowed_field_paths(response_config);
    let requires_json = mode == "json" || !paths.is_empty();
    if !requires_json {
        return release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            content_type,
            body,
            json!({"ok":true,"mode":"adapter_passthrough","adapter":adapter_type}),
        );
    }
    let mut payload = match serde_json::from_slice::<Value>(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return block_forward_response(
                state,
                decision,
                method,
                url,
                status,
                json!({"error":"response_invalid_json","adapter":adapter_type}),
            )
        }
    };
    let redacted = !paths.is_empty();
    if redacted {
        payload = redact_json_value(&payload, &paths);
    }
    match serde_json::to_vec(&payload) {
        Ok(bytes) => release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            Some("application/json"),
            bytes,
            json!({"ok":true,"mode":"json","allowed_fields_redacted":redacted,"adapter":adapter_type}),
        ),
        Err(_) => block_forward_response(
            state,
            decision,
            method,
            url,
            status,
            json!({"error":"response_serialization_failed","adapter":adapter_type}),
        ),
    }
}

fn validate_forward_response(
    state: &GateState,
    decision: &Value,
    method: &str,
    url: &Url,
    status: StatusCode,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Vec<u8> {
    let Some(principal_id) = decision.get("principal_id").and_then(Value::as_str) else {
        return release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            content_type,
            body,
            json!({"ok":true,"mode":"decision_context_missing"}),
        );
    };
    let Some(route_id) = decision.get("route_id").and_then(Value::as_str) else {
        return release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            content_type,
            body,
            json!({"ok":true,"mode":"decision_context_missing"}),
        );
    };
    let snapshot = current_snapshot(state);
    let Some(route_match) = snapshot.match_route(principal_id, method, url) else {
        return block_forward_response(
            state,
            decision,
            method,
            url,
            status,
            json!({"error":"response_route_context_missing"}),
        );
    };
    if route_match.route.id != route_id {
        return block_forward_response(
            state,
            decision,
            method,
            url,
            status,
            json!({"error":"response_route_context_mismatch"}),
        );
    }
    let response_config = route_match
        .route
        .adapter_config
        .get("response")
        .unwrap_or(&Value::Null);
    if let Some(max_body) = response_config.get("maxBodyBytes").and_then(Value::as_u64) {
        if body.len() as u64 > max_body {
            return block_forward_response(
                state,
                decision,
                method,
                url,
                status,
                json!({"error":"response_body_too_large","maxBodyBytes":max_body}),
            );
        }
    }
    if status.as_u16() < 400 {
        if let Err(payload) = validate_response_constraints(route_match.route, &body) {
            return block_forward_response(state, decision, method, url, status, payload);
        }
    }
    if route_match.route.adapter_type != "gmail.v1" {
        return validate_policy_json_response(
            state,
            decision,
            method,
            url,
            status,
            content_type,
            body,
            response_config,
            &route_match.route.adapter_type,
        );
    }
    if status.as_u16() >= 400 {
        return release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            content_type,
            body,
            json!({"ok":true,"mode":"adapter_passthrough","adapter":"gmail.v1"}),
        );
    }
    let validate_internal_date = response_config
        .get("validateInternalDate")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let has_allowed_fields = response_config
        .get("allowedFields")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    if !validate_internal_date && !has_allowed_fields {
        return release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            content_type,
            body,
            json!({"ok":true,"mode":"validation_disabled"}),
        );
    }
    let mut payload = match serde_json::from_slice::<Value>(&body) {
        Ok(payload) => payload,
        Err(_) => {
            return block_forward_response(
                state,
                decision,
                method,
                url,
                status,
                json!({"error":"gmail_response_invalid_json"}),
            )
        }
    };
    let days = config_u64(&route_match.route.adapter_config, "maxAgeDays", 30);
    let is_list_response = !route_match.params.contains_key("message_id");
    let mut validated_message_ids = Vec::new();
    if validate_internal_date {
        if !is_list_response {
            if let Err(payload) = validate_gmail_internal_date(&payload, days) {
                return block_forward_response(state, decision, method, url, status, payload);
            }
        } else {
            let validate_missing_by_metadata = response_config
                .get("validateListByMetadataFetch")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut pending = Vec::new();
            if let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) {
                for item in messages {
                    let Some(object) = item.as_object_mut() else {
                        continue;
                    };
                    let Some(id) = object.get("id").and_then(Value::as_str).map(str::to_string)
                    else {
                        continue;
                    };
                    if object.get("internalDate").is_none() && validate_missing_by_metadata {
                        object.insert(
                            "serverwareAgeProof".to_string(),
                            Value::String("pending".to_string()),
                        );
                        pending.push(Value::String(id));
                        continue;
                    }
                    if let Err(payload) =
                        validate_gmail_internal_date_value(object.get("internalDate"), days)
                    {
                        return block_forward_response(
                            state, decision, method, url, status, payload,
                        );
                    }
                    object.insert(
                        "serverwareAgeProof".to_string(),
                        Value::String("validated".to_string()),
                    );
                    validated_message_ids.push(id);
                }
            }
            if !pending.is_empty() {
                if let Some(object) = payload.as_object_mut() {
                    object.insert(
                        "serverwarePendingAgeProof".to_string(),
                        Value::Array(pending),
                    );
                }
            }
        }
    }
    if is_list_response {
        remember_gmail_proofs(
            state,
            principal_id,
            route_id,
            route_match.route,
            validated_message_ids,
        );
    }
    let redacted = apply_gmail_allowed_fields(&mut payload, response_config, is_list_response);
    match serde_json::to_vec(&payload) {
        Ok(bytes) => release_forward_response(
            state,
            decision,
            method,
            url,
            status,
            Some("application/json"),
            bytes,
            json!({"ok":true,"mode":"gmail_internal_date","allowed_fields_redacted":redacted}),
        ),
        Err(_) => block_forward_response(
            state,
            decision,
            method,
            url,
            status,
            json!({"error":"gmail_response_serialization_failed"}),
        ),
    }
}

fn finalize_upstream_response(
    state: &GateState,
    decision: &Value,
    request_method: &str,
    upstream_url: &Url,
    response: reqwest::blocking::Response,
    stream_writer: Option<&mut dyn Write>,
    keep_alive: bool,
) -> ForwardResult {
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let content_length = response_content_length(response.headers());
    let stream_policy = response_policy_for_decision(state, decision, request_method, upstream_url)
        .as_ref()
        .and_then(streaming_response_policy);
    if let Some(policy) = stream_policy {
        if let Some(max_body) = policy.max_body_bytes {
            match content_length {
                Some(length) if length > max_body => {
                    return ForwardResult::Buffered(block_forward_response(
                        state,
                        decision,
                        request_method,
                        upstream_url,
                        status,
                        json!({"error":"response_body_too_large","maxBodyBytes":max_body,"contentLength":length}),
                    ));
                }
                None if policy.mode == "stream" => {
                    return ForwardResult::Buffered(block_forward_response(
                        state,
                        decision,
                        request_method,
                        upstream_url,
                        status,
                        json!({"error":"streaming_response_requires_content_length","maxBodyBytes":max_body}),
                    ));
                }
                _ => {}
            }
        }
        if let Some(writer) = stream_writer {
            match stream_forward_response(
                state,
                decision,
                request_method,
                upstream_url,
                status,
                content_type.as_deref(),
                content_length,
                response,
                writer,
                keep_alive,
                &policy,
            ) {
                Ok(()) => return ForwardResult::Streamed,
                Err(err) => {
                    enqueue_audit(
                        state,
                        "data_plane.response.blocked",
                        decision_audit_event(
                            decision,
                            request_method,
                            upstream_url,
                            "blocked",
                            json!({"stage":"stream_response","error":"stream_response_failed","detail":err}),
                        ),
                    );
                    return ForwardResult::Streamed;
                }
            }
        }
    }
    match response.bytes() {
        Ok(bytes) => ForwardResult::Buffered(validate_forward_response(
            state,
            decision,
            request_method,
            upstream_url,
            status,
            content_type.as_deref(),
            bytes.to_vec(),
        )),
        Err(err) => {
            enqueue_audit(
                state,
                "data_plane.response.blocked",
                decision_audit_event(
                    decision,
                    request_method,
                    upstream_url,
                    "blocked",
                    json!({"stage":"upstream_body","error":"upstream_body_failed","detail":err.to_string()}),
                ),
            );
            ForwardResult::Buffered(json_status_response(
                StatusCode::BAD_GATEWAY,
                json!({"error":"upstream_body_failed","detail":err.to_string()}),
            ))
        }
    }
}

fn forward_absolute_request_inner(
    state: &GateState,
    request: IncomingRequest,
    authenticated_principal_id: Option<&str>,
    stream_writer: Option<&mut dyn Write>,
    keep_alive: bool,
) -> ForwardResult {
    macro_rules! buffered {
        ($response:expr) => {
            return ForwardResult::Buffered($response)
        };
    }

    let target_url = match Url::parse(&request.target) {
        Ok(url) if url.scheme() == "https" || url.scheme() == "http" => url,
        Ok(_) => {
            buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"unsupported_forward_scheme"}),
            ))
        }
        Err(err) => {
            buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_forward_url","detail":err.to_string()}),
            ))
        }
    };
    let decision_request = DecisionRequest {
        client_ip: request.client_ip.clone(),
        method: request.method.clone(),
        url: request.target.clone(),
        headers: request.headers.clone(),
        body: String::from_utf8_lossy(&request.body).to_string(),
        body_sha256: Some(body_sha_bytes(&request.body)),
        credential_metadata: BTreeMap::new(),
        gmail_proofs: Vec::new(),
    };
    let decision = decide_internal(state, decision_request, authenticated_principal_id);
    if !decision
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        enqueue_audit(
            state,
            "data_plane.request.denied",
            decision_audit_event(
                &decision,
                &request.method,
                &target_url,
                "denied",
                json!({"stage":"policy_decision"}),
            ),
        );
        buffered!(json_status_response(
            status_from_decision(&decision),
            decision
        ));
    }
    let mut upstream_url = target_url;
    apply_rewrite(
        &mut upstream_url,
        decision.get("rewrite").unwrap_or(&Value::Null),
    );
    let mut headers = filtered_forward_headers(&request.headers);
    if let Some(credential_ref) = decision.get("credential_ref").and_then(Value::as_str) {
        let credential_version = decision
            .get("credential_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let Some(lease) = credential_lease(state, credential_ref, credential_version) else {
            enqueue_audit(
                state,
                "data_plane.request.denied",
                decision_audit_event(
                    &decision,
                    &request.method,
                    &upstream_url,
                    "denied",
                    json!({
                        "stage":"credential_lease",
                        "error":"credential_lease_missing",
                        "credential_ref":credential_ref,
                        "credential_version":credential_version,
                    }),
                ),
            );
            buffered!(json_status_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error":"credential_lease_missing",
                    "credential_ref":credential_ref,
                    "credential_version":credential_version,
                }),
            ));
        };
        if let Err(err) = apply_credential_injection(
            &mut headers,
            &mut upstream_url,
            decision
                .get("injection")
                .and_then(|value| value.get("plan"))
                .unwrap_or(&Value::Null),
            &lease,
        ) {
            enqueue_audit(
                state,
                "data_plane.request.denied",
                decision_audit_event(
                    &decision,
                    &request.method,
                    &upstream_url,
                    "denied",
                    json!({"stage":"credential_injection","error":"credential_injection_failed","detail":err.clone()}),
                ),
            );
            buffered!(json_status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"credential_injection_failed","detail":err}),
            ));
        }
    }
    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_method","detail":err.to_string()}),
            ))
        }
    };
    let request_method = request.method.clone();
    let mut builder = state
        .upstream_client
        .request(method, upstream_url.as_str())
        .headers(headers);
    if !request.body.is_empty() {
        builder = builder.body(request.body);
    }
    let response = match builder.send() {
        Ok(response) => response,
        Err(err) => {
            enqueue_audit(
                state,
                "data_plane.response.blocked",
                decision_audit_event(
                    &decision,
                    &request_method,
                    &upstream_url,
                    "blocked",
                    json!({"stage":"upstream_request","error":"upstream_request_failed","detail":error_chain(&err)}),
                ),
            );
            buffered!(json_status_response(
                StatusCode::BAD_GATEWAY,
                json!({"error":"upstream_request_failed","detail":error_chain(&err)}),
            ));
        }
    };
    finalize_upstream_response(
        state,
        &decision,
        &request_method,
        &upstream_url,
        response,
        stream_writer,
        keep_alive,
    )
}

fn forward_absolute_streaming_request_to(
    state: &GateState,
    request: RequestHead,
    body_stream: RequestBodyStream,
    stats: Arc<Mutex<RequestBodyStreamStats>>,
    request_policy: StreamingRequestPolicy,
    authenticated_principal_id: Option<&str>,
    keep_alive: bool,
    writer: &mut dyn Write,
) -> bool {
    macro_rules! write_buffered {
        ($response:expr) => {{
            let response = override_response_connection($response, keep_alive);
            return writer.write_all(&response).is_ok() && writer.flush().is_ok();
        }};
    }

    let target_url = match Url::parse(&request.target) {
        Ok(url) if url.scheme() == "https" || url.scheme() == "http" => url,
        Ok(_) => {
            write_buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"unsupported_forward_scheme"}),
            ))
        }
        Err(err) => {
            write_buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_forward_url","detail":err.to_string()}),
            ))
        }
    };
    let decision_request = DecisionRequest {
        client_ip: request.client_ip.clone(),
        method: request.method.clone(),
        url: request.target.clone(),
        headers: request.headers.clone(),
        body: String::new(),
        body_sha256: Some(sha256_prefixed(b"")),
        credential_metadata: BTreeMap::new(),
        gmail_proofs: Vec::new(),
    };
    let decision = decide_internal(state, decision_request, authenticated_principal_id);
    if !decision
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        enqueue_audit(
            state,
            "data_plane.request.denied",
            decision_audit_event(
                &decision,
                &request.method,
                &target_url,
                "denied",
                json!({"stage":"policy_decision","request_body_mode":request_policy.mode}),
            ),
        );
        write_buffered!(json_status_response(
            status_from_decision(&decision),
            decision
        ));
    }
    let mut upstream_url = target_url;
    apply_rewrite(
        &mut upstream_url,
        decision.get("rewrite").unwrap_or(&Value::Null),
    );
    let mut headers = filtered_forward_headers(&request.headers);
    if let Some(credential_ref) = decision.get("credential_ref").and_then(Value::as_str) {
        let credential_version = decision
            .get("credential_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let Some(lease) = credential_lease(state, credential_ref, credential_version) else {
            enqueue_audit(
                state,
                "data_plane.request.denied",
                decision_audit_event(
                    &decision,
                    &request.method,
                    &upstream_url,
                    "denied",
                    json!({
                        "stage":"credential_lease",
                        "error":"credential_lease_missing",
                        "credential_ref":credential_ref,
                        "credential_version":credential_version,
                        "request_body_mode":request_policy.mode,
                    }),
                ),
            );
            write_buffered!(json_status_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error":"credential_lease_missing",
                    "credential_ref":credential_ref,
                    "credential_version":credential_version,
                }),
            ));
        };
        if let Err(err) = apply_credential_injection(
            &mut headers,
            &mut upstream_url,
            decision
                .get("injection")
                .and_then(|value| value.get("plan"))
                .unwrap_or(&Value::Null),
            &lease,
        ) {
            enqueue_audit(
                state,
                "data_plane.request.denied",
                decision_audit_event(
                    &decision,
                    &request.method,
                    &upstream_url,
                    "denied",
                    json!({"stage":"credential_injection","error":"credential_injection_failed","detail":err.clone(),"request_body_mode":request_policy.mode}),
                ),
            );
            write_buffered!(json_status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"credential_injection_failed","detail":err}),
            ));
        }
    }
    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            write_buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_method","detail":err.to_string()}),
            ))
        }
    };
    let request_method = request.method.clone();
    let content_length = request.content_length as u64;
    let output_stats = if json_stream_redacts_body(&request_policy.mode) {
        Some(Arc::new(Mutex::new(RequestBodyStreamStats::new())))
    } else {
        None
    };
    let upstream_body = match (request_policy.mode.as_str(), output_stats.clone()) {
        ("jsonlStream", Some(stats)) => Body::new(JsonLinesRedactorReader::new(
            Box::new(body_stream),
            request_policy.max_line_bytes,
            request_policy.allowed_fields.clone(),
            stats,
        )),
        ("jsonArrayStream", Some(stats)) => Body::new(JsonArrayRedactorReader::new(
            Box::new(body_stream),
            request_policy.max_item_bytes,
            request_policy.allowed_fields.clone(),
            stats,
        )),
        ("jsonSseStream", Some(stats)) => Body::new(JsonSseRedactorReader::new(
            Box::new(body_stream),
            request_policy.max_line_bytes,
            request_policy.max_event_bytes,
            request_policy.allowed_fields.clone(),
            stats,
        )),
        ("jsonNestedStream", Some(stats)) => Body::new(JsonNestedRedactorReader::new(
            Box::new(body_stream),
            request_policy.max_nested_bytes,
            request_policy.allowed_fields.clone(),
            stats,
        )),
        ("formUrlencodedStream", Some(stats)) => Body::new(FormUrlencodedRedactorReader::new(
            Box::new(body_stream),
            request_policy.max_pair_bytes,
            request_policy.allowed_fields.clone(),
            stats,
        )),
        ("csvStream", Some(stats)) => Body::new(CsvRedactorReader::new(
            Box::new(body_stream),
            request_policy.max_record_bytes,
            request_policy.allowed_fields.clone(),
            stats,
        )),
        _ => Body::sized(body_stream, content_length),
    };
    let builder = state
        .upstream_client
        .request(method, upstream_url.as_str())
        .headers(headers)
        .body(upstream_body);
    let response = match builder.send() {
        Ok(response) => response,
        Err(err) => {
            let (body_sha256, body_bytes) = request_stream_stats_snapshot(&stats);
            let (mutated_body_sha256, mutated_body_bytes) = output_stats
                .as_ref()
                .map(request_stream_stats_snapshot)
                .unwrap_or_else(|| (body_sha256.clone(), body_bytes));
            enqueue_audit(
                state,
                "data_plane.response.blocked",
                decision_audit_event(
                    &decision,
                    &request_method,
                    &upstream_url,
                    "blocked",
                    json!({
                        "stage":"upstream_request",
                        "error":"upstream_request_failed",
                        "detail":error_chain(&err),
                        "request_body_mode":request_policy.mode,
                        "request_body_sha256":body_sha256,
                        "body_sha256":body_sha256,
                        "request_body_bytes":body_bytes,
                        "mutated_request_body_sha256":mutated_body_sha256,
                        "mutated_request_body_bytes":mutated_body_bytes,
                        "request_body_mutated":json_stream_redacts_body(&request_policy.mode),
                        "content_length":content_length,
                    }),
                ),
            );
            write_buffered!(json_status_response(
                StatusCode::BAD_GATEWAY,
                json!({"error":"upstream_request_failed","detail":error_chain(&err)}),
            ));
        }
    };
    let (body_sha256, body_bytes) = request_stream_stats_snapshot(&stats);
    if body_bytes != content_length {
        enqueue_audit(
            state,
            "data_plane.response.blocked",
            decision_audit_event(
                &decision,
                &request_method,
                &upstream_url,
                "blocked",
                json!({
                    "stage":"request_stream",
                    "error":"request_stream_incomplete",
                    "request_body_mode":request_policy.mode,
                    "request_body_sha256":body_sha256,
                    "body_sha256":body_sha256,
                    "request_body_bytes":body_bytes,
                    "content_length":content_length,
                }),
            ),
        );
        write_buffered!(json_status_response(
            StatusCode::BAD_GATEWAY,
            json!({"error":"request_stream_incomplete","contentLength":content_length,"streamedBytes":body_bytes}),
        ));
    }
    enqueue_audit(state, "data_plane.request.streamed", {
        let mut details = json!({
            "request_body_mode":request_policy.mode,
            "request_body_sha256":body_sha256,
            "body_sha256":body_sha256,
            "request_body_bytes":body_bytes,
            "content_length":content_length,
            "max_body_bytes":request_policy.max_body_bytes,
        });
        if let Some(output_stats) = output_stats.as_ref() {
            let (mutated_body_sha256, mutated_body_bytes) =
                request_stream_stats_snapshot(output_stats);
            if let Some(object) = details.as_object_mut() {
                object.insert("request_body_mutated".to_string(), Value::Bool(true));
                object.insert(
                    "mutated_request_body_sha256".to_string(),
                    Value::String(mutated_body_sha256),
                );
                object.insert(
                    "mutated_request_body_bytes".to_string(),
                    Value::Number(mutated_body_bytes.into()),
                );
            }
        }
        decision_audit_event(
            &decision,
            &request_method,
            &upstream_url,
            "streamed",
            details,
        )
    });
    match finalize_upstream_response(
        state,
        &decision,
        &request_method,
        &upstream_url,
        response,
        Some(writer),
        keep_alive,
    ) {
        ForwardResult::Buffered(response) => {
            let response = override_response_connection(response, keep_alive);
            writer.write_all(&response).is_ok() && writer.flush().is_ok()
        }
        ForwardResult::Streamed => true,
    }
}

fn forward_intercepted_streaming_request_to<R: Read + Write>(
    state: &GateState,
    mut request: RequestHead,
    tls: &mut R,
    request_policy: StreamingRequestPolicy,
    authenticated_principal_id: Option<&str>,
    keep_alive: bool,
) -> bool {
    macro_rules! write_buffered {
        ($response:expr) => {{
            let response = override_response_connection($response, keep_alive);
            return tls.write_all(&response).is_ok() && tls.flush().is_ok();
        }};
    }

    let prefetched = std::mem::take(&mut request.prefetched_body);
    let target_url = match Url::parse(&request.target) {
        Ok(url) if url.scheme() == "https" || url.scheme() == "http" => url,
        Ok(_) => {
            write_buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"unsupported_forward_scheme"}),
            ))
        }
        Err(err) => {
            write_buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_forward_url","detail":err.to_string()}),
            ))
        }
    };
    let decision_request = DecisionRequest {
        client_ip: request.client_ip.clone(),
        method: request.method.clone(),
        url: request.target.clone(),
        headers: request.headers.clone(),
        body: String::new(),
        body_sha256: Some(sha256_prefixed(b"")),
        credential_metadata: BTreeMap::new(),
        gmail_proofs: Vec::new(),
    };
    let decision = decide_internal(state, decision_request, authenticated_principal_id);
    if !decision
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        enqueue_audit(
            state,
            "data_plane.request.denied",
            decision_audit_event(
                &decision,
                &request.method,
                &target_url,
                "denied",
                json!({"stage":"policy_decision","request_body_mode":request_policy.mode,"intercepted_connect":true}),
            ),
        );
        write_buffered!(json_status_response(
            status_from_decision(&decision),
            decision
        ));
    }
    let mut upstream_url = target_url;
    apply_rewrite(
        &mut upstream_url,
        decision.get("rewrite").unwrap_or(&Value::Null),
    );
    let mut headers = filtered_forward_headers(&request.headers);
    if let Some(credential_ref) = decision.get("credential_ref").and_then(Value::as_str) {
        let credential_version = decision
            .get("credential_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let Some(lease) = credential_lease(state, credential_ref, credential_version) else {
            enqueue_audit(
                state,
                "data_plane.request.denied",
                decision_audit_event(
                    &decision,
                    &request.method,
                    &upstream_url,
                    "denied",
                    json!({
                        "stage":"credential_lease",
                        "error":"credential_lease_missing",
                        "credential_ref":credential_ref,
                        "credential_version":credential_version,
                        "request_body_mode":request_policy.mode,
                        "intercepted_connect":true,
                    }),
                ),
            );
            write_buffered!(json_status_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error":"credential_lease_missing",
                    "credential_ref":credential_ref,
                    "credential_version":credential_version,
                }),
            ));
        };
        if let Err(err) = apply_credential_injection(
            &mut headers,
            &mut upstream_url,
            decision
                .get("injection")
                .and_then(|value| value.get("plan"))
                .unwrap_or(&Value::Null),
            &lease,
        ) {
            enqueue_audit(
                state,
                "data_plane.request.denied",
                decision_audit_event(
                    &decision,
                    &request.method,
                    &upstream_url,
                    "denied",
                    json!({"stage":"credential_injection","error":"credential_injection_failed","detail":err.clone(),"request_body_mode":request_policy.mode,"intercepted_connect":true}),
                ),
            );
            write_buffered!(json_status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"credential_injection_failed","detail":err}),
            ));
        }
    }
    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            write_buffered!(json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_method","detail":err.to_string()}),
            ))
        }
    };
    let request_method = request.method.clone();
    let content_length = request.content_length as u64;
    let client = state.upstream_client.clone();
    let upstream_url_text = upstream_url.as_str().to_string();
    let (body_sender, body_receiver) = mpsc::sync_channel::<Vec<u8>>(4);
    let stats = Arc::new(Mutex::new(RequestBodyStreamStats::new()));
    let output_stats = if json_stream_redacts_body(&request_policy.mode) {
        Some(Arc::new(Mutex::new(RequestBodyStreamStats::new())))
    } else {
        None
    };
    let request_policy_for_thread = request_policy.clone();
    let output_stats_for_thread = output_stats.clone();
    let sender_thread = thread::spawn(move || {
        let body_reader = ChannelBodyReader::new(body_receiver);
        let body = match (
            request_policy_for_thread.mode.as_str(),
            output_stats_for_thread,
        ) {
            ("jsonlStream", Some(stats)) => Body::new(JsonLinesRedactorReader::new(
                Box::new(body_reader),
                request_policy_for_thread.max_line_bytes,
                request_policy_for_thread.allowed_fields.clone(),
                stats,
            )),
            ("jsonArrayStream", Some(stats)) => Body::new(JsonArrayRedactorReader::new(
                Box::new(body_reader),
                request_policy_for_thread.max_item_bytes,
                request_policy_for_thread.allowed_fields.clone(),
                stats,
            )),
            ("jsonSseStream", Some(stats)) => Body::new(JsonSseRedactorReader::new(
                Box::new(body_reader),
                request_policy_for_thread.max_line_bytes,
                request_policy_for_thread.max_event_bytes,
                request_policy_for_thread.allowed_fields.clone(),
                stats,
            )),
            ("jsonNestedStream", Some(stats)) => Body::new(JsonNestedRedactorReader::new(
                Box::new(body_reader),
                request_policy_for_thread.max_nested_bytes,
                request_policy_for_thread.allowed_fields.clone(),
                stats,
            )),
            ("formUrlencodedStream", Some(stats)) => Body::new(FormUrlencodedRedactorReader::new(
                Box::new(body_reader),
                request_policy_for_thread.max_pair_bytes,
                request_policy_for_thread.allowed_fields.clone(),
                stats,
            )),
            ("csvStream", Some(stats)) => Body::new(CsvRedactorReader::new(
                Box::new(body_reader),
                request_policy_for_thread.max_record_bytes,
                request_policy_for_thread.allowed_fields.clone(),
                stats,
            )),
            _ => Body::sized(body_reader, content_length),
        };
        client
            .request(method, upstream_url_text)
            .headers(headers)
            .body(body)
            .send()
            .map_err(|err| error_chain(&err))
    });
    let pump_result = pump_request_body_to_channel(
        tls,
        prefetched,
        request.content_length,
        body_sender,
        stats.clone(),
    );
    let response_result = sender_thread
        .join()
        .map_err(|_| "upstream request thread panicked".to_string())
        .and_then(|result| result);
    let (body_sha256, body_bytes) = request_stream_stats_snapshot(&stats);
    if let Err(err) = pump_result {
        enqueue_audit(
            state,
            "data_plane.response.blocked",
            decision_audit_event(
                &decision,
                &request_method,
                &upstream_url,
                "blocked",
                json!({
                    "stage":"request_stream",
                    "error":"request_stream_failed",
                    "detail":err,
                    "request_body_mode":request_policy.mode,
                    "intercepted_connect":true,
                    "request_body_sha256":body_sha256,
                    "body_sha256":body_sha256,
                    "request_body_bytes":body_bytes,
                    "content_length":content_length,
                }),
            ),
        );
        write_buffered!(json_status_response(
            StatusCode::BAD_GATEWAY,
            json!({"error":"request_stream_failed","contentLength":content_length,"streamedBytes":body_bytes}),
        ));
    }
    if body_bytes != content_length {
        enqueue_audit(
            state,
            "data_plane.response.blocked",
            decision_audit_event(
                &decision,
                &request_method,
                &upstream_url,
                "blocked",
                json!({
                    "stage":"request_stream",
                    "error":"request_stream_incomplete",
                    "request_body_mode":request_policy.mode,
                    "intercepted_connect":true,
                    "request_body_sha256":body_sha256,
                    "body_sha256":body_sha256,
                    "request_body_bytes":body_bytes,
                    "content_length":content_length,
                }),
            ),
        );
        write_buffered!(json_status_response(
            StatusCode::BAD_GATEWAY,
            json!({"error":"request_stream_incomplete","contentLength":content_length,"streamedBytes":body_bytes}),
        ));
    }
    let response = match response_result {
        Ok(response) => response,
        Err(err) => {
            let (mutated_body_sha256, mutated_body_bytes) = output_stats
                .as_ref()
                .map(request_stream_stats_snapshot)
                .unwrap_or_else(|| (body_sha256.clone(), body_bytes));
            enqueue_audit(
                state,
                "data_plane.response.blocked",
                decision_audit_event(
                    &decision,
                    &request_method,
                    &upstream_url,
                    "blocked",
                    json!({
                        "stage":"upstream_request",
                        "error":"upstream_request_failed",
                        "detail":err,
                        "request_body_mode":request_policy.mode,
                        "intercepted_connect":true,
                        "request_body_sha256":body_sha256,
                        "body_sha256":body_sha256,
                        "request_body_bytes":body_bytes,
                        "mutated_request_body_sha256":mutated_body_sha256,
                        "mutated_request_body_bytes":mutated_body_bytes,
                        "request_body_mutated":json_stream_redacts_body(&request_policy.mode),
                        "content_length":content_length,
                    }),
                ),
            );
            write_buffered!(json_status_response(
                StatusCode::BAD_GATEWAY,
                json!({"error":"upstream_request_failed"}),
            ));
        }
    };
    enqueue_audit(state, "data_plane.request.streamed", {
        let mut details = json!({
            "request_body_mode":request_policy.mode,
            "intercepted_connect":true,
            "request_body_sha256":body_sha256,
            "body_sha256":body_sha256,
            "request_body_bytes":body_bytes,
            "content_length":content_length,
            "max_body_bytes":request_policy.max_body_bytes,
        });
        if let Some(output_stats) = output_stats.as_ref() {
            let (mutated_body_sha256, mutated_body_bytes) =
                request_stream_stats_snapshot(output_stats);
            if let Some(object) = details.as_object_mut() {
                object.insert("request_body_mutated".to_string(), Value::Bool(true));
                object.insert(
                    "mutated_request_body_sha256".to_string(),
                    Value::String(mutated_body_sha256),
                );
                object.insert(
                    "mutated_request_body_bytes".to_string(),
                    Value::Number(mutated_body_bytes.into()),
                );
            }
        }
        decision_audit_event(
            &decision,
            &request_method,
            &upstream_url,
            "streamed",
            details,
        )
    });
    match finalize_upstream_response(
        state,
        &decision,
        &request_method,
        &upstream_url,
        response,
        Some(tls),
        keep_alive,
    ) {
        ForwardResult::Buffered(response) => {
            let response = override_response_connection(response, keep_alive);
            tls.write_all(&response).is_ok() && tls.flush().is_ok()
        }
        ForwardResult::Streamed => true,
    }
}

fn forward_absolute_request_to(
    state: &GateState,
    request: IncomingRequest,
    authenticated_principal_id: Option<&str>,
    keep_alive: bool,
    writer: &mut dyn Write,
) -> bool {
    match forward_absolute_request_inner(
        state,
        request,
        authenticated_principal_id,
        Some(writer),
        keep_alive,
    ) {
        ForwardResult::Buffered(response) => {
            let response = override_response_connection(response, keep_alive);
            writer.write_all(&response).is_ok() && writer.flush().is_ok()
        }
        ForwardResult::Streamed => true,
    }
}

fn request_streaming_preflight(
    state: &GateState,
    request: &RequestHead,
    authenticated_principal_id: Option<&str>,
) -> RequestStreamingPreflight {
    let target_url = match Url::parse(&request.target) {
        Ok(url) if url.scheme() == "https" || url.scheme() == "http" => url,
        _ => return RequestStreamingPreflight::Buffer,
    };
    let headers = lower_headers(&request.headers);
    let snapshot = current_snapshot(state);
    let principal = if let Some(principal_id) = authenticated_principal_id {
        snapshot
            .principals
            .iter()
            .find(|item| item.id == principal_id)
    } else {
        snapshot.identify_principal(request.client_ip.as_deref(), &headers)
    };
    let Some(principal) = principal else {
        return RequestStreamingPreflight::Buffer;
    };
    let Some(route_match) = snapshot.match_route(&principal.id, &request.method, &target_url)
    else {
        return RequestStreamingPreflight::Buffer;
    };
    let route = route_match.route;
    let Some(request_config_object) = get_object(&route.adapter_config, "request") else {
        return RequestStreamingPreflight::Buffer;
    };
    let request_config = route.adapter_config.get("request").unwrap_or(&Value::Null);
    let body_mode = request_config_object
        .get("bodyMode")
        .and_then(Value::as_str)
        .unwrap_or("any");
    if body_mode != "stream"
        && body_mode != "jsonlStream"
        && body_mode != "jsonArrayStream"
        && body_mode != "jsonSseStream"
        && body_mode != "jsonNestedStream"
        && body_mode != "formUrlencodedStream"
        && body_mode != "csvStream"
    {
        return RequestStreamingPreflight::Buffer;
    }
    if route.adapter_type != "generic.rest" {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"streaming_request_unsupported_adapter","adapter":route.adapter_type}),
        ));
    }
    if route
        .jit
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::FORBIDDEN,
            json!({"error":"streaming_request_jit_unsupported","route_id":route.id}),
        ));
    }
    if headers.get("transfer-encoding").is_some() {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::BAD_REQUEST,
            json!({"error":"streaming_request_transfer_encoding_unsupported"}),
        ));
    }
    if !request.has_content_length {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::LENGTH_REQUIRED,
            json!({"error":"streaming_request_requires_content_length"}),
        ));
    }
    let Some(max_body_bytes) = request_config_object
        .get("maxBodyBytes")
        .and_then(Value::as_u64)
    else {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"streaming_request_max_body_missing","route_id":route.id}),
        ));
    };
    if request.content_length as u64 > max_body_bytes {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error":"request_body_too_large","maxBodyBytes":max_body_bytes,"contentLength":request.content_length}),
        ));
    }
    if request.prefetched_body.len() > request.content_length {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::BAD_REQUEST,
            json!({"error":"request_pipeline_not_supported"}),
        ));
    }
    let allowed_fields = allowed_field_paths(request_config);
    if json_stream_redacts_body(body_mode) && allowed_fields.is_empty() {
        return RequestStreamingPreflight::Reject(json_status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"streaming_redaction_request_allowed_fields_missing","route_id":route.id,"bodyMode":body_mode}),
        ));
    }
    RequestStreamingPreflight::Stream(StreamingRequestPolicy {
        mode: body_mode.to_string(),
        max_body_bytes,
        max_line_bytes: json_lines_max_line_bytes(request_config),
        max_item_bytes: json_array_max_item_bytes(request_config),
        max_event_bytes: json_sse_max_event_bytes(request_config),
        max_pair_bytes: form_urlencoded_max_pair_bytes(request_config),
        max_record_bytes: csv_max_record_bytes(request_config),
        max_nested_bytes: json_nested_max_nested_bytes(request_config),
        allowed_fields,
    })
}

fn read_request_head_from<R: Read>(
    reader: &mut R,
    client_ip: Option<String>,
) -> Result<RequestHead, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let read = reader.read(&mut chunk).map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("connection closed before headers".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
        if buffer.len() > 1024 * 1024 {
            return Err("headers too large".to_string());
        }
    }
    let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let target = parts.next().ok_or("missing request target")?.to_string();
    let mut content_length = 0usize;
    let mut has_content_length = false;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_string(), value.trim().to_string());
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|err| err.to_string())?;
            }
        }
    }
    let lowered = lower_headers(&headers);
    if lowered.get("transfer-encoding").is_some() {
        return Err("transfer-encoding request bodies are not supported".to_string());
    }
    Ok(RequestHead {
        method,
        target,
        headers,
        content_length,
        has_content_length,
        prefetched_body: buffer[header_end..].to_vec(),
        client_ip,
    })
}

fn read_request_body_from_head<R: Read>(
    reader: &mut R,
    head: RequestHead,
) -> Result<IncomingRequest, String> {
    if head.prefetched_body.len() > head.content_length {
        return Err("request pipelining is not supported".to_string());
    }
    let mut body = head.prefetched_body;
    let mut chunk = [0u8; 4096];
    while body.len() < head.content_length {
        let read = reader.read(&mut chunk).map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("connection closed before body".to_string());
        }
        let remaining = head.content_length - body.len();
        body.extend_from_slice(&chunk[..read.min(remaining)]);
        if read > remaining {
            return Err("request pipelining is not supported".to_string());
        }
    }
    Ok(IncomingRequest {
        method: head.method,
        target: head.target,
        headers: head.headers,
        body,
        client_ip: head.client_ip,
    })
}

fn read_request_head(
    stream: &mut TcpStream,
    client_ip: Option<String>,
) -> Result<RequestHead, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| err.to_string())?;
    read_request_head_from(stream, client_ip)
}

fn request_target_parts(target: &str) -> (String, BTreeMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    (path.to_string(), params)
}

fn release_provenance_digest(path: &Option<String>) -> Value {
    signed_json_digest(path, "provenance_digest")
}

fn image_signatures_digest(path: &Option<String>) -> Value {
    signed_json_digest(path, "image_signature_bundle_digest")
}

fn source_tree_digest(path: &Option<String>) -> Value {
    let Some(path) = path else {
        return Value::Null;
    };
    let Ok(bytes) = fs::read(path) else {
        return Value::Null;
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        if let Some(digest) = value
            .get("provenance")
            .and_then(|item| item.get("source_tree"))
            .and_then(|item| item.get("digest"))
            .and_then(Value::as_str)
        {
            if digest.starts_with("sha256:") {
                return Value::String(digest.to_string());
            }
        }
    }
    Value::Null
}

fn signed_json_digest(path: &Option<String>, digest_field: &str) -> Value {
    let Some(path) = path else {
        return Value::Null;
    };
    let Ok(bytes) = fs::read(path) else {
        return Value::Null;
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        if let Some(digest) = value.get(digest_field).and_then(Value::as_str) {
            if digest.starts_with("sha256:") {
                return Value::String(digest.to_string());
            }
        }
    }
    Value::String(sha256_prefixed(&bytes))
}

fn runtime_manifest(state: &GateState) -> Value {
    let snapshot = current_snapshot(state);
    let provenance_digest = release_provenance_digest(&state.release_provenance_path);
    let image_signature_digest = image_signatures_digest(&state.image_signatures_path);
    let source_digest = source_tree_digest(&state.release_provenance_path);
    json!({
        "component":"serverware-decision-gate-rs",
        "version":env!("CARGO_PKG_VERSION"),
        "binary_digest":state.binary_digest,
        "policy_hash":snapshot.hash,
        "policy_signing_key_id":snapshot.policy_signing_key_id,
        "policy_trust_root_source":state.policy_trust_root_source.label(),
        "provenance_digest":provenance_digest,
        "image_signatures_digest":image_signature_digest,
        "source_tree_digest":source_digest,
        "routes":snapshot.routes.len(),
        "credential_lease_cache":state.credential_leases.lock().expect("credential lease mutex poisoned").len(),
        "jit_grant_store": if state.grant_consume_url.is_some() {"shared"} else {"local"},
        "shared_rate_limit_store": state.rate_limit_consume_url.is_some(),
        "absolute_form_forwarder":true,
        "absolute_form_request_body_streaming":true,
        "connect_request_body_streaming":true,
        "jsonl_streaming_request_response_redaction":true,
        "json_array_streaming_request_response_redaction":true,
        "json_sse_streaming_request_response_redaction":true,
        "json_nested_streaming_request_response_redaction":true,
        "form_urlencoded_streaming_request_response_redaction":true,
        "csv_streaming_request_response_redaction":true,
        "connect_mitm_interceptor":state.mitm_authority.is_some(),
        "leaf_config_cache":state.leaf_configs.lock().expect("leaf config cache mutex poisoned").len(),
        "audit":audit_status(state),
        "policy_reload":{
            "success":state.policy_reload_success.load(Ordering::Relaxed),
            "failed":state.policy_reload_failed.load(Ordering::Relaxed),
        },
        "hot_path":{
            "sqlite_calls":0,
            "filesystem_calls":0,
        },
    })
}

fn attestation(state: &GateState, nonce: Option<String>) -> Value {
    let manifest = runtime_manifest(state);
    let snapshot = current_snapshot(state);
    let provenance_digest = release_provenance_digest(&state.release_provenance_path);
    let image_signature_digest = image_signatures_digest(&state.image_signatures_path);
    let source_digest = source_tree_digest(&state.release_provenance_path);
    json!({
        "tee_platform":"none-dev",
        "quote":null,
        "runtime_manifest":manifest,
        "runtime_manifest_digest":sha256_prefixed(canonical_json(&manifest).as_bytes()),
        "data_plane_binary_digest":state.binary_digest,
        "policy_bundle_digest":snapshot.hash,
        "policy_signing_key_id":snapshot.policy_signing_key_id,
        "policy_trust_root_source":state.policy_trust_root_source.label(),
        "provenance_digest":provenance_digest,
        "image_signatures_digest":image_signature_digest,
        "source_tree_digest":source_digest,
        "credential_generations":state.credential_generations.lock().expect("credential generation mutex poisoned").len(),
        "credential_leases":state.credential_leases.lock().expect("credential lease mutex poisoned").len(),
        "connect_mitm_interceptor":state.mitm_authority.is_some(),
        "leaf_config_cache":state.leaf_configs.lock().expect("leaf config cache mutex poisoned").len(),
        "audit":audit_status(state),
        "nonce":nonce,
    })
}

fn connect_inner_absolute_target(
    authority: &str,
    target: &str,
    expected_host: &str,
    expected_port: u16,
) -> Result<String, String> {
    if absolute_form_target(target) {
        let url = Url::parse(target).map_err(|err| format!("invalid absolute inner URL: {err}"))?;
        let host = url
            .host_str()
            .ok_or("absolute inner URL is missing host")?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or("absolute inner URL is missing port")?;
        if host != expected_host || port != expected_port {
            return Err("absolute inner URL does not match CONNECT authority".to_string());
        }
        return Ok(target.to_string());
    }
    if !target.starts_with('/') {
        return Err(
            "intercepted CONNECT request target must be origin-form or absolute-form".to_string(),
        );
    }
    Ok(format!("https://{authority}{target}"))
}

fn handle_connect_request(mut stream: TcpStream, state: Arc<GateState>, request: IncomingRequest) {
    let client_ip = request.client_ip.clone();
    let decision = connect_preflight(
        &state,
        request.client_ip.as_deref(),
        &request.target,
        &request.headers,
    );
    if !decision
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        enqueue_audit(
            &state,
            "data_plane.connect.denied",
            connect_audit_event(
                &decision,
                &request.target,
                request.client_ip.as_deref(),
                "denied",
            ),
        );
        let response = if decision
            .get("status_code")
            .and_then(Value::as_u64)
            .unwrap_or(403)
            == 400
        {
            http_response("400 Bad Request", decision)
        } else {
            http_response("403 Forbidden", decision)
        };
        let _ = stream.write_all(&response);
        let _ = stream.flush();
        return;
    }
    let (host, port) = match connect_authority(&request.target) {
        Ok(parsed) => parsed,
        Err(err) => {
            let response = json_status_response(
                StatusCode::BAD_REQUEST,
                json!({"error":"invalid_connect_target","detail":err}),
            );
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            return;
        }
    };
    let tls_config = match mitm_server_config(&state, &host) {
        Ok(config) => config,
        Err(err) => {
            enqueue_audit(
                &state,
                "data_plane.connect.denied",
                json!({
                    "component":"serverware-decision-gate-rs",
                    "method":"CONNECT",
                    "target":request.target,
                    "authority":authority_string(&host, port),
                    "outcome":"denied",
                    "stage":"mitm_ca",
                    "error":"mitm_ca_unavailable",
                    "detail":err.clone(),
                    "client_ip":request.client_ip,
                    "policy_hash":current_snapshot(&state).hash.clone(),
                }),
            );
            let response = json_status_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"mitm_ca_unavailable","detail":err}),
            );
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            return;
        }
    };
    let tls_conn = match ServerConnection::new(tls_config) {
        Ok(conn) => conn,
        Err(err) => {
            enqueue_audit(
                &state,
                "data_plane.connect.denied",
                json!({
                    "component":"serverware-decision-gate-rs",
                    "method":"CONNECT",
                    "target":request.target,
                    "authority":authority_string(&host, port),
                    "outcome":"denied",
                    "stage":"mitm_tls",
                    "error":"mitm_tls_init_failed",
                    "detail":err.to_string(),
                    "client_ip":request.client_ip,
                    "policy_hash":current_snapshot(&state).hash.clone(),
                }),
            );
            let response = json_status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"mitm_tls_init_failed","detail":err.to_string()}),
            );
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            return;
        }
    };
    if stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let authority = authority_string(&host, port);
    enqueue_audit(
        &state,
        "data_plane.connect.established",
        connect_audit_event(
            &decision,
            &request.target,
            request.client_ip.as_deref(),
            "established",
        ),
    );
    let authenticated_principal_id = decision
        .get("principal_id")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let mut tls = StreamOwned::new(tls_conn, stream);
    let mut handled_requests = 0u64;
    loop {
        let head = match read_request_head_from(&mut tls, client_ip.clone()) {
            Ok(head) => head,
            Err(err) if err == "connection closed before headers" => break,
            Err(err) => {
                let response = json_status_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"bad_intercepted_request","detail":err}),
                );
                let _ = tls.write_all(&response);
                let _ = tls.flush();
                break;
            }
        };
        let close_after = request_head_wants_close(&head);
        let mut head = head;
        let forwarded = match connect_inner_absolute_target(&authority, &head.target, &host, port) {
            Ok(target) => {
                head.target = target;
                match request_streaming_preflight(
                    &state,
                    &head,
                    authenticated_principal_id.as_deref(),
                ) {
                    RequestStreamingPreflight::Stream(policy) => {
                        forward_intercepted_streaming_request_to(
                            &state,
                            head,
                            &mut tls,
                            policy,
                            authenticated_principal_id.as_deref(),
                            !close_after,
                        )
                    }
                    RequestStreamingPreflight::Reject(response) => {
                        let response = override_response_connection(response, false);
                        tls.write_all(&response).is_ok() && tls.flush().is_ok() && false
                    }
                    RequestStreamingPreflight::Buffer => {
                        let inner = match read_request_body_from_head(&mut tls, head) {
                            Ok(inner) => inner,
                            Err(err) => {
                                let response = override_response_connection(
                                    json_status_response(
                                        StatusCode::BAD_REQUEST,
                                        json!({"error":"bad_intercepted_request","detail":err}),
                                    ),
                                    false,
                                );
                                let _ = tls.write_all(&response);
                                let _ = tls.flush();
                                break;
                            }
                        };
                        forward_absolute_request_to(
                            &state,
                            inner,
                            authenticated_principal_id.as_deref(),
                            !close_after,
                            &mut tls,
                        )
                    }
                }
            }
            Err(err) => {
                let keep_alive = !close_after && head.content_length == head.prefetched_body.len();
                let response = override_response_connection(
                    json_status_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid_connect_inner_request","detail":err}),
                    ),
                    keep_alive,
                );
                tls.write_all(&response).is_ok() && tls.flush().is_ok() && keep_alive
            }
        };
        handled_requests += 1;
        if !forwarded {
            break;
        }
        if close_after {
            break;
        }
    }
    if handled_requests > 1 {
        enqueue_audit(
            &state,
            "data_plane.connect.keep_alive",
            connect_audit_event(
                &decision,
                &request.target,
                request.client_ip.as_deref(),
                "keep_alive",
            )
            .as_object()
            .cloned()
            .map(|mut event| {
                event.insert(
                    "intercepted_request_count".to_string(),
                    Value::Number(handled_requests.into()),
                );
                Value::Object(event)
            })
            .unwrap_or_else(|| json!({"intercepted_request_count":handled_requests})),
        );
    }
}

fn handle_connection(mut stream: TcpStream, state: Arc<GateState>) {
    let client_ip = stream.peer_addr().ok().map(|addr| addr.ip().to_string());
    let head = match read_request_head(&mut stream, client_ip) {
        Ok(head) => head,
        Err(err) => {
            let response = http_response(
                "400 Bad Request",
                json!({"error":"bad_request","detail":err}),
            );
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            return;
        }
    };
    if head.method == "CONNECT" {
        let request = match read_request_body_from_head(&mut stream, head) {
            Ok(request) => request,
            Err(err) => {
                let response = http_response(
                    "400 Bad Request",
                    json!({"error":"bad_request","detail":err}),
                );
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                return;
            }
        };
        handle_connect_request(stream, state, request);
        return;
    }
    if absolute_form_target(&head.target) {
        match request_streaming_preflight(&state, &head, None) {
            RequestStreamingPreflight::Stream(policy) => {
                let mut request = head;
                let prefetched = std::mem::take(&mut request.prefetched_body);
                let reader_stream = match stream.try_clone() {
                    Ok(reader_stream) => reader_stream,
                    Err(err) => {
                        let response = json_status_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({"error":"request_stream_clone_failed","detail":err.to_string()}),
                        );
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                        return;
                    }
                };
                let stats = Arc::new(Mutex::new(RequestBodyStreamStats::new()));
                let body_stream = RequestBodyStream::new(
                    Box::new(reader_stream),
                    prefetched,
                    request.content_length,
                    stats.clone(),
                );
                let _ = forward_absolute_streaming_request_to(
                    &state,
                    request,
                    body_stream,
                    stats,
                    policy,
                    None,
                    false,
                    &mut stream,
                );
                return;
            }
            RequestStreamingPreflight::Reject(response) => {
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                return;
            }
            RequestStreamingPreflight::Buffer => {}
        }
        let request = match read_request_body_from_head(&mut stream, head) {
            Ok(request) => request,
            Err(err) => {
                let response = http_response(
                    "400 Bad Request",
                    json!({"error":"bad_request","detail":err}),
                );
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                return;
            }
        };
        let _ = forward_absolute_request_to(&state, request, None, false, &mut stream);
        return;
    }
    let request = match read_request_body_from_head(&mut stream, head) {
        Ok(request) => request,
        Err(err) => {
            let response = http_response(
                "400 Bad Request",
                json!({"error":"bad_request","detail":err}),
            );
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            return;
        }
    };
    let response = if request.method == "GET" {
        let (path, query) = request_target_parts(&request.target);
        match path.as_str() {
            "/healthz" => {
                let snapshot = current_snapshot(&state);
                http_response(
                    "200 OK",
                    json!({
                        "ok":true,
                        "policy_hash":snapshot.hash,
                        "policy_signing_key_id":snapshot.policy_signing_key_id,
                        "policy_trust_root_source":state.policy_trust_root_source.label(),
                        "data_plane_binary_digest":state.binary_digest,
                        "routes":snapshot.routes.len(),
                        "grants":state.grants.lock().expect("grant cache mutex poisoned").len(),
                        "credential_generations":state.credential_generations.lock().expect("credential generation mutex poisoned").len(),
                        "credential_leases":state.credential_leases.lock().expect("credential lease mutex poisoned").len(),
                        "jit_grant_store": if state.grant_consume_url.is_some() {"shared"} else {"local"},
                        "shared_rate_limit_store":state.rate_limit_consume_url.is_some(),
                        "leaf_config_cache":state.leaf_configs.lock().expect("leaf config cache mutex poisoned").len(),
                            "connect_preflight":true,
                            "connect_mitm_interceptor":state.mitm_authority.is_some(),
                            "absolute_form_forwarder":true,
                            "absolute_form_request_body_streaming":true,
                            "connect_request_body_streaming":true,
                            "jsonl_streaming_request_response_redaction":true,
                            "json_array_streaming_request_response_redaction":true,
                            "json_sse_streaming_request_response_redaction":true,
                            "json_nested_streaming_request_response_redaction":true,
                            "form_urlencoded_streaming_request_response_redaction":true,
                            "csv_streaming_request_response_redaction":true,
                            "audit":audit_status(&state),
                        "policy_reload":{
                            "success":state.policy_reload_success.load(Ordering::Relaxed),
                            "failed":state.policy_reload_failed.load(Ordering::Relaxed),
                        },
                    }),
                )
            }
            "/attestation" => {
                http_response("200 OK", attestation(&state, query.get("nonce").cloned()))
            }
            _ => http_response("404 Not Found", json!({"error":"not_found"})),
        }
    } else if request.method == "POST" && request.target == "/v1/decide" {
        match serde_json::from_slice::<DecisionRequest>(&request.body) {
            Ok(req) => http_response("200 OK", decide(&state, req)),
            Err(err) => http_response(
                "400 Bad Request",
                json!({"error":"invalid_decision_request","detail":err.to_string()}),
            ),
        }
    } else if request.method == "POST" && request.target == "/v1/grants" {
        match serde_json::from_slice::<GrantCreate>(&request.body) {
            Ok(req) => http_response("200 OK", create_grant(&state, req)),
            Err(err) => http_response(
                "400 Bad Request",
                json!({"error":"invalid_grant_request","detail":err.to_string()}),
            ),
        }
    } else {
        http_response("404 Not Found", json!({"error":"not_found"}))
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

fn main() -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let policy_path = env::var("SERVERWARE_POLICY_BUNDLE")
        .unwrap_or_else(|_| "/data/policy-bundle.json".to_string());
    let policy_trust_root_source = if let Some(url) =
        env::var("SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    {
        PolicyTrustRootSource::AttestedControlPlane {
            url,
            expected_quote_key_id: env::var("SERVERWARE_EXPECTED_CONTROL_PLANE_QUOTE_KEY_ID")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
    } else {
        PolicyTrustRootSource::File(
            env::var("SERVERWARE_POLICY_SIGNING_PUBLIC_KEY")
                .unwrap_or_else(|_| "/data/policy-signing-ed25519.pub.pem".to_string()),
        )
    };
    let generation_path = env::var("SERVERWARE_CREDENTIAL_GENERATIONS")
        .unwrap_or_else(|_| "/data/credential-generations.json".to_string());
    let lease_path = env::var("SERVERWARE_CREDENTIAL_LEASES")
        .unwrap_or_else(|_| "/data/credential-leases.json".to_string());
    let generation_poll_seconds = env::var("SERVERWARE_CREDENTIAL_GENERATION_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.25);
    let policy_poll_seconds = env::var("SERVERWARE_POLICY_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(generation_poll_seconds);
    let audit_url = env::var("SERVERWARE_CONTROL_PLANE_AUDIT_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let audit_token = env::var("SERVERWARE_DATA_PLANE_AUDIT_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if audit_url.is_some() != audit_token.is_some() {
        return Err(
            "SERVERWARE_CONTROL_PLANE_AUDIT_URL and SERVERWARE_DATA_PLANE_AUDIT_TOKEN must be set together"
                .to_string(),
        );
    }
    let grant_consume_url = env::var("SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if grant_consume_url.is_some() && audit_token.is_none() {
        return Err(
            "SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL requires SERVERWARE_DATA_PLANE_AUDIT_TOKEN"
                .to_string(),
        );
    }
    let rate_limit_consume_url = env::var("SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if rate_limit_consume_url.is_some() && audit_token.is_none() {
        return Err(
            "SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL requires SERVERWARE_DATA_PLANE_AUDIT_TOKEN"
                .to_string(),
        );
    }
    let audit_queue_max = env::var("SERVERWARE_DATA_PLANE_AUDIT_QUEUE_MAX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000)
        .max(1);
    let audit_batch_max = env::var("SERVERWARE_DATA_PLANE_AUDIT_BATCH_MAX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 200);
    let gmail_proof_cache_max = env::var("SERVERWARE_GMAIL_PROOF_CACHE_MAX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000)
        .max(1);
    let audit_flush_ms = env::var("SERVERWARE_DATA_PLANE_AUDIT_FLUSH_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100)
        .max(10);
    let host = env::var("SERVERWARE_DECISION_GATE_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("SERVERWARE_DECISION_GATE_PORT").unwrap_or_else(|_| "9090".to_string());
    let release_provenance_path = env::var("SERVERWARE_RELEASE_PROVENANCE").ok();
    let image_signatures_path = env::var("SERVERWARE_IMAGE_SIGNATURES").ok();
    let initial_policy_mtime = file_mtime(&policy_path);
    let snapshot = Arc::new(load_snapshot(&policy_path, &policy_trust_root_source)?);
    let binary_digest = current_binary_digest()?;
    let upstream_client = build_upstream_client()?;
    let audit_client = build_audit_client()?;
    let mitm_authority = build_mitm_authority()?;
    let state = Arc::new(GateState {
        snapshot: RwLock::new(snapshot),
        policy_path,
        policy_trust_root_source,
        policy_mtime: Mutex::new(initial_policy_mtime),
        policy_reload_success: AtomicU64::new(0),
        policy_reload_failed: AtomicU64::new(0),
        grants: Mutex::new(HashMap::new()),
        gmail_proofs: Mutex::new(HashMap::new()),
        gmail_proof_cache_max,
        constraint_rate_counters: Mutex::new(HashMap::new()),
        credential_generations: Mutex::new(HashMap::new()),
        generation_mtime: Mutex::new(None),
        generation_path,
        credential_leases: Mutex::new(HashMap::new()),
        lease_mtime: Mutex::new(None),
        lease_path,
        upstream_client,
        audit_client,
        audit_url,
        audit_token,
        grant_consume_url,
        rate_limit_consume_url,
        audit_queue: Mutex::new(VecDeque::new()),
        audit_queue_max,
        audit_batch_max,
        audit_enqueued: AtomicU64::new(0),
        audit_dropped: AtomicU64::new(0),
        audit_required_failed: AtomicU64::new(0),
        audit_sent: AtomicU64::new(0),
        audit_send_failed: AtomicU64::new(0),
        mitm_authority: mitm_authority.map(Mutex::new),
        leaf_configs: Mutex::new(HashMap::new()),
        binary_digest,
        release_provenance_path,
        image_signatures_path,
    });
    refresh_generation_cache(&state, true)?;
    refresh_lease_cache(&state, true)?;
    let policy_state = Arc::clone(&state);
    thread::spawn(move || {
        policy_worker(
            policy_state,
            Duration::from_secs_f64(policy_poll_seconds.max(0.05)),
        )
    });
    let generation_state = Arc::clone(&state);
    thread::spawn(move || {
        generation_worker(
            generation_state,
            Duration::from_secs_f64(generation_poll_seconds.max(0.05)),
        )
    });
    let lease_state = Arc::clone(&state);
    thread::spawn(move || {
        lease_worker(
            lease_state,
            Duration::from_secs_f64(generation_poll_seconds.max(0.05)),
        )
    });
    if audit_enabled(&state) {
        let audit_state = Arc::clone(&state);
        thread::spawn(move || audit_worker(audit_state, Duration::from_millis(audit_flush_ms)));
    }
    let listener = TcpListener::bind(format!("{host}:{port}"))
        .map_err(|err| format!("bind decision gate: {err}"))?;
    let snapshot = current_snapshot(&state);
    eprintln!(
        "serverware decision gate listening on {host}:{port} policy_hash={} binary_digest={} routes={} generations={} leases={} connect_mitm={} audit={}",
        snapshot.hash,
        state.binary_digest,
        snapshot.routes.len(),
        state
            .credential_generations
            .lock()
            .expect("credential generation mutex poisoned")
            .len(),
        state
            .credential_leases
            .lock()
            .expect("credential lease mutex poisoned")
            .len(),
        state.mitm_authority.is_some(),
        audit_enabled(&state)
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || handle_connection(stream, state));
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
    Ok(())
}
