//! Ordinary-host, single-use exact-request signing transport. No reusable AWS
//! tuple, generic lease cache, automatic retry or publication selection fallback.
use crate::aws_ecr_publication as ecr;
use crate::*;
use std::sync::atomic::AtomicUsize;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const ERROR: &str = "ecr_publication_unavailable";
const UNKNOWN: &str = "ecr_publication_outcome_unknown";
const PREFIX: &str = "/api/data-plane/ecr-publications/";
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
struct Slot;
impl Slot {
    fn acquire() -> Result<Self, String> {
        ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 2).then_some(n + 1)
            })
            .map(|_| Self)
            .map_err(|_| ERROR.to_owned())
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
fn require(condition: bool) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(ERROR.into())
    }
}
fn ordinary(state: &GateState, snapshot: &Arc<Snapshot>) -> Result<(), String> {
    require(
        state.host_trusted_approvals_enabled
            && !state.is_production
            && state.policy_shadow.is_operator_demo()
            && state.proxy_ingress_attestation.mode == operator_demo::INGRESS_MODE
            && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy
            && !state.atomic_release_authorization_enabled
            && state.native_serving_privileges.is_none()
            && state.native_secret_broker.is_none()
            && state.native_runtime_lifetime.is_none()
            && state.native_policy_bytes.is_none()
            && state.policy_shadow_generation_control.is_none()
            && snapshot_is_active(state, snapshot)
            && policy_trust_is_fresh(state),
    )
}
fn exact(value: &Value, names: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|n| o.contains_key(*n)))
}
fn nonce() -> Result<([u8; 32], String), String> {
    let mut bytes = [0u8; 32];
    ring_rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ERROR.to_owned())?;
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    Ok((bytes, encoded))
}
fn child_id() -> Result<String, String> {
    let (mut bytes, _) = nonce()?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let h = hex::encode(&bytes[..16]);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn endpoint(state: &GateState, suffix: &str) -> Result<Url, String> {
    require(matches!(suffix, "context" | "reserve" | "finish"))?;
    let mut url = Url::parse(state.credential_lease_url.as_deref().ok_or(ERROR)?)
        .map_err(|_| ERROR.to_owned())?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/api/data-plane/credential-leases",
    )?;
    url.set_path(&format!("{PREFIX}{suffix}"));
    Ok(url)
}
fn call(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    suffix: &str,
    value: &Value,
    response_nonce: &str,
) -> Result<(StatusCode, SensitiveJsonValue), String> {
    if suffix != "finish" {
        ordinary(state, snapshot)?;
    }
    let url = endpoint(state, suffix)?;
    let wire = Zeroizing::new(native_response_profile::canonical_ascii_bytes(value)?);
    let limit = if suffix == "finish" {
        34 * 1024 * 1024 + 4096
    } else if suffix == "reserve" {
        22 * 1024 * 1024 + 8192
    } else {
        8192
    };
    require(wire.len() <= limit)?;
    let client = control_plane_client_builder(Duration::from_secs(10))?
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|_| ERROR.to_owned())?;
    let mut response = client
        .post(url.as_str())
        .header(
            "X-Serverware-Data-Plane-Token",
            state.credential_lease_token.as_deref().ok_or(ERROR)?,
        )
        .header("X-Serverware-Response-Nonce", response_nonce)
        .header("content-type", "application/json")
        .body(wire.to_vec())
        .timeout(Duration::from_secs(10))
        .send()
        .map_err(|_| UNKNOWN.to_owned())?;
    let status = response.status();
    let bytes = Zeroizing::new(
        read_bounded_control_plane_response_body(&mut response, 65536, "ECR control response")
            .map_err(|_| UNKNOWN.to_owned())?,
    );
    verify_credential_lease_response(
        snapshot,
        url.as_str(),
        response_nonce,
        status,
        response.headers(),
        &bytes,
    )
    .map_err(|_| UNKNOWN.to_owned())?;
    if suffix != "finish" {
        ordinary(state, snapshot)?;
    }
    let value = SensitiveJsonValue::new(
        strict_json_value_from_slice(&bytes).map_err(|_| UNKNOWN.to_owned())?,
    );
    Ok((status, value))
}
fn binding(
    publication: &str,
    principal: &str,
    route: &str,
    credential: &str,
    policy: &str,
) -> Value {
    json!({"publicationId":publication,"principalId":principal,"routeId":route,"credentialId":credential,"policyHash":policy})
}
fn denial(payload: &Value, status: StatusCode) -> Value {
    if status.as_u16() == 428 {
        let url = payload
            .get("approval_url")
            .or_else(|| payload.pointer("/payload/approval_url"))
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("/approvals/"))
            .filter(|s| ecr::uuid(s));
        if let Some(id) = url {
            return json!({"error":"ecr_publication_approval_required","status_code":428,
            "approval_url":format!("/approvals/{id}"),"retry_semantics":"explicit_identical_request_after_approval"});
        }
    }
    json!({"error":if status.is_client_error(){ERROR}else{UNKNOWN},"status_code":503})
}
pub(super) fn decision(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    req: &DecisionRequest,
    url: &Url,
    principal: &Principal,
    route: &Route,
    started: Instant,
    preview: bool,
    shadow: bool,
) -> Value {
    let result = (|| -> Result<Value, Value> {
        ordinary(state, snapshot).map_err(|_| json!({"error":ERROR,"status_code":503}))?;
        if shadow || req.client_request_digest.is_some() {
            return Err(json!({"error":"ecr_publication_proof_unsupported","status_code":422}));
        }
        let operation = ecr::validate_request(req, url, route)?;
        let credential_id = route
            .credential_ref
            .as_deref()
            .ok_or_else(|| json!({"error":ERROR}))?;
        let mut context = binding(
            operation["publicationId"].as_str().unwrap_or(""),
            &principal.id,
            &route.id,
            credential_id,
            &snapshot.hash,
        );
        context["apiVersion"] = json!("serverware.ecrContextRequest/v1");
        let (_, proof_nonce) = nonce().map_err(|_| json!({"error":ERROR}))?;
        let (status, response) = call(state, snapshot, "context", &context, &proof_nonce)
            .map_err(|_| json!({"error":ERROR,"status_code":503}))?;
        if status != StatusCode::OK {
            return Err(denial(&response, status));
        }
        let version = response["credentialVersion"].as_u64().filter(|n| *n > 0);
        let expiry = response["expiresAtEpochMs"]
            .as_u64()
            .filter(|n| u128::from(*n) > now_epoch_ms());
        let echoed = [
            "publicationId",
            "principalId",
            "routeId",
            "credentialId",
            "policyHash",
        ];
        if !exact(
            &response,
            &[
                "apiVersion",
                "publicationId",
                "principalId",
                "routeId",
                "credentialId",
                "policyHash",
                "credentialVersion",
                "expiresAtEpochMs",
            ],
        ) || response["apiVersion"] != "serverware.ecrContextResponse/v1"
            || echoed.iter().any(|k| response[*k] != context[*k])
            || version.is_none()
            || expiry.is_none()
        {
            return Err(json!({"error":ERROR,"status_code":503}));
        }
        let version = version.unwrap();
        let headers = BTreeMap::from([
            (
                "host".to_owned(),
                ecr::authority(&route.adapter_config).map_err(|_| json!({"error":ERROR}))?,
            ),
            ("content-type".to_owned(), ecr::MEDIA.to_owned()),
            ("content-length".to_owned(), req.body.len().to_string()),
            (
                "x-amz-target".to_owned(),
                format!(
                    "AmazonEC2ContainerRegistry_V20150921.{}",
                    operation["action"].as_str().unwrap_or("")
                ),
            ),
        ]);
        let canonical = canonical_request(
            req,
            &headers,
            url,
            principal,
            route,
            version,
            &snapshot.hash,
            &operation,
        );
        let request_digest = canonical_request_digest_profile(&canonical, ReleaseProfile::Legacy);
        let operation_digest = operation_digest_profile(&canonical, ReleaseProfile::Legacy);
        Ok(
            json!({"action":if preview{"preview"}else{"allow"},"allowed":!preview,"would_allow":false,
            "preview":preview,"authorizes_forwarding":!preview,"status_code":200,
            "principal_id":principal.id,"route_id":route.id,"adapter":ecr::ADAPTER,
            "policy_hash":snapshot.hash,"snapshot_epoch":snapshot.epoch,"credential_ref":credential_id,
            "credential_version":version,"publication_expires_at_epoch_ms":expiry,
            "client_request_digest":Value::Null,"request_digest":request_digest,"operation_digest":operation_digest,
            "operation":operation,"rewrite":{},"discard_headers":route.discard_headers,
            "discarded_request_headers":discarded_request_header_evidence(&req.headers,&route.discard_headers),
            "jit":{"required":false},"injection":Value::Null,"canonical_request":canonical,
            "ecr_signing":{"mode":"exact_request_lease_v1","credential_tuple_released":false},
            "decision_us":u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)}),
        )
    })();
    result.unwrap_or_else(|payload| {
        deny_for_route(
            payload["status_code"].as_u64().unwrap_or(503) as u16,
            "ECR publication is unavailable",
            payload,
            route,
            started,
        )
    })
}

struct SignedLease {
    binding: Value,
    request_binding: String,
    headers: BTreeMap<String, Zeroizing<String>>,
    authority: String,
    body_digest: String,
    body_length: usize,
    expires: u64,
    publication_expires: u64,
    principal_expires: u64,
    monotonic_deadline: Instant,
}
impl SignedLease {
    fn fresh(&self) -> Result<(), &'static str> {
        if now_epoch_ms() >= u128::from(self.expires)
            || now_epoch_ms() >= u128::from(self.publication_expires)
            || now_epoch_ms() >= u128::from(self.principal_expires)
            || Instant::now() >= self.monotonic_deadline
        {
            Err("ecr_signing_lease_expired")
        } else {
            Ok(())
        }
    }
    fn assert_dispatch(&self, request: &reqwest::blocking::Request) -> Result<(), &'static str> {
        self.fresh()?;
        let body = request
            .body()
            .and_then(reqwest::blocking::Body::as_bytes)
            .ok_or("ecr_signed_body_missing")?;
        let url = request.url();
        if request.method() != reqwest::Method::POST
            || url.scheme() != "https"
            || url.host_str() != Some(self.authority.as_str())
            || url.port_or_known_default() != Some(443)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || body.len() != self.body_length
            || sha256_prefixed(body) != self.body_digest
            || request.headers().len() != self.headers.len() + 1
        {
            return Err("ecr_signed_request_changed");
        }
        for (name, value) in request.headers() {
            let expected = if name.as_str() == "content-length" {
                self.body_length.to_string()
            } else {
                self.headers
                    .get(name.as_str())
                    .ok_or("ecr_signed_header_extra")?
                    .to_string()
            };
            if value.as_bytes() != expected.as_bytes() {
                return Err("ecr_signed_header_changed");
            }
        }
        Ok(())
    }
    fn guard(&self) -> ResponseSecretGuard {
        let mut guard = ResponseSecretGuard::default();
        for name in ["authorization", "x-amz-security-token"] {
            if let Some(value) = self.headers.get(name) {
                guard.add_text_encodings(value);
            }
        }
        if let Some(auth) = self.headers.get("authorization") {
            if let Some(key) = auth
                .split("Credential=")
                .nth(1)
                .and_then(|s| s.split('/').next())
            {
                guard.add_text_encodings(key);
            }
            if let Some(signature) = auth.split("Signature=").nth(1) {
                guard.add_text_encodings(signature);
            }
        }
        guard
    }
}
const AAD_FIELDS: &[&str] = &[
    "apiVersion",
    "requestBindingSha256",
    "publicationId",
    "childId",
    "principalId",
    "routeId",
    "credentialId",
    "credentialVersion",
    "policyHash",
    "dataPlaneBinaryDigest",
    "recipientKeyId",
    "recipientNonce",
    "issuedAtEpochMs",
    "expiresAtEpochMs",
    "publicationExpiresAtEpochMs",
];
const CRYPTO_FIELDS: &[&str] = &[
    "serverEphemeralPublicKey",
    "aeadNonce",
    "ciphertext",
    "ciphertextSha256",
];
fn decode(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    let encoded = value[name].as_str().ok_or(ERROR)?;
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ERROR.to_owned())?;
    require(general_purpose::URL_SAFE_NO_PAD.encode(&bytes) == encoded)?;
    Ok(bytes)
}
fn reserve(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    decision: &Value,
    body: &[u8],
) -> Result<SignedLease, String> {
    let started = Instant::now();
    let scope = CredentialLeaseScope::new(
        decision["principal_id"].as_str().ok_or(ERROR)?,
        decision["route_id"].as_str().ok_or(ERROR)?,
        decision["credential_ref"].as_str().ok_or(ERROR)?,
    );
    let principal_expires = u64::try_from(operator_static_preparation::principal_expiry(
        snapshot, &scope,
    )?)
    .map_err(|_| ERROR.to_owned())?;
    let mut private_bytes = Zeroizing::new([0u8; 32]);
    ring_rand::SystemRandom::new()
        .fill(private_bytes.as_mut())
        .map_err(|_| ERROR.to_owned())?;
    let private = X25519StaticSecret::from(*private_bytes);
    let public = X25519PublicKey::from(&private);
    let (nonce_bytes, recipient_nonce) = nonce()?;
    let mut request = binding(
        decision["operation"]["publicationId"]
            .as_str()
            .ok_or(ERROR)?,
        decision["principal_id"].as_str().ok_or(ERROR)?,
        decision["route_id"].as_str().ok_or(ERROR)?,
        decision["credential_ref"].as_str().ok_or(ERROR)?,
        &snapshot.hash,
    );
    request["apiVersion"] = json!("serverware.ecrSigningRequest/v1");
    request["childId"] = json!(child_id()?);
    request["expectedCredentialVersion"] = decision["credential_version"].clone();
    request["dataPlaneBinaryDigest"] = json!(state.binary_digest);
    request["action"] = decision["operation"]["action"].clone();
    request["bodyBase64"] = json!(general_purpose::STANDARD.encode(body));
    request["bodySha256"] = json!(sha256_prefixed(body));
    request["recipientPublicKey"] =
        json!(general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes()));
    request["recipientKeyId"] = json!(sha256_prefixed(public.as_bytes()));
    request["recipientNonce"] = json!(recipient_nonce);
    request["maxTtlSeconds"] = json!(5);
    let request_binding =
        sha256_prefixed(&native_response_profile::canonical_ascii_bytes(&request)?);
    let (status, envelope) = call(state, snapshot, "reserve", &request, &recipient_nonce)?;
    require(status == StatusCode::OK)?;
    let names = AAD_FIELDS
        .iter()
        .chain(CRYPTO_FIELDS)
        .copied()
        .collect::<Vec<_>>();
    require(exact(&envelope, &names))?;
    let mut aad = json!({});
    for name in AAD_FIELDS {
        aad[*name] = envelope[*name].clone();
    }
    require(
        aad["apiVersion"] == "serverware.ecrSigningEnvelope/v1"
            && aad["requestBindingSha256"] == request_binding
            && [
                "publicationId",
                "childId",
                "principalId",
                "routeId",
                "credentialId",
                "policyHash",
                "dataPlaneBinaryDigest",
                "recipientKeyId",
                "recipientNonce",
            ]
            .iter()
            .all(|k| aad[*k] == request[*k])
            && aad["credentialVersion"] == request["expectedCredentialVersion"]
            && aad["publicationExpiresAtEpochMs"] == decision["publication_expires_at_epoch_ms"],
    )?;
    let issued = aad["issuedAtEpochMs"].as_u64().ok_or(ERROR)?;
    let expires = aad["expiresAtEpochMs"].as_u64().ok_or(ERROR)?;
    let publication_expires = aad["publicationExpiresAtEpochMs"].as_u64().ok_or(ERROR)?;
    require(
        expires > issued
            && expires - issued <= 5000
            && u128::from(issued) <= now_epoch_ms() + 1000
            && u128::from(expires) > now_epoch_ms()
            && expires <= publication_expires,
    )?;
    let server: [u8; 32] = decode(&envelope, "serverEphemeralPublicKey")?
        .try_into()
        .map_err(|_| ERROR.to_owned())?;
    let shared = private.diffie_hellman(&X25519PublicKey::from(server));
    require(shared.was_contributory())?;
    let aead_nonce: [u8; 12] = decode(&envelope, "aeadNonce")?
        .try_into()
        .map_err(|_| ERROR.to_owned())?;
    let mut ciphertext = Zeroizing::new(decode(&envelope, "ciphertext")?);
    require(
        ciphertext.len() >= 16
            && ciphertext.len() <= 32768
            && envelope["ciphertextSha256"] == sha256_prefixed(&ciphertext),
    )?;
    let aad_bytes = Zeroizing::new(native_response_profile::canonical_ascii_bytes(&aad)?);
    let mut info = Zeroizing::new(b"serverware:credential-lease-envelope:v2\0".to_vec());
    info.extend_from_slice(&Sha256::digest(&aad_bytes));
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &nonce_bytes);
    let prk = salt.extract(shared.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    prk.expand(&[info.as_slice()], Aes256KeyLength)
        .map_err(|_| ERROR.to_owned())?
        .fill(key.as_mut())
        .map_err(|_| ERROR.to_owned())?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref()).map_err(|_| ERROR.to_owned())?,
    );
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(aead_nonce),
            aead::Aad::from(aad_bytes.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| ERROR.to_owned())?;
    let signed = SensitiveJsonValue::new(
        strict_json_value_from_slice(plaintext).map_err(|_| ERROR.to_owned())?,
    );
    require(
        exact(
            &signed,
            &[
                "apiVersion",
                "method",
                "scheme",
                "authority",
                "path",
                "query",
                "bodySha256",
                "bodyLength",
                "headers",
            ],
        ) && signed["apiVersion"] == "serverware.ecrSignedRequest/v1"
            && signed["method"] == "POST"
            && signed["scheme"] == "https"
            && signed["path"] == "/"
            && signed["query"] == ""
            && signed["bodySha256"] == request["bodySha256"]
            && signed["bodyLength"].as_u64() == Some(body.len() as u64),
    )?;
    let authority = ecr::authority(&decision["operation"])?;
    require(signed["authority"] == authority)?;
    let headers = signed["headers"].as_object().ok_or(ERROR)?;
    let token = headers.contains_key("x-amz-security-token");
    let expected = if token {
        vec![
            "accept",
            "authorization",
            "content-type",
            "host",
            "x-amz-date",
            "x-amz-target",
            "x-amz-security-token",
        ]
    } else {
        vec![
            "accept",
            "authorization",
            "content-type",
            "host",
            "x-amz-date",
            "x-amz-target",
        ]
    };
    require(headers.len() == expected.len() && expected.iter().all(|n| headers.contains_key(*n)))?;
    let mut owned = BTreeMap::new();
    for (name, value) in headers {
        let value = value.as_str().ok_or(ERROR)?;
        require(
            !value.is_empty()
                && value.len() <= 8192
                && value.bytes().all(|b| (0x20..=0x7e).contains(&b)),
        )?;
        owned.insert(name.clone(), Zeroizing::new(value.to_owned()));
    }
    require(
        headers["accept"] == "*/*"
            && headers["content-type"] == ecr::MEDIA
            && headers["host"] == authority
            && headers["x-amz-target"]
                == format!(
                    "AmazonEC2ContainerRegistry_V20150921.{}",
                    request["action"].as_str().ok_or(ERROR)?
                ),
    )?;
    let timestamp = headers["x-amz-date"].as_str().ok_or(ERROR)?;
    let signed_seconds = ecr::sdk_timestamp(timestamp).ok_or(ERROR)?;
    require(signed_seconds.abs_diff(issued / 1000) <= 1)?;
    let auth = headers["authorization"].as_str().ok_or(ERROR)?;
    let prefix = "AWS4-HMAC-SHA256 Credential=";
    let remainder = auth.strip_prefix(prefix).ok_or(ERROR)?;
    let (access, rest) = remainder.split_once('/').ok_or(ERROR)?;
    require(
        access.len() == 20
            && access
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && access != ecr::DUMMY_ACCESS_KEY
            && if token {
                access.starts_with("ASIA")
            } else {
                access.starts_with("AKIA")
            },
    )?;
    let signed_headers = if token {
        "accept;content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
    } else {
        "accept;content-type;host;x-amz-date;x-amz-target"
    };
    let signature_prefix = format!(
        "{}/{}/ecr/aws4_request, SignedHeaders={signed_headers}, Signature=",
        &timestamp[..8],
        decision["operation"]["region"].as_str().ok_or(ERROR)?
    );
    let signature = rest.strip_prefix(&signature_prefix).ok_or(ERROR)?;
    require(
        signature.len() == 64
            && signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    let remaining = u64::try_from(u128::from(expires).saturating_sub(now_epoch_ms()))
        .map_err(|_| ERROR.to_owned())?;
    let lease = SignedLease {
        binding: request,
        request_binding,
        headers: owned,
        authority,
        body_digest: sha256_prefixed(body),
        body_length: body.len(),
        expires,
        publication_expires,
        principal_expires,
        monotonic_deadline: (Instant::now() + Duration::from_millis(remaining))
            .min(started + Duration::from_secs(5)),
    };
    lease.fresh().map_err(str::to_owned)?;
    Ok(lease)
}
fn finish(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    lease: &SignedLease,
    response: Option<(StatusCode, &[u8])>,
) -> Result<Value, String> {
    let mut request = binding(
        lease.binding["publicationId"].as_str().ok_or(ERROR)?,
        lease.binding["principalId"].as_str().ok_or(ERROR)?,
        lease.binding["routeId"].as_str().ok_or(ERROR)?,
        lease.binding["credentialId"].as_str().ok_or(ERROR)?,
        &snapshot.hash,
    );
    request["apiVersion"] = json!("serverware.ecrFinishRequest/v1");
    request["childId"] = lease.binding["childId"].clone();
    request["requestBindingSha256"] = json!(lease.request_binding);
    request["expectedCredentialVersion"] = lease.binding["expectedCredentialVersion"].clone();
    request["outcome"] = json!(if response.is_some() {
        "response"
    } else {
        "unknown"
    });
    let response_digest = response.map(|(_, b)| sha256_prefixed(b));
    if let Some((status, body)) = response {
        request["statusCode"] = json!(status.as_u16());
        request["responseBodyBase64"] = json!(general_purpose::STANDARD.encode(body));
    }
    let (_, response_nonce) = nonce()?;
    let (status, receipt) = call(state, snapshot, "finish", &request, &response_nonce)?;
    require(
        status == StatusCode::OK
            && exact(
                &receipt,
                &[
                    "apiVersion",
                    "publicationId",
                    "childId",
                    "requestBindingSha256",
                    "principalId",
                    "routeId",
                    "credentialId",
                    "credentialVersion",
                    "policyHash",
                    "requestBodySha256",
                    "responseBodySha256",
                    "status",
                    "revision",
                    "acknowledged",
                    "responseReleaseAllowed",
                ],
            )
            && receipt["apiVersion"] == "serverware.ecrFinishResponse/v1"
            && [
                "publicationId",
                "childId",
                "requestBindingSha256",
                "principalId",
                "routeId",
                "credentialId",
                "policyHash",
            ]
            .iter()
            .all(|k| receipt[*k] == request[*k])
            && receipt["credentialVersion"] == request["expectedCredentialVersion"]
            && receipt["requestBodySha256"] == lease.body_digest
            && receipt["responseBodySha256"] == json!(response_digest)
            && receipt["revision"].as_u64().is_some()
            && receipt["status"].as_str().is_some_and(|s| {
                matches!(
                    s,
                    "active" | "published" | "failed" | "uncertain" | "expired"
                )
            })
            && receipt["acknowledged"].is_boolean(),
    )?;
    require(
        receipt["responseReleaseAllowed"].is_boolean()
            && (receipt["responseReleaseAllowed"] != true
                || receipt["acknowledged"] == true
                    && matches!(receipt["status"].as_str(), Some("active" | "published"))),
    )?;
    Ok(receipt.into_value())
}

fn ack_releasable(lease: &SignedLease, receipt: &Value) -> bool {
    receipt["acknowledged"] == true
        && receipt["responseReleaseAllowed"] == true
        && now_epoch_ms() < u128::from(lease.principal_expires)
        && now_epoch_ms() < u128::from(lease.publication_expires)
}
fn failed(state: &GateState, decision: &Value, url: &Url, stage: &str) -> SensitiveResponseBytes {
    enqueue_audit(
        state,
        "data_plane.ecr_publication.outcome_unknown",
        decision_audit_event(
            decision,
            "POST",
            url,
            "outcome_unknown",
            json!({"stage":stage,"automatic_retry":false}),
        ),
    );
    json_status_response(StatusCode::BAD_GATEWAY,json!({"error":UNKNOWN,"automatic_retry":false,
        "instruction":"Inspect this publication before any further request; do not automatically replay."})).into()
}
pub(super) fn forward(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    decision: &Value,
    mut request: IncomingRequest,
    prepared: PreparedUpstream,
    url: &Url,
) -> SensitiveResponseBytes {
    let _slot = match Slot::acquire() {
        Ok(slot) => slot,
        Err(_) => {
            return json_status_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"ecr_publication_busy"}),
            )
            .into()
        }
    };
    if ordinary(state, snapshot).is_err() {
        return failed(state, decision, url, "preparation");
    }
    let lease = match reserve(state, snapshot, decision, &request.body) {
        Ok(lease) => lease,
        Err(_) => return failed(state, decision, url, "signing_lease"),
    };
    let guard = lease.guard();
    let mut builder = prepared.client.post(url.as_str());
    for (name, value) in &lease.headers {
        builder = builder.header(name, value.as_str());
    }
    builder = builder
        .header("content-length", lease.body_length)
        .body(std::mem::take(&mut request.body));
    let deadlines = UpstreamSendDeadlines {
        reservation_expires_at_epoch_ms: Some(lease.publication_expires),
        dispatch_expires_at_epoch_ms: Some(lease.expires),
        policy_expires_at_epoch_ms: Some(lease.principal_expires),
    };
    let sent = send_upstream_request_with_final_check(
        state,
        snapshot,
        None,
        builder,
        Some(Duration::from_secs(5)),
        deadlines,
        false,
        None,
        |built| lease.assert_dispatch(built),
        |_| Ok(None),
        || lease.fresh(),
    );
    let mut response = match sent {
        Ok(response) => response,
        Err(_) => {
            let _ = finish(state, snapshot, &lease, None);
            return failed(state, decision, url, "dispatch");
        }
    };
    let status = response.status();
    let route = match decision_route_context(snapshot, decision, "POST", url) {
        Ok(m) => m.route,
        Err(_) => {
            let _ = finish(state, snapshot, &lease, None);
            return failed(state, decision, url, "route_currentness");
        }
    };
    let headers = match response_metadata::prepare(response.headers(), &route.constraints, &guard) {
        Ok(headers) => headers,
        Err(_) => {
            let _ = finish(state, snapshot, &lease, None);
            return failed(state, decision, url, "response_metadata");
        }
    };
    let limit = if status == StatusCode::OK {
        ecr::RESPONSE_BYTES
    } else {
        ecr::ERROR_BYTES
    };
    let mut body = SensitiveResponseBytes::with_capacity(16384);
    if (&mut response)
        .take(limit + 1)
        .read_to_end(&mut body)
        .is_err()
        || body.len() as u64 > limit
        || validate_response_envelopes(
            route,
            status,
            &headers,
            Some(body.len() as u64),
            decision.get("operation"),
        )
        .is_err()
    {
        let _ = finish(state, snapshot, &lease, None);
        return failed(state, decision, url, "response_body");
    }
    let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());
    let body = match ecr::inspect_response(
        url,
        status,
        content_type,
        &ecr::response_profile(status != StatusCode::OK),
        &decision["operation"],
        body,
        &guard,
    ) {
        Ok(body) => body,
        Err(_) => {
            let _ = finish(state, snapshot, &lease, None);
            return failed(state, decision, url, "response_validation");
        }
    };
    let receipt = match finish(state, snapshot, &lease, Some((status, &body))) {
        Ok(receipt) => receipt,
        Err(_) => return failed(state, decision, url, "acknowledgment_commit"),
    };
    if status != StatusCode::OK || receipt["acknowledged"] != true {
        return failed(state, decision, url, "provider_outcome");
    }
    // Retain the provider observation durably before the existing fresh client
    // response-release barrier. Recording an ACK never overrides revocation.
    enqueue_audit(
        state,
        "data_plane.ecr_publication.acknowledged",
        decision_audit_event(
            decision,
            "POST",
            url,
            "acknowledged",
            json!({"publication_status":receipt["status"],"publication_revision":receipt["revision"],
            "response_body_sha256":sha256_prefixed(&body),"response_body_bytes":body.len(),"automatic_retry":false}),
        ),
    );
    if !ack_releasable(&lease, &receipt) {
        enqueue_audit(
            state,
            "data_plane.ecr_publication.response_refused",
            decision_audit_event(
                decision,
                "POST",
                url,
                "refused",
                json!({"provider_outcome":"acknowledged","publication_status":receipt["status"],"automatic_retry":false}),
            ),
        );
        return json_status_response(StatusCode::BAD_GATEWAY,json!({"error":"ecr_publication_response_refused",
            "providerOutcome":"acknowledged","retryProviderRequest":false,
            "instruction":"The provider acknowledgment was recorded. Inspect this publication; do not replay the request."})).into();
    }
    release_forward_response(
        state,
        snapshot,
        decision,
        "POST",
        url,
        status,
        Some(ecr::MEDIA),
        &SensitiveReleasedHeaders::default(),
        body,
        &guard,
        json!({"ok":true,"mode":ecr::MODE,"adapter":ecr::ADAPTER,"body_bytes_preserved":true,
            "publication_status":receipt["status"],"publication_revision":receipt["revision"],"acknowledged":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ecr_exact_dispatch_and_final_freshness() {
        let body = br#"{"registryId":"123456789012","repositoryName":"example/app"}"#;
        let authority = "api.ecr.us-east-1.amazonaws.com";
        let headers = BTreeMap::from([
            ("accept".to_owned(), Zeroizing::new("*/*".to_owned())),
            ("host".to_owned(), Zeroizing::new(authority.to_owned())),
            (
                "content-type".to_owned(),
                Zeroizing::new(ecr::MEDIA.to_owned()),
            ),
            (
                "authorization".to_owned(),
                Zeroizing::new("synthetic-exact-header".to_owned()),
            ),
        ]);
        let now = u64::try_from(now_epoch_ms()).unwrap();
        let mut lease = SignedLease {
            binding: json!({}),
            request_binding: "synthetic".into(),
            headers,
            authority: authority.into(),
            body_digest: sha256_prefixed(body),
            body_length: body.len(),
            expires: now + 5000,
            publication_expires: now + 10000,
            principal_expires: now + 10000,
            monotonic_deadline: Instant::now() + Duration::from_secs(5),
        };
        let client = Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .build()
            .unwrap();
        let mut builder = client
            .post(format!("https://{authority}/"))
            .body(body.to_vec())
            .header("content-length", body.len());
        for (name, value) in &lease.headers {
            builder = builder.header(name, value.as_str());
        }
        let mut request = builder.build().unwrap();
        lease.assert_dispatch(&request).unwrap();
        request
            .headers_mut()
            .insert("user-agent", HeaderValue::from_static("unexpected"));
        assert!(lease.assert_dispatch(&request).is_err());
        request.headers_mut().remove("user-agent");
        *request.body_mut() = Some(reqwest::blocking::Body::from(b"changed".to_vec()));
        assert!(lease.assert_dispatch(&request).is_err());
        lease.monotonic_deadline = Instant::now() - Duration::from_millis(1);
        assert!(lease.fresh().is_err());
        lease.monotonic_deadline = Instant::now() + Duration::from_secs(5);
        let allowed = json!({"acknowledged":true,"responseReleaseAllowed":true});
        assert!(ack_releasable(&lease, &allowed));
        assert!(!ack_releasable(
            &lease,
            &json!({"acknowledged":true,"responseReleaseAllowed":false})
        ));
        lease.principal_expires = now - 1;
        assert!(lease.fresh().is_err());
        assert!(!ack_releasable(&lease, &allowed));
        lease.principal_expires = now + 10000;
        lease.publication_expires = now - 1;
        assert!(!ack_releasable(&lease, &allowed));
    }
}
