//! Separately cold-assigned protected-review ownership. Only an actual custody
//! runtime constructs Owner. Private bytes never leave it before a purpose-bound
//! definite-commit acknowledgment; neither sealing nor a portal verdict opens it.
use crate::{enclave_runtime_identity_v1::{CredentialRecipientV1, EnclaveRuntimeIdentityV1},
    native_secret_broker_v1 as broker, native_currentness_v1 as current,
    native_oauth_exchange_v1::BrowserTls, native_response_profile_v1::canonical_ascii_bytes};
use crate::native_jit_review_browser_v1::{self as browser, Accepted, Kind};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use zeroize::Zeroizing;

#[path = "native_jit_review_open_policy.rs"]
mod policy;
#[path = "native_jit_review_open_wire.rs"]
mod wire;
pub use policy::Configuration;
pub const MAX_ASSIGNMENT: usize = 64 * 1024;
pub const SIGNED_ASSIGNMENT: &str = "catchplate.signedNativeJitReviewOpeningAssignment/v1";
const SOURCE_CONTRACT_DIGEST: &str = "sha256:ed6d471a03516c96aa4968b89e4d220f9d5aaa0dfc4c1f848acfcc58343de4f0";
pub(crate) const CHALLENGE_SCHEMA: &str = "catchplate.nativeJitReviewOpeningChallenge/v1";
pub(crate) const PREPARATION_SCHEMA: &str = "catchplate.nativeJitReviewOpeningPreparation/v1";
pub(crate) const NATIVE_FIELDS: &[&str] = &["holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest"];
pub(crate) fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native protected review unavailable".into()) }
}
pub(crate) fn fields(v: &Value, names: &[&str]) -> Result<(), String> {
    require(v.as_object().is_some_and(|o| o.len() == names.len() && names.iter().all(|name| o.contains_key(*name))))
}
pub(crate) fn sha(raw: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(raw))) }
pub(crate) fn clocks() -> Result<(u64, u64), String> {
    let boot = broker::now()?;
    let wall = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "review clock")?.as_nanos())
        .map_err(|_| "review clock width")?;
    require(boot > 0 && wall > 0 && wall <= i64::MAX as u64)?; Ok((wall, boot))
}
fn nonce() -> Result<String, String> {
    let mut raw = [0u8; 32]; SystemRandom::new().fill(&mut raw).map_err(|_| "review entropy")?;
    require(raw != [0; 32])?; Ok(URL_SAFE_NO_PAD.encode(raw))
}
fn id() -> Result<String, String> {
    let mut raw = [0u8; 16]; SystemRandom::new().fill(&mut raw).map_err(|_| "review identity entropy")?;
    raw[6] = (raw[6] & 15) | 64; raw[8] = (raw[8] & 63) | 128;
    let text = hex::encode(raw); Ok(format!("{}-{}-{}-{}-{}", &text[..8], &text[8..12], &text[12..16], &text[16..20], &text[20..]))
}
fn text<'a>(v: &'a Value, name: &str, maximum: usize) -> Result<&'a str, String> {
    let result = v[name].as_str().ok_or("review literal absent")?;
    require(!result.is_empty() && result.len() <= maximum)?; Ok(result)
}
fn attempt_capacity(count: usize, limit: u64) -> Result<(), String> {
    require((1..=16).contains(&limit) && count < limit as usize)
}

// Cross-connection state is independent of Transport's per-socket write fence.
// Replacing a state with Spent occurs before any uncertain broker/write work.
enum Phase {
    Issuing { recipient: CredentialRecipientV1, statement: Value },
    Challenged { recipient: CredentialRecipientV1, original: String, statement: Value },
    Prepared { view: Zeroizing<Vec<u8>>, statement: Value, proof_sha: Option<String> },
    Spent,
}
struct Attempt {
    marker: Arc<()>, nonce: Zeroizing<String>, expires: u64, deadline: u64, phase: Phase,
}
impl Attempt {
    fn authenticate(&self, marker: &Arc<()>, cookie: &str, wall: u64, boot: u64) -> Result<(), String> {
        require(Arc::ptr_eq(marker, &self.marker) && cookie.len() == self.nonce.len()
            && ring::constant_time::verify_slices_are_equal(cookie.as_bytes(), self.nonce.as_bytes()).is_ok()
            && wall < self.expires && boot < self.deadline)
    }
    fn consume(&mut self) -> Phase { std::mem::replace(&mut self.phase, Phase::Spent) }
}

// Only pre-authority validation and socket output use this local result.
// Actual retained custody checks, signing and broker work remain Result errors.
pub(crate) enum RequestOutcome<T> { Ready(T), Refused }
impl<T> RequestOutcome<T> {
    pub(crate) fn local(result: Result<T, String>) -> Self {
        match result { Ok(value) => Self::Ready(value), Err(_) => Self::Refused }
    }
}
#[derive(Default)]
struct ServiceFence { poisoned: bool }
impl ServiceFence {
    fn check(&self) -> Result<(), String> { require(!self.poisoned) }
    fn poison(&mut self) { self.poisoned = true; }
}
pub(crate) struct Preparation {
    id: String, marker: Arc<()>, recipient: CredentialRecipientV1, salt: [u8;32],
    command: Value, authorization_sha: String, scope: Value, expires: u64, deadline: u64,
}
pub(crate) struct Disclosure {
    id: String, marker: Arc<()>, view: Zeroizing<Vec<u8>>, expires: u64, deadline: u64,
}

/// No caller-supplied keys, deserialization, Clone, or plaintext getter.
pub struct Owner {
    config: Configuration, assignment: policy::Admission, ingress: Arc<BrowserTls>,
    marker: Arc<()>, identity: Value, owner_scope: String, attempts: BTreeMap<String, Attempt>,
    preparations: usize, pid: u32, last_wall: u64, last_boot: u64, fence: ServiceFence,
}
impl Owner {
    pub(crate) fn configure(config: Configuration, original: &[u8], broker: &mut broker::Owner,
        identity: &mut EnclaveRuntimeIdentityV1, boot: &str, key: &str, cp: &str, binary: &str,
        deadline: u64) -> Result<Self, String> {
        let assignment = policy::admit(&config, original, identity, boot, key, cp, binary, deadline)?;
        let ingress = identity.prepare_browser_ingress(config.native_origin(), time::OffsetDateTime::now_utc(), deadline)?;
        identity.verify_browser_ingress(&ingress, deadline)?;
        let configuration = config.broker_configuration(&assignment.original)?;
        let owner_scope = sha(&canonical_ascii_bytes(&configuration)?);
        let marker = broker.configure_jit_review_open(configuration, Arc::clone(&ingress), identity, deadline)?;
        let mut native = serde_json::Map::new();
        for name in NATIVE_FIELDS { native.insert((*name).into(), assignment.assignment[*name].clone()); }
        native.insert("browserCertificateSha256".into(), json!(ingress.certificate_sha));
        native.insert("browserPublicKeySpkiSha256".into(), json!(ingress.spki_sha));
        let (wall, mono) = clocks()?;
        let mut result = Self { config, assignment, ingress, marker, identity: Value::Object(native), owner_scope,
            attempts: BTreeMap::new(), preparations: 0, pid: std::process::id(), last_wall: wall, last_boot: mono, fence: ServiceFence::default() };
        result.check(broker, identity, deadline)?; Ok(result)
    }
    pub fn browser_vsock_port(&self) -> u32 { self.config.browser_vsock_port() }
    pub fn browser_ingress(&self) -> Arc<BrowserTls> { Arc::clone(&self.ingress) }
    pub(crate) fn assignment_original(&self) -> &str { &self.assignment.original }
    pub(crate) fn identity(&self) -> &Value { &self.identity }
    pub(crate) fn deadline(&self, requested: u64) -> u64 { requested.min(self.assignment.deadline) }
    pub(crate) fn check(&mut self, broker: &mut broker::Owner, identity: &mut EnclaveRuntimeIdentityV1,
        deadline: u64) -> Result<(), String> {
        let result = (|| {
            self.fence.check()?; require(self.pid == std::process::id())?;
            self.assignment.check()?; identity.verify_browser_ingress(&self.ingress, deadline)?;
            require(Arc::ptr_eq(&self.marker, &broker.jit_review_open_marker(identity, &self.ingress, deadline)?))?;
            let scope = identity.refresh_scope(deadline)?;
            for name in ["releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256"] {
                require(scope[name] == self.identity[name])?;
            }
            let (wall, boot) = clocks()?;
            require(wall >= self.last_wall && boot >= self.last_boot && boot < deadline)?;
            self.last_wall = wall; self.last_boot = boot; Ok(())
        })();
        if result.is_err() { self.poison(); } result
    }
    pub(crate) fn poison(&mut self) { self.fence.poison(); self.attempts.clear(); }
    pub(crate) fn discard_attempt(&mut self, id: &str) {
        if let Some(item) = self.attempts.get_mut(id) { item.consume(); }
    }
    pub(crate) fn require_request(&self, request: &Accepted) -> Result<(), String> {
        self.fence.check()?; request.verify_ingress(&self.ingress)
    }
    pub(crate) fn page(&self, request: &mut Accepted) -> Result<(), String> {
        self.require_request(request)?; require(request.kind() == Kind::Page)?;
        let (page, csp) = browser::page(self.config.portal_origin())?;
        request.respond("text/html; charset=utf-8", &page, None, &csp)
    }
    pub(crate) fn begin_challenge(&mut self, request: &mut Accepted) -> Result<(String, Value), String> {
        self.require_request(request)?; require(request.kind() == Kind::Challenge)?;
        let input = request.input()?; let approval = text(&input, "approvalRequestId", 128)?;
        require(approval.trim() == approval && !approval.chars().any(char::is_control))?;
        let (wall, boot) = clocks()?;
        self.attempts.retain(|_, item| wall < item.expires && boot < item.deadline);
        let capacity = self.config.policy()["attemptCapacity"].as_u64().ok_or("review capacity")?;
        attempt_capacity(self.attempts.len(), capacity)?;
        attempt_capacity(self.preparations, capacity)?;
        let interval = self.config.policy()["operationMaxSeconds"].as_u64().ok_or("review window")?
            .checked_mul(1_000_000_000).ok_or("review window overflow")?;
        let expires = wall.checked_add(interval).ok_or("review expiry overflow")?.min(self.assignment.expires);
        let deadline = boot.checked_add(expires.checked_sub(wall).ok_or("review expiry")?).ok_or("review clock overflow")?
            .min(self.assignment.deadline).min(request.deadline());
        require(boot < deadline)?;
        let expires = expires.min(wall.checked_add(deadline - boot).ok_or("review wall overflow")?);
        // Signing and the public challenge write share this retained attempt's
        // cap, not merely the potentially wider original accepted-socket cap.
        request.narrow_deadline(deadline)?;
        let review_id = id()?; require(!self.attempts.contains_key(&review_id))?;
        let cookie = Zeroizing::new(nonce()?); let recipient = CredentialRecipientV1::generate()?;
        let statement = json!({"schema":CHALLENGE_SCHEMA,"reviewId":review_id,"approvalRequestId":approval,
            "sourceContractDigest":SOURCE_CONTRACT_DIGEST,"controlPlaneConfigurationDigest":self.config.configuration_digest(),
            "openingAssignmentSha256":sha(self.assignment.original.as_bytes()),"ownerScopeDigest":self.owner_scope,
            "identity":self.identity,"nativeOrigin":self.config.native_origin(),"portalOrigin":self.config.portal_origin(),
            "browserNonceCommitment":sha(cookie.as_bytes()),"recipientPublicKey":URL_SAFE_NO_PAD.encode(recipient.public_key_bytes()?),
            "challenge":nonce()?,"issuedAtEpochNs":wall,"expiresAtEpochNs":expires});
        self.attempts.insert(review_id.clone(), Attempt { marker: Arc::clone(&self.marker), nonce: cookie, expires, deadline,
            phase: Phase::Issuing { recipient, statement: statement.clone() } });
        Ok((review_id, statement))
    }
    pub(crate) fn finish_challenge(&mut self, id: &str, original: String, request: &mut Accepted) -> Result<(), String> {
        self.require_request(request)?;
        let (wall, boot) = clocks()?;
        let item = self.attempts.get_mut(id).ok_or("review attempt absent")?;
        require(wall < item.expires && boot < item.deadline)?;
        let Phase::Issuing { recipient, statement } = item.consume() else { return Err("review challenge spent".into()); };
        // Cookie transport uses whole seconds; round upward so an admitted
        // one-second window is usable. Exact wall/BOOTTIME gates still decide.
        let remaining = (item.expires - wall).div_ceil(1_000_000_000);
        let cookie = browser::cookie(id, &item.nonce, remaining)?;
        let response = canonical_ascii_bytes(&json!({"apiVersion":"catchplate.nativeJitReviewChallengeResponse/v1","challengeOriginal":original}))?;
        item.phase = Phase::Challenged { recipient, original, statement };
        let result = request.respond("application/json", &response, Some(&cookie), "default-src 'none'; frame-ancestors 'none'");
        if result.is_err() { item.consume(); } result
    }
    pub(crate) fn plan_preparation(&mut self, request: &mut Accepted) -> Result<Preparation, String> {
        self.require_request(request)?; require(request.kind() == Kind::Prepare)?;
        // The broker retains a finite lifetime replay ledger. Exhaustion is
        // known locally and must never become a fatal private-channel request.
        attempt_capacity(self.preparations, self.config.policy()["attemptCapacity"].as_u64().ok_or("review capacity")?)?;
        let input = request.input()?; let id = text(&input, "reviewId", 128)?.to_owned();
        let (wall, boot) = clocks()?;
        let item = self.attempts.get_mut(&id).ok_or("review attempt absent")?;
        item.authenticate(&self.marker, request.cookie(&id)?, wall, boot)?;
        let Phase::Challenged { recipient, original, statement: challenge } = item.consume() else { return Err("review preparation spent".into()); };
        let authorization = text(&input, "authorizationOriginal", 64 * 1024)?;
        let grant = wire::authority(authorization, self.config.policy(), false, wall)?;
        wire::grant_join(&grant, &challenge, &original, &input, self.assignment.expires)?;
        let expires = wire::integer(&grant["expiresAtEpochNs"])?;
        require(expires <= item.expires && expires > wall)?;
        let deadline = item.deadline.min(request.deadline()).min(boot.checked_add(expires-wall).ok_or("review grant clock")?);
        request.narrow_deadline(deadline)?;
        let command = json!({"apiVersion":"catchplate.nativeJitReviewOpenChannel/v1","phase":"prepare",
            "challengeOriginal":original,"authorizationOriginal":authorization,
            "parentOriginal":text(&input,"parentOriginal",512*1024)?,"childOriginal":text(&input,"childOriginal",512*1024)?,
            "pairOriginal":text(&input,"pairOriginal",1024*1024)?,"evidenceOriginal":text(&input,"proofOriginal",128*1024)?,
            "deadlineBoottimeNs":deadline});
        let plan = Preparation { id, marker: Arc::clone(&self.marker), recipient,
            salt: current::bytes32(text(&challenge,"challenge",64)?)?, command,
            authorization_sha: sha(authorization.as_bytes()), scope: grant["scope"].clone(), expires, deadline };
        request.check()?;
        self.preparations += 1;
        Ok(plan)
    }
    pub(crate) fn prepare(&mut self, plan: Preparation, broker: &mut broker::Owner,
        identity: &mut EnclaveRuntimeIdentityV1) -> Result<(String, Value), String> {
        require(Arc::ptr_eq(&self.marker, &plan.marker))?;
        let item = self.attempts.get_mut(&plan.id).ok_or("review attempt absent")?;
        require(matches!(item.phase, Phase::Spent))?;
        let view = broker.prepare_jit_review_open(identity, &self.ingress, &plan.command, plan.recipient,
            plan.salt, plan.deadline)?;
        require(!view.is_empty() && view.len() <= 256*1024 && std::str::from_utf8(&view).is_ok())?;
        wire::review_digest_join(&plan.command, &view)?;
        let (prepared, mono) = clocks()?; require(prepared < plan.expires && mono < plan.deadline)?;
        let statement = json!({"schema":PREPARATION_SCHEMA,"operation":"nativeJitReviewOpen.prepare/v1",
            "authorizationSha256":plan.authorization_sha,"scope":plan.scope,"identity":self.identity,
            "reviewDigest":sha(&view),"reviewFormat":"catchplate.nativeJitImmutableReview/v1",
            "preparedAtEpochNs":prepared,"expiresAtEpochNs":plan.expires});
        item.expires = plan.expires; item.deadline = plan.deadline;
        item.phase = Phase::Prepared { view, statement: statement.clone(), proof_sha: None };
        Ok((plan.id, statement))
    }
    pub(crate) fn finish_preparation(&mut self, id: &str, original: String, request: &mut Accepted) -> Result<(), String> {
        self.require_request(request)?;
        let (wall, boot) = clocks()?;
        let item = self.attempts.get_mut(id).ok_or("review attempt absent")?;
        item.authenticate(&self.marker, request.cookie(id)?, wall, boot)?;
        let Phase::Prepared { proof_sha, .. } = &mut item.phase else { return Err("review preparation missing".into()); };
        require(proof_sha.is_none())?; *proof_sha = Some(sha(original.as_bytes()));
        let response = canonical_ascii_bytes(&json!({"apiVersion":"catchplate.nativeJitReviewPreparationResponse/v1","preparationOriginal":original}))?;
        let result = request.respond("application/json", &response, None, "default-src 'none'; frame-ancestors 'none'");
        if result.is_err() { item.consume(); } result
    }
    pub(crate) fn plan_disclosure(&mut self, request: &mut Accepted) -> Result<Disclosure, String> {
        self.require_request(request)?; require(request.kind() == Kind::Disclose)?;
        let input = request.input()?; let id = text(&input, "reviewId", 128)?;
        let (wall, boot) = clocks()?;
        let item = self.attempts.get_mut(id).ok_or("review attempt absent")?;
        item.authenticate(&self.marker, request.cookie(id)?, wall, boot)?;
        // Cross-connection attempt becomes terminal before ACK processing or
        // private output. Invalid/uncertain acknowledgment never restores it.
        let Phase::Prepared { view, statement, proof_sha: Some(proof_sha) } = item.consume()
            else { return Err("review disclosure spent".into()); };
        let ack = wire::authority(text(&input,"commitAckOriginal",64*1024)?, self.config.policy(), true, wall)?;
        wire::ack_join(&ack, &statement, &proof_sha)?;
        let expires = wire::integer(&ack["expiresAtEpochNs"])?;
        require(expires <= item.expires)?;
        let (wall, boot) = clocks()?; require(wall < expires && boot < item.deadline)?;
        let deadline = item.deadline.min(request.deadline()).min(boot.checked_add(expires-wall).ok_or("review ACK clock")?);
        request.narrow_deadline(deadline)?;
        Ok(Disclosure { id: id.to_owned(), marker: Arc::clone(&self.marker), view, expires, deadline })
    }
    pub(crate) fn disclose(&mut self, plan: Disclosure, request: &mut Accepted) -> Result<(), String> {
        self.require_request(request)?;
        require(Arc::ptr_eq(&self.marker, &plan.marker))?;
        let item = self.attempts.get(&plan.id).ok_or("review attempt absent")?;
        let (wall, boot) = clocks()?;
        item.authenticate(&self.marker, request.cookie(&plan.id)?, wall, boot)?;
        require(matches!(item.phase, Phase::Spent) && wall < plan.expires && boot < plan.deadline)?;
        // View is the exact immutable broker-produced JSON whose bytes were
        // signed before commit. No history lookup or rerender occurs here.
        request.respond("application/json", &plan.view, None, "default-src 'none'; frame-ancestors 'none'")
    }
}

#[cfg(test)]
#[path = "native_jit_review_open_tests.rs"]
mod tests;
