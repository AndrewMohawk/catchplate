//! Closed, bounded observations after operator-static admission; never authority.
//! Original errors are classified but never formatted, copied into a record, or
//! replaced. A failed diagnostic write cannot change the preparation result.
use super::{digest_json, is_sha256_digest, CredentialLeaseScope, GateState, ReleaseProfile, Snapshot};
use serde_json::json;
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

const LIMIT: usize = 64;
static RECORDS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    AdmissionDeadline, GenerationLookup, GenerationRefresh, GenerationMargin,
    Binding, PairBeforeSecret, SecretRefresh, FinalAdmission, FinalPair, FinalDeadline,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::AdmissionDeadline => "admission_deadline",
            Self::GenerationLookup => "generation_lookup",
            Self::GenerationRefresh => "generation_refresh",
            Self::GenerationMargin => "generation_margin",
            Self::Binding => "binding",
            Self::PairBeforeSecret => "pair_before_secret",
            Self::SecretRefresh => "secret_refresh",
            Self::FinalAdmission => "final_admission",
            Self::FinalPair => "final_pair",
            Self::FinalDeadline => "final_deadline",
        }
    }
}

fn error_code(error: &str) -> &'static str {
    match error {
        "operator static credential preparation unavailable" => "static_preparation_unavailable",
        "credential lease singleflight timed out" => "singleflight_timeout",
        "operator background credential renewal unavailable" => "background_renewal_unavailable",
        "operator publication coordination refused" => "publication_coordination_refused",
        "operator publication coordination deadline expired" => "publication_coordination_deadline",
        "custody I/O deadline exceeded during native credential original operation"
        | "custody I/O deadline exceeded during credential original request" => "operation_deadline",
        "currentness drain exceeded its original deadline; no acknowledgement" => "cache_admission_deadline",
        "credential lease response has an invalid Content-Length"
        | "credential lease response Content-Length does not match the streamed body" => "response_body_contract",
        "credential lease response statement parse failed" => "response_statement_parse",
        "credential lease response context mismatch" => "response_context_mismatch",
        "credential lease response statement binding mismatch"
        | "credential lease response request binding mismatch" => "response_binding_mismatch",
        "credential lease response statement is outside the clock window" => "response_clock_window",
        "credential lease response signing key is not attested" => "response_signing_key",
        "parse_credential_lease_envelope" | "parse_credential_lease_envelope_contract"
        | "credential lease envelope does not match its exact versioned shape" => "envelope_decode",
        "credential lease envelope binding or expiry mismatch" => "envelope_binding_or_expiry",
        "credential lease AEAD authentication failed" => "envelope_authentication",
        "parse_decrypted_credential_lease_set" | "parse_decrypted_credential_lease_set_contract" => "material_decode",
        "decrypted credential lease set binding mismatch" => "material_binding_mismatch",
        "credential lease expired during verification" => "material_expired",
        "credential lease metadata digest mismatch" => "metadata_digest_mismatch",
        "credential generation binding or expiry is invalid" => "generation_cache_invalid",
        "credential lease metadata or expiry is invalid" => "secret_cache_invalid",
        "credential generation owner profile changed before caching" => "generation_profile_changed",
        "credential generation cache capacity exhausted" => "generation_cache_capacity",
        "credential lease cache capacity exhausted" => "secret_cache_capacity",
        "credential secret lease generation is stale or invalid" => "secret_generation_stale",
        "dispatch secret fetch credential generation is stale or invalid" => "dispatch_generation_stale_before_fetch",
        "operator static release generation changed before secret fetch" => "static_release_generation_pin_changed",
        "credential secret lease has no cached generation"
        | "dispatch secret fetch requires a cached credential generation" => "generation_cache_missing",
        "credential generation or metadata changed during secret fetch" => "generation_changed_during_secret_fetch",
        "credential lease version regression rejected" => "version_regression",
        "credential metadata changed without a version increment" => "metadata_changed_same_version",
        "credential lease semantics changed without a version increment" => "lease_semantics_changed_same_version",
        "credential provider metadata does not match signed policy"
        | "credential subject metadata does not match signed policy"
        | "runtime route credential binding is inconsistent"
        | "static credential scopes metadata does not exactly match signed policy"
        | "static credential class metadata does not match route binding" => "runtime_binding_mismatch",
        "policy snapshot changed while credential lease was fetched"
        | "policy snapshot changed before credential generation caching"
        | "policy snapshot changed before credential lease caching"
        | "policy snapshot was revoked before credential lease refresh" => "snapshot_changed",
        _ if error.starts_with("fetch credential leases: ") => "fetch_transport",
        _ if error.starts_with("read credential lease response: ") => "response_body_read",
        _ if error.starts_with("credential lease response exceeds ") => "response_body_bound",
        _ if error.starts_with("credential lease response signature verification failed: ") => "response_signature",
        _ if error.starts_with("credential lease response ") => "response_authentication_other",
        _ if error.starts_with("credential lease control plane returned HTTP ") => "response_http_status",
        _ if error.starts_with("decode credential lease server public key: ")
            || error.starts_with("decode credential lease AEAD nonce: ")
            || error.starts_with("decode credential lease ciphertext: ") => "envelope_decode",
        _ => "other",
    }
}

pub(super) struct Attempt<'a> {
    enabled: bool,
    snapshot: &'a Snapshot,
    scope: &'a CredentialLeaseScope,
}

impl<'a> Attempt<'a> {
    /// The caller has already obtained `admitted(...) == true`. This redundant
    /// local exclusion protects logging, not admission, and performs no probes.
    pub(super) fn after_admission(state: &GateState, snapshot: &'a Snapshot, scope: &'a CredentialLeaseScope) -> Self {
        Self { enabled: state.policy_shadow.is_operator_demo() && !state.is_production
            && state.response_proof_signer.release_profile() == ReleaseProfile::Legacy, snapshot, scope }
    }

    pub(super) fn observe<T>(&self, stage: Stage, result: Result<T, String>) -> Result<T, String> {
        #[cfg(test)]
        if let Some(capture) = TEST_CAPTURE.with(|slot| slot.borrow().clone()) {
            return self.observe_with(stage, result, &capture.counter, |line| {
                if capture.fail_write { return Err(io::ErrorKind::BrokenPipe.into()); }
                capture.lines.borrow_mut().push(String::from_utf8(line.to_vec()).unwrap());
                Ok(())
            });
        }
        self.observe_with(stage, result, &RECORDS, |line| io::stderr().lock().write_all(line))
    }

    fn observe_with<T>(&self, stage: Stage, result: Result<T, String>, counter: &AtomicUsize,
        sink: impl FnOnce(&[u8]) -> io::Result<()>) -> Result<T, String> {
        if self.enabled {
            if let Err(error) = &result {
                if let Ok(previous) = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                    |value| if value < LIMIT { Some(value + 1) } else { None }) {
                    // Match the existing background-renewal public scope hash.
                    let scope_sha256 = digest_json(&json!({"principal_id":self.scope.principal_id,
                        "route_id":self.scope.route_id,"credential_id":self.scope.credential_id}));
                    let record = json!({"schema":"serverware.operatorStaticPreparationFailure/v1",
                        "ordinal":previous + 1,"stage":stage.label(),"error_code":error_code(error),
                        "scope_sha256":scope_sha256,
                        "policy_sha256":is_sha256_digest(&self.snapshot.hash).then_some(self.snapshot.hash.as_str())});
                    if let Ok(mut line) = serde_json::to_vec(&record) {
                        line.push(b'\n');
                        let _ = sink(&line);
                    }
                }
            }
        }
        result
    }

    #[cfg(test)]
    pub(super) fn observe_with_for_test<T>(&self, stage: Stage, result: Result<T, String>, counter: &AtomicUsize,
        sink: impl FnOnce(&[u8]) -> io::Result<()>) -> Result<T, String> {
        self.observe_with(stage, result, counter, sink)
    }
}

// Test-only, thread-scoped capture: actual preparation exercises its unchanged
// admission, while independent tests never share the production record budget.
#[cfg(test)]
struct Capture {
    counter: AtomicUsize,
    lines: std::cell::RefCell<Vec<String>>,
    fail_write: bool,
}
#[cfg(test)]
thread_local! {
    static TEST_CAPTURE: std::cell::RefCell<Option<std::rc::Rc<Capture>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn capture<T>(fail_write: bool, operation: impl FnOnce() -> T) -> (T, Vec<String>, usize) {
    struct Reset(Option<std::rc::Rc<Capture>>);
    impl Drop for Reset {
        fn drop(&mut self) { TEST_CAPTURE.with(|slot| { slot.replace(self.0.take()); }); }
    }
    let capture = std::rc::Rc::new(Capture { counter: AtomicUsize::new(0),
        lines: std::cell::RefCell::new(Vec::new()), fail_write });
    let _reset = Reset(TEST_CAPTURE.with(|slot| slot.replace(Some(std::rc::Rc::clone(&capture)))));
    let result = operation();
    let lines = capture.lines.borrow().clone();
    (result, lines, capture.counter.load(Ordering::Relaxed))
}
