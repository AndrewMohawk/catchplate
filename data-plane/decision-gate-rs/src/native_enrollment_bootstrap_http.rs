//! One finite native bootstrap exchange on the actual accepted TLS stream.
//! Request decoding is not authority. The retained admission performs every
//! caller/delegation/setup/target join before durable signing and quotation.

use super::*;
use super::native_enrollment_admission::{self as peer, AdmissionClock};
use super::native_enrollment_bootstrap_admission;
use crate::native_enrollment_bootstrap_exchange_v1 as exchange;

const PROCESSING_WINDOW: Duration = Duration::from_secs(30);

enum Failure { BadRequest, Unavailable }

/// The connection entry calls this before TLS or HTTP intake, including any
/// application bytes coalesced with handshake/header reads. Other routes drop
/// the unused owner; their ordinary deadlines are not changed. A missing or
/// expired opening never permits a later bootstrap-only replacement window.
pub(super) fn opening(state: &GateState) -> Option<AdmissionClock> {
    let original = Instant::now().checked_add(PROCESSING_WINDOW)?;
    if !state.is_production { return None; }
    let lifetime = state.native_runtime_lifetime.as_ref()?;
    let authorizer = state.native_enrollment_authorizer.as_ref()?;
    AdmissionClock::open(original, lifetime.deadline(), authorizer.deadline()).ok()
}

/// Always terminal: one success/error response or an unacknowledged close.
/// There is no retry, continuation, legacy fallback or second response after
/// admission/signing begins. An interrupted result does not mean no signature.
pub(super) fn handle(state: &GateState, head: &RequestHead,
    stream: &mut DirectProxyStream, trusted_mtls: Option<&TrustedMtlsEvidence>,
    management_listener: bool, proxy_ingress: &ProxyIngressConfig,
    bootstrap_opening: Option<AdmissionClock>) {
    let Some(mut clock) = bootstrap_opening else { return; };
    let prepared = (|| {
        restrict(stream, &mut clock).map_err(|_| Failure::Unavailable)?;
        if management_listener || !state.is_production
            || !matches!(stream, DirectProxyStream::MutualTls(_))
            || !matches!(proxy_ingress, ProxyIngressConfig::MutualTls(config)
                if config.native_owner.is_some())
            || !trusted_mtls.is_some_and(|evidence| evidence.verified_by_trusted_ingress
                && evidence.is_live_at(now_epoch_ms())) {
            return Err(Failure::Unavailable);
        }
        if head.method != "POST" || head.target != exchange::PATH
            || head.http_version != "HTTP/1.1" || !head.has_content_length
            || head.content_length == 0 || head.content_length > exchange::MAX_REQUEST_BYTES
            || head.prefetched_body.len() > head.content_length
            || head.headers.get("content-type").map(String::as_str) != Some("application/json")
            || head.headers.get("connection").map(String::as_str) != Some("close")
            || ["transfer-encoding", "expect", "upgrade", "x-serverware-ingress-continuation",
                "x-serverware-ingress-evidence"].iter().any(|name| head.headers.contains_key(*name)) {
            return Err(Failure::BadRequest);
        }
        peer::request_challenge(head).map_err(|_| Failure::BadRequest)?;
        clock.check(clock.deadline).map_err(|_| Failure::Unavailable)?;
        let mut original = Vec::with_capacity(head.content_length);
        original.extend_from_slice(&head.prefetched_body);
        let mut chunk = [0u8; 4096];
        while original.len() < head.content_length {
            restrict(stream, &mut clock).map_err(|_| Failure::Unavailable)?;
            let maximum = chunk.len().min(head.content_length - original.len());
            let count = stream.read(&mut chunk[..maximum]).map_err(|_| Failure::BadRequest)?;
            if count == 0 || count > maximum { return Err(Failure::BadRequest); }
            original.extend_from_slice(&chunk[..count]);
            clock.check(clock.deadline).map_err(|_| Failure::Unavailable)?;
        }
        reject_buffered_plaintext(stream).map_err(|_| Failure::BadRequest)?;
        clock.check(clock.deadline).map_err(|_| Failure::Unavailable)?;
        let originals = exchange::decode_original(&original).map_err(|_| Failure::BadRequest)?;
        clock.check(clock.deadline).map_err(|_| Failure::Unavailable)?;
        Ok(originals)
    })();
    let originals = match prepared {
        Ok(originals) => originals,
        Err(failure) => { reject(stream, &mut clock, failure); return; }
    };
    let Some(trusted_mtls) = trusted_mtls else { return; };
    // Move the same pre-intake clock and actual mutable stream into admission.
    // Once this starts, every error closes without exposing internal failures
    // or guessing whether the durable signing operation completed.
    let _ = native_enrollment_bootstrap_admission::admit_on_clock(state, head, stream,
        trusted_mtls, proxy_ingress, originals.delegation_original(),
        originals.target_request_original(), clock)
        .and_then(|admission| admission.prepare_packet(originals.setup_original()))
        .and_then(|prepared| prepared.deliver_once());
}

fn restrict(stream: &mut DirectProxyStream, clock: &mut AdmissionClock) -> Result<(), String> {
    let opening = Instant::now();
    let remaining = clock.remaining()?;
    let deadline = opening.checked_add(remaining).ok_or("native bootstrap transport deadline overflow")?;
    stream.restrict_operation_deadline(deadline);
    stream.set_terminal_write_deadline(Some(deadline));
    stream.check_operation_deadline().map_err(|_| "native bootstrap transport expired".to_owned())
}

/// Only inspect already decrypted plaintext; never perform a speculative
/// network read. Any observed second request/body suffix makes this terminal
/// exchange fail. Unread socket bytes carry no timing or verification claim.
pub(super) fn reject_buffered_plaintext(stream: &mut DirectProxyStream) -> Result<(), String> {
    let DirectProxyStream::MutualTls(tls) = stream else {
        return Err("native bootstrap requires its original TLS stream".to_owned());
    };
    match tls.read_plaintext(&mut [0u8; 1]) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        _ => Err("native bootstrap refuses buffered continuation or premature TLS close".to_owned()),
    }
}

fn reject(stream: &mut DirectProxyStream, clock: &mut AdmissionClock, failure: Failure) {
    if !matches!(stream, DirectProxyStream::MutualTls(_)) || restrict(stream, clock).is_err() { return; }
    let (status, body) = match failure {
        Failure::BadRequest => (StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_native_bootstrap_request"}"#.to_vec()),
        Failure::Unavailable => (StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":"native_bootstrap_unavailable"}"#.to_vec()),
    };
    let response = http_binary_response_with_headers(status, Some("application/json"), body,
        &[("Cache-Control".to_owned(), "no-store".to_owned())]);
    if stream.write_all(&response).is_err() || restrict(stream, clock).is_err()
        || stream.flush().is_err() || clock.check(clock.deadline).is_err() { return; }
    if let DirectProxyStream::MutualTls(tls) = stream {
        if tls.send_close_notify().is_err() { return; }
    }
    if restrict(stream, clock).is_ok() { let _ = stream.flush(); }
}
