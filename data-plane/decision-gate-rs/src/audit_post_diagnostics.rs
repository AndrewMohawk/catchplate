//! Bounded, non-secret observations of legacy audit failures, never admission.
//!
//! Keep the verifier and retry decisions authoritative. In particular, an HTTP
//! status or a diagnostic context parse must never turn a rejected ACK into an
//! accepted one. Do not format AuditPostError, response material, or digests.
use super::{
    strict_json_value_from_slice, AuditPostError, AuditPostFailure, GateState, SensitiveJsonValue,
    Snapshot, MAX_CONTROL_PLANE_RESPONSE_HEADER_BYTES, MAX_CONTROL_PLANE_RESPONSE_STATEMENT_BYTES,
};
use base64::{engine::general_purpose, Engine as _};
use reqwest::{header::HeaderMap, StatusCode};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    Unclassified,
    Preflight,
    Transport,
    ResponseBody,
    ServiceLifetime,
    SnapshotNotCurrent,
    SnapshotChanged,
    ResponseStatementParse,
    ResponseContextParse,
    ResponseContextPolicyMismatch,
    ResponseContextOtherMismatch,
    ResponseVerificationOther,
    HttpStatus,
    AckParse,
    AckInstanceMismatch,
    AckCountMismatch,
    AckDigestMismatch,
    AckContractMismatch,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Preflight => "preflight",
            Self::Transport => "transport",
            Self::ResponseBody => "response_body",
            Self::ServiceLifetime => "service_lifetime",
            Self::SnapshotNotCurrent => "snapshot_not_current",
            Self::SnapshotChanged => "snapshot_changed",
            Self::ResponseStatementParse => "response_statement_parse",
            Self::ResponseContextParse => "response_context_parse",
            Self::ResponseContextPolicyMismatch => "response_context_policy_mismatch",
            Self::ResponseContextOtherMismatch => "response_context_other_mismatch",
            Self::ResponseVerificationOther => "response_verification_other",
            Self::HttpStatus => "http_status",
            Self::AckParse => "ack_parse",
            Self::AckInstanceMismatch => "ack_instance_mismatch",
            Self::AckCountMismatch => "ack_count_mismatch",
            Self::AckDigestMismatch => "ack_digest_mismatch",
            Self::AckContractMismatch => "ack_contract_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Initial,
    Retry,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Diagnostic {
    stage: Stage,
    event_count: Option<u64>,
    status: Option<u16>,
    elapsed_ms: Option<u64>,
    same_snapshot: Option<bool>,
    same_policy_sequence: Option<bool>,
}

pub(super) struct Attempt<'a> {
    state: &'a GateState,
    started: Instant,
    event_count: u64,
    status: Option<u16>,
    snapshot: Option<Arc<Snapshot>>,
}

impl<'a> Attempt<'a> {
    pub(super) fn new(state: &'a GateState, event_count: usize) -> Self {
        Self {
            state,
            started: Instant::now(),
            event_count: event_count as u64,
            status: None,
            snapshot: None,
        }
    }

    pub(super) fn snapshot(&mut self, snapshot: &Arc<Snapshot>) {
        self.snapshot = Some(Arc::clone(snapshot));
    }

    pub(super) fn status(&mut self, status: StatusCode) {
        self.status = Some(status.as_u16());
    }

    pub(super) fn failure(&self, stage: Stage, mut error: AuditPostError) -> AuditPostError {
        // Observation only: never wait for a publication lock, and never let a
        // poisoned/contended diagnostic read replace the original failure.
        let observation = self.snapshot.as_ref().and_then(|captured| {
            self.state.snapshot.try_read().ok().map(|current| {
                (
                    current.epoch == captured.epoch && Arc::ptr_eq(&current, captured),
                    current.policy_sequence == captured.policy_sequence,
                )
            })
        });
        let observed_stage =
            if stage == Stage::SnapshotNotCurrent && observation.is_some_and(|(same, _)| !same) {
                Stage::SnapshotChanged
            } else {
                stage
            };
        error.diagnostic = Some(Diagnostic {
            stage: observed_stage,
            event_count: Some(self.event_count),
            status: self.status,
            elapsed_ms: Some(self.started.elapsed().as_millis().min(u64::MAX as u128) as u64),
            same_snapshot: observation.map(|(same, _)| same),
            same_policy_sequence: observation.map(|(_, same)| same),
        });
        error
    }
}

// Called only after the unchanged verifier has already rejected the response.
// A second, bounded parse provides a category, not trust or acceptance. Unknown
// errors deliberately stay generic rather than printing/interpolating them.
pub(super) fn verification_stage(message: &str, headers: &HeaderMap, snapshot: &Snapshot) -> Stage {
    match message {
        "audit acknowledgement statement parse failed" => match context_shape(headers, snapshot) {
            Some((false, _)) => Stage::ResponseContextParse,
            _ => Stage::ResponseStatementParse,
        },
        "audit acknowledgement context mismatch" => match context_shape(headers, snapshot) {
            Some((true, Some(false))) => Stage::ResponseContextPolicyMismatch,
            _ => Stage::ResponseContextOtherMismatch,
        },
        _ => Stage::ResponseVerificationOther,
    }
}

fn context_shape(headers: &HeaderMap, snapshot: &Snapshot) -> Option<(bool, Option<bool>)> {
    let mut values = headers
        .get_all("x-catchplate-response-statement-b64")
        .iter();
    let encoded = values.next()?.as_bytes();
    if values.next().is_some() || encoded.len() > MAX_CONTROL_PLANE_RESPONSE_HEADER_BYTES {
        return None;
    }
    let decoded = Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.decode(encoded).ok()?);
    if decoded.len() > MAX_CONTROL_PLANE_RESPONSE_STATEMENT_BYTES {
        return None;
    }
    let statement = SensitiveJsonValue::new(strict_json_value_from_slice(&decoded).ok()?);
    let Some(context) = statement.get("context").and_then(|value| value.as_object()) else {
        return Some((false, None));
    };
    const REQUIRED: [&str; 2] = ["runtime_manifest_digest", "policy_bundle_digest"];
    const OPTIONAL: [&str; 3] = [
        "provenance_digest",
        "image_signatures_digest",
        "source_tree_digest",
    ];
    let valid = REQUIRED
        .iter()
        .all(|key| context.get(*key).is_some_and(|value| value.is_string()))
        && context.iter().all(|(key, value)| {
            REQUIRED.contains(&key.as_str())
                || (OPTIONAL.contains(&key.as_str()) && (value.is_null() || value.is_string()))
        });
    Some((
        valid,
        context
            .get("policy_bundle_digest")
            .and_then(|value| value.as_str())
            .map(|digest| digest == snapshot.hash),
    ))
}

fn boolean(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

pub(super) fn line(error: &AuditPostError, phase: Phase) -> String {
    let diagnostic = error.diagnostic.unwrap_or(Diagnostic {
        stage: Stage::Unclassified,
        event_count: None,
        status: None,
        elapsed_ms: None,
        same_snapshot: None,
        same_policy_sequence: None,
    });
    let kind = match error.kind {
        AuditPostFailure::NotSent => "not_sent",
        AuditPostFailure::LocalTooLarge => "local_too_large",
        AuditPostFailure::AuthenticatedTooLarge => "authenticated_too_large",
        AuditPostFailure::OutcomeUnknown => "outcome_unknown",
    };
    format!("audit_post_failure phase={} stage={} outcome={} status={} event_count={} elapsed_ms={} same_snapshot={} same_policy_sequence={}",
        match phase { Phase::Initial => "initial", Phase::Retry => "retry" },
        diagnostic.stage.label(), kind,
        diagnostic.status.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        diagnostic.event_count.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        diagnostic.elapsed_ms.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        boolean(diagnostic.same_snapshot), boolean(diagnostic.same_policy_sequence))
}

pub(super) fn emit(error: &AuditPostError, phase: Phase) {
    eprintln!("{}", line(error, phase));
}

#[cfg(test)]
#[path = "audit_post_diagnostics_tests.rs"]
mod tests;
