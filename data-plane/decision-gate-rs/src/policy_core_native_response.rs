//! Join the actual native TLS/persistence owner to bounded shadow evaluation.
//! This is not a legacy transport-receipt verifier or an externally supplied
//! "capture succeeded" flag. Only the native transaction can create the owner.
use super::*;
use crate::response_v2::CommittedNativeCapture;
use serverware_decision_gate::native_target_dispatch_v1 as native;
use serverware_decision_gate::V2Http11TransferCodingV1;

pub(crate) struct NativeResponseRetention {
    _reservation: QueueByteReservation,
}

impl ShadowRequestHandle {
    pub(crate) fn reserve_native_response_retention(
        &self, raw_bytes: usize, originals_bytes: usize,
    ) -> Result<NativeResponseRetention, String> {
        // Reserve before retaining the raw original across custody calls.
        // Four raw-sized buffers cover the held original, exact head/body
        // split, parser entity and queued entity. Original serialization and
        // small derived commitments are charged too. The later queued job
        // has its own charge while this retention owner remains alive.
        if raw_bytes == 0 || originals_bytes > 1024 * 1024 {
            return Err("native shadow capture originals exceed their bound".into());
        }
        let bytes = raw_bytes.checked_mul(4)
            .and_then(|n| originals_bytes.checked_mul(3).and_then(|size| n.checked_add(size)))
            .and_then(|n| n.checked_add(32 * 1024))
            .map(shadow_job_bytes_with_terminal_retention)
            .filter(|n| *n <= SHADOW_MAX_JOB_BYTES)
            .ok_or("native shadow capture exceeds the existing job budget")?;
        let reservation = QueueByteReservation::reserve(
            &self.inner.queued_bytes, &self.inner.queue_poisoned, &self.inner.ledger,
            self.inner.generation.generation_id(), self.inner.ingress_sequence,
            &self.inner.request_binding_sha256, &self.inner.request_commitment_sha256, bytes,
        ).ok_or("native shadow capture has no queue capacity")?;
        Ok(NativeResponseRetention { _reservation: reservation })
    }
}

impl ShadowResponseHook {
    pub(crate) fn finish_native_response(
        &self,
        snapshot: &Arc<Snapshot>,
        original: &CommittedNativeCapture,
        active_validation: &Value,
        returned_response: &[u8],
    ) {
        if self.try_finish_native_response(snapshot, original, active_validation, returned_response).is_err() {
            if !self.record_unavailable_detail(
                PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
                Some(returned_response),
            ) {
                self.inner.ledger.mark_hard_unready();
            }
        }
    }

    fn try_finish_native_response(
        &self,
        snapshot: &Arc<Snapshot>,
        original: &CommittedNativeCapture,
        active_validation: &Value,
        returned_response: &[u8],
    ) -> Result<(), String> {
        if !self.inner.generation_is_current_for(snapshot) {
            return Err("native response shadow generation changed".into());
        }
        let pending = self.inner.state.try_lock()
            .map_err(|_| "native response lifecycle is busy")?
            .pending_active.clone().ok_or("native response has no actual dispatch barrier")?;
        let capture = original.capture();
        let completion = original.completion();
        let dispatch = &capture.statement.original;
        let transaction = &dispatch.binding.transaction;
        let raw = original.raw();
        let descriptor = capture.statement.raw_response.as_ref()
            .ok_or("native response has no actual capture descriptor")?;
        if !pending.dispatch_authorized
            || pending.final_upstream_request_commitment_sha256.as_deref()
                != Some(dispatch.request_sha256.as_str())
            || transaction.policy_sha256 != snapshot.hash
            || pending.active_evaluation.route_id.as_deref() != Some(transaction.route_id.as_str())
            || pending.active_decision.get("principal_id").and_then(Value::as_str)
                != Some(transaction.principal_id.as_str())
            || self.inner.facts.method != original.method()
            || capture.statement.phase != "capture"
            || descriptor.sha256 != native::sha256(raw)
            || descriptor.byte_length != raw.len() as u64
            || completion.object.object_sha256 != descriptor.sha256
            || completion.object.byte_length != descriptor.byte_length
            || completion.capture_sha256 != native::sha256(&native::canonical(capture)?)
            || active_validation.get("outcome").and_then(Value::as_str) != Some("released")
            || active_validation.get("releasedResponseSha256").and_then(Value::as_str)
                != Some(sha256_prefixed(returned_response).as_str())
            || pending.effect_requirements.gmail_metadata_fanout()
        {
            // Gmail fanout needs its actual typed hydration/proof owner; a
            // generic native capture is not a substitute for that evidence.
            return Err("native response does not bind the actual shadow request and release".into());
        }
        let parsed = crate::response_v2::response_observation_v2_parse_http11(raw, Some(original.method()))?;
        if !parsed.framing.informational_statuses.is_empty() {
            return Err("shadow exact capture does not yet cover informational response chains".into());
        }
        let head_length = usize::try_from(parsed.framing.header_section_length)
            .map_err(|_| "native response header length overflow")?;
        let head = raw.get(..head_length).ok_or("native response physical head is missing")?;
        let body = raw.get(head_length..).ok_or("native response physical body is missing")?;
        let (status, headers, physical_header_count) = parse_raw_response_head(head)?;
        if status != parsed.status || body.len() > SHADOW_MAX_RESPONSE_BODY_BYTES
            || parsed.entity_body.len() > SHADOW_MAX_RESPONSE_BODY_BYTES
        {
            return Err("native response parsed status/body exceeds exact shadow bounds".into());
        }
        let framing = match parsed.framing.transfer_coding {
            V2Http11TransferCodingV1::NoBody => TransportResponseFraming::NoBody,
            V2Http11TransferCodingV1::Chunked => TransportResponseFraming::Chunked,
            V2Http11TransferCodingV1::Identity if parsed.framing.declared_content_length.is_some() =>
                TransportResponseFraming::ContentLength,
            V2Http11TransferCodingV1::Identity => TransportResponseFraming::CloseDelimited,
        };
        let tls = capture.statement.tls.as_ref().ok_or("native TLS peer original is absent")?;
        let attestation = general_purpose::STANDARD.decode(&capture.native_key_evidence.attestation_document_b64)
            .map_err(|_| "native capture attestation encoding changed")?;
        if attestation.is_empty() || attestation.len() > 16 * 1024 {
            return Err("native capture attestation is outside its original bound".into());
        }
        // These commitments retain their genuine native domains. Nothing
        // asserts that the legacy transport-receipt signature was produced.
        let transport_capture_receipt_sha256 = digest_json_ensure_ascii(&json!({
            "domain":"serverware.policyShadowNativeTransportCapture/v1",
            "capture":capture,
            "committedPersistence":completion,
        }));
        let verified = VerifiedRawResponseCapture {
            status, parsed_headers: headers.clone(), physical_header_count,
            raw_response_head: Arc::from(head), raw_response_body: Arc::from(body),
            body: Arc::from(parsed.entity_body.as_slice()),
            gmail_metadata_evidence: None, transport_capture_receipt_sha256,
            runtime_attestation_sha256: sha256_prefixed(&attestation),
            peer_identity_sha256: native::sha256(&native::canonical(tls)?), framing,
        };
        let dispatch_completion_sha256 = native::sha256(&native::canonical(completion)?);
        let handle = ShadowRequestHandle { inner: Arc::clone(&self.inner) };
        let mut attempt = self.begin(snapshot, StatusCode::from_u16(status)
            .map_err(|_| "native upstream status is invalid")?, &headers)?;
        let result = attempt.try_finish_exact(
            snapshot, verified, active_validation, &parsed.entity_body, returned_response,
            |validation_sha256| {
                let effects = handle.post_dispatch_terminal_effects(
                    &pending, &pending.active_decision, returned_response,
                    PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
                    true, Some(validation_sha256), Some(&dispatch_completion_sha256),
                )?;
                // A signed response does not prove that unrelated quota,
                // OAuth or credential effects completed. Missing owners stay
                // unavailable instead of being promoted to an allow result.
                effects.require_all_completed()?;
                Ok(effects)
            },
        );
        attempt.completed = true;
        result
    }
}
