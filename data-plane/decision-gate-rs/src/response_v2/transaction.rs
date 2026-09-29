use super::*;
use serverware_decision_gate::{
    CustodyServiceRole, ProviderAuthorityScopeV2,
    ServiceOperationV1,
};

pub(super) fn response_observation_v2_http11_request(
    request: &IncomingRequest,
    upstream_url: &Url,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>, ResponseObservationV2TransactionError> {
    let authority = upstream_url
        .host_str()
        .map(|host| match upstream_url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        })
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let mut canonical_headers = headers.clone();
    canonical_headers.insert("host".to_owned(), authority);
    canonical_headers.insert(
        "content-length".to_owned(),
        request.body.len().to_string(),
    );
    if canonical_headers.keys().any(|name| {
        name.starts_with(SERVERWARE_INTERNAL_HEADER_PREFIX)
            || matches!(
                name.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "set-cookie"
                    | "connection"
                    | "transfer-encoding"
                    | "upgrade"
            )
    }) {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut bytes = Vec::with_capacity(
        request.body.len()
            + canonical_headers
                .iter()
                .map(|(name, value)| name.len() + value.len() + 4)
                .sum::<usize>()
            + upstream_url.as_str().len()
            + request.method.len()
            + 32,
    );
    write!(
        &mut bytes,
        "{} {} HTTP/1.1\r\n",
        request.method,
        upstream_url.as_str(),
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    for (name, value) in canonical_headers {
        if name.bytes().any(|byte| {
            !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && byte != b'-'
        }) || value.bytes().any(|byte| {
            matches!(byte, b'\r' | b'\n' | 0)
        })
        {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
        write!(&mut bytes, "{name}: {value}\r\n").map_err(
            |_| {
                ResponseObservationV2TransactionError::InvalidResponse
            },
        )?;
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&request.body);
    Ok(bytes)
}

pub(super) fn execute_response_observation_v2_transaction(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    decision: &Value,
    request: &IncomingRequest,
    upstream_url: &Url,
    provider_headers: &BTreeMap<String, String>,
    injection_plan: &Value,
    release_authorization: &mut Option<ReleaseAuthorizationGuard<'_>>,
    execution: &ResponseObservationV2Execution<'_>,
    shadow_finalization:
        Option<&policy_core::ShadowRequestHandle>,
    shadow_dispatch_barrier_crossed: &mut bool,
) -> Result<
    SensitiveResponseBytes,
    ResponseObservationV2TransactionError,
> {
    let client = state
        .response_observation_v2_client
        .as_ref()
        .ok_or(ResponseObservationV2TransactionError::Unavailable)?;
    let now_epoch_ms = u64::try_from(now_epoch_ms()).map_err(|_| {
        ResponseObservationV2TransactionError::Unavailable
    })?;
    let requested_timeout_ms = u64::try_from(
        execution.route.lifecycle_timeout.as_millis(),
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::Unavailable
    })?;
    let nonce_remaining_ms = execution
        .context
        .nonce_expires_at_epoch_ms
        .saturating_sub(now_epoch_ms);
    let nonce_lifecycle_budget_ms =
        nonce_remaining_ms.checked_sub(1).ok_or(
            ResponseObservationV2TransactionError::Unavailable,
        )?;
    let lifecycle_ms = requested_timeout_ms
        .min(nonce_lifecycle_budget_ms)
        .min(RESPONSE_OBSERVATION_V2_MAX_OPERATION_MS);
    if lifecycle_ms == 0 {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    let deadline_at_boottime_ns =
        response_observation_v2_boottime_ns()?
            .checked_add(
                lifecycle_ms
                    .checked_mul(1_000_000)
                    .ok_or(
                        ResponseObservationV2TransactionError::Unavailable,
                    )?,
            )
            .ok_or(
                ResponseObservationV2TransactionError::Unavailable,
            )?;
    // State authority uses an exact millisecond BOOTTIME contract. Narrow once
    // before Hello and retain that one original through every later owner.
    let deadline_at_boottime_ns = deadline_at_boottime_ns / 1_000_000 * 1_000_000;
    let lifecycle_deadline =
        ResponseObservationV2Deadline::from_absolute(
            deadline_at_boottime_ns,
        );
    let deadline_at_epoch_ms = now_epoch_ms
        .checked_add(lifecycle_ms)
        .ok_or(ResponseObservationV2TransactionError::Unavailable)?;
    let monotonic_deadline = V2MonotonicDeadlineV1 {
        api_version: V2_MONOTONIC_DEADLINE_VERSION.to_owned(),
        custody_boot_id: client.boot_id.clone(),
        clock_id: V2MonotonicClockId::ClockBoottime,
        absolute_boottime_ns:
            deadline_at_boottime_ns.to_string(),
    };
    let mut session = ResponseObservationV2Session::open(
        client,
        lifecycle_deadline,
        monotonic_deadline.clone(),
        deadline_at_epoch_ms,
    )?;
    let principal_id = decision
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let route_id = decision
        .get("route_id")
        .and_then(Value::as_str)
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let client_request_sha256 = decision
        .get("client_request_digest")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let decision_request_sha256 = decision
        .get("request_digest")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let attempt_id = decision
        .get("attempt_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            response_observation_id(
                &execution.context.client_nonce,
            )
        });
    if attempt_id.is_empty()
        || attempt_id.len() > 256
        || attempt_id.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace()
        })
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let stable_resume_id =
        response_observation_v2_stable_resume_id_sha256(
            &client.generation_id,
            client.provider_generation,
            client_request_sha256,
            &attempt_id,
        );
    let credential_id = decision
        .get("credential_ref")
        .and_then(Value::as_str);
    let credential_generation = match credential_id {
        Some(_) => Some(
            decision
                .get("credential_version")
                .and_then(Value::as_u64)
                .filter(|generation| *generation > 0)
                .ok_or(
                    ResponseObservationV2TransactionError::InvalidResponse,
                )?,
        ),
        None => None,
    };
    let credential_binding_sha256 = credential_id
        .zip(credential_generation)
        .map(|(credential_id, credential_generation)| {
            digest_json(&json!({
                "credentialId":credential_id,
                "credentialGeneration":credential_generation,
                "injectionPlanSha256":digest_json(injection_plan),
            }))
        });
    let route_semantics = json!({
        "apiVersion":"serverware.responseObservationV2RouteSemantics/v1",
        "principalId":principal_id,
        "routeId":route_id,
        "scheme":upstream_url.scheme(),
        "authority":upstream_url
            .host_str()
            .map(|host| match upstream_url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            })
            .ok_or(
                ResponseObservationV2TransactionError::InvalidResponse,
            )?,
        "method":request.method,
        "target":upstream_url.as_str(),
        "adapterType":decision
            .get("adapter_type")
            .cloned()
            .unwrap_or(Value::Null),
        "policySha256":snapshot.hash,
        "connectionIdentitySha256":
            execution.connection_identity_sha256,
        "clientRequestSha256":client_request_sha256,
        "decisionRequestSha256":decision_request_sha256,
        "operationSha256":decision
            .get("operation_digest")
            .cloned()
            .unwrap_or(Value::Null),
        "credentialBindingSha256":credential_binding_sha256,
        "observationSessionId":
            response_observation_id(
                &execution.context.client_nonce,
            ),
        "tlsSessionSha256":
            sha256_prefixed(
                execution.context.tls_exporter.as_bytes(),
            ),
        "enrollmentSessionId":decision
            .get("enrollment_session_id")
            .cloned()
            .unwrap_or(Value::Null),
    });
    let route_semantics_bytes =
        custody_canonical_json_bytes(&route_semantics).map_err(
            |_| {
                ResponseObservationV2TransactionError::InvalidResponse
            },
        )?;
    let mut transaction = V2TransactionBindingV1 {
        principal_id: principal_id.to_owned(),
        connection_identity_sha256:
            execution.connection_identity_sha256.clone(),
        client_request_sha256: client_request_sha256.to_owned(),
        decision_request_sha256:
            decision_request_sha256.to_owned(),
        route_id: route_id.to_owned(),
        route_semantics_sha256:
            sha256_prefixed(&route_semantics_bytes),
        policy_sha256: snapshot.hash.clone(),
        credential_binding_sha256:
            credential_binding_sha256.clone(),
        upstream_response_sha256: None,
        tls_session_sha256: sha256_prefixed(
            execution.context.tls_exporter.as_bytes(),
        ),
        enrollment_session_id: decision
            .get("enrollment_session_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        observation_session_id: response_observation_id(
            &execution.context.client_nonce,
        ),
    };
    let mut cursor = ResponseObservationV2AttemptCursor {
        attempt: AttemptStateReference {
            attempt_id: attempt_id.clone(),
            state: V2AttemptState::Genesis,
            state_sha256:
                client.pinned_genesis_state_sha256.clone(),
            attempt_revision: 0,
            // Zero is a reservation sentinel. The linearizable state
            // authority allocates the first nonzero fence in Reserve.
            fencing_token: 0,
        },
        transaction: transaction.clone(),
        monotonic_deadline: monotonic_deadline.clone(),
        deadline_at_epoch_ms,
    };

    let reserve_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let decision_bytes =
        custody_canonical_json_bytes(decision).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let runtime_attestation = json!({
        "apiVersion":"serverware.responseObservationV2GateRuntimeEvidence/v1",
        "helloAttestation":&session.hello_attestation,
        "connectionIdentitySha256":
            execution.connection_identity_sha256,
        "transaction":transaction,
    });
    let runtime_attestation_bytes =
        custody_canonical_json_bytes(&runtime_attestation)
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    let reserve_objects = vec![
        response_observation_v2_exact_input(
            &format!("{attempt_id}-route"),
            ExactObjectMediaType::CanonicalJson,
            0,
            &route_semantics_bytes,
            lifecycle_deadline,
        )?,
        response_observation_v2_exact_input(
            &format!("{attempt_id}-decision"),
            ExactObjectMediaType::CanonicalJson,
            1,
            &decision_bytes,
            lifecycle_deadline,
        )?,
        response_observation_v2_exact_input(
            &format!("{attempt_id}-runtime"),
            ExactObjectMediaType::EvidenceBundle,
            2,
            &runtime_attestation_bytes,
            lifecycle_deadline,
        )?,
    ];
    let reserve = V2OperationRequest::Reserve {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: reserve_request_id.clone(),
        boot_id: Some(client.boot_id.clone()),
        params: V2ReserveParams {
            binding: cursor.operation_binding(
                &reserve_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            route_semantics:
                reserve_objects[0].descriptor.clone(),
            policy_decision:
                reserve_objects[1].descriptor.clone(),
            runtime_attestation:
                reserve_objects[2].descriptor.clone(),
        },
    };
    let mut staging_previous=None;
    let reserve_result = if client.native_staging {
        super::staging_client::execute(state,snapshot,decision,&session,&mut cursor,&reserve,reserve_objects,
            &mut staging_previous,&stable_resume_id)?
    } else { (match session.execute(&reserve, reserve_objects) {
        Ok(reply) => reply,
        Err(_) => {
            let replay_session = ResponseObservationV2Session::open(
                client,
                lifecycle_deadline,
                monotonic_deadline.clone(),
                deadline_at_epoch_ms,
            )
            .map_err(|error| {
                error.with_resume(&attempt_id, &stable_resume_id)
            })?;
            let replay_objects = vec![
                response_observation_v2_exact_input(
                    &format!("{attempt_id}-route"),
                    ExactObjectMediaType::CanonicalJson,
                    0,
                    &route_semantics_bytes,
                    lifecycle_deadline,
                )?,
                response_observation_v2_exact_input(
                    &format!("{attempt_id}-decision"),
                    ExactObjectMediaType::CanonicalJson,
                    1,
                    &decision_bytes,
                    lifecycle_deadline,
                )?,
                response_observation_v2_exact_input(
                    &format!("{attempt_id}-runtime"),
                    ExactObjectMediaType::EvidenceBundle,
                    2,
                    &runtime_attestation_bytes,
                    lifecycle_deadline,
                )?,
            ];
            replay_session
                .execute(&reserve, replay_objects)
                .map_err(|error| {
                    error.with_resume(&attempt_id, &stable_resume_id)
                })?
        }
    }).result };
    let reservation_evidence = match reserve_result {
            V2OperationResult::Reserve(
                V2ReserveResult::Reserved {
                    attempt,
                    reservation_evidence,
                },
            ) if client.native_staging || cursor.advance(
                &reserve,
                V2AttemptState::Reserved,
                &reservation_evidence.evidence_sha256,
                attempt.clone(),
            ) => reservation_evidence,
            V2OperationResult::Reserve(
                V2ReserveResult::Denied {
                    attempt,
                    terminal_evidence,
                },
            ) if cursor.advance(
                &reserve,
                V2AttemptState::Denied,
                &terminal_evidence.evidence_sha256,
                attempt.clone(),
            ) => {
                return Err(
                    ResponseObservationV2TransactionError::Denied
                        .with_resume(
                            &attempt_id,
                            &stable_resume_id,
                        ),
                )
            }
            _ => {
                return Err(
                    ResponseObservationV2TransactionError::InvalidResponse
                        .with_resume(
                            &attempt_id,
                            &stable_resume_id,
                        ),
                )
            }
        };

    let outcome = (|| -> Result<
        SensitiveResponseBytes,
        ResponseObservationV2TransactionError,
    > {
    let authority_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let authority_plan = response_observation_v2_authority_plan(
        decision,
        release_authorization.as_ref(),
    );
    let authority_plan_bytes =
        custody_canonical_json_bytes(&authority_plan).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let authorization_evidence = json!({
        "apiVersion":"serverware.responseObservationV2ReservedAuthorityEvidence/v1",
        "requestSha256":client_request_sha256,
        "policySha256":snapshot.hash,
        "authorityPlanSha256":
            sha256_prefixed(&authority_plan_bytes),
        "gateRuntimeAttestationSha256":
            sha256_prefixed(&runtime_attestation_bytes),
    });
    let authorization_evidence_bytes =
        custody_canonical_json_bytes(&authorization_evidence)
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    let authority_objects = vec![
        response_observation_v2_exact_input(
            &format!("{attempt_id}-authority-plan"),
            ExactObjectMediaType::CanonicalJson,
            0,
            &authority_plan_bytes,
            lifecycle_deadline,
        )?,
        response_observation_v2_exact_input(
            &format!("{attempt_id}-authority-evidence"),
            ExactObjectMediaType::EvidenceBundle,
            1,
            &authorization_evidence_bytes,
            lifecycle_deadline,
        )?,
    ];
    let authority = V2OperationRequest::Authority {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: authority_request_id.clone(),
        boot_id: Some(client.boot_id.clone()),
        params: V2AuthorityParams {
            binding: cursor.operation_binding(
                &authority_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            reservation_evidence,
            authority_plan:
                authority_objects[0].descriptor.clone(),
            authorization_evidence:
                authority_objects[1].descriptor.clone(),
        },
    };
    let authority_result=if client.native_staging {
        super::staging_client::execute(state,snapshot,decision,&session,&mut cursor,&authority,authority_objects,
            &mut staging_previous,&stable_resume_id)?
    }else{session.execute(&authority,authority_objects)?.result};
    let (authority_evidence_root, authority_state) =
        match authority_result {
            V2OperationResult::Authority(
                V2AuthorityResult::Ready {
                    attempt,
                    authority_evidence_root,
                    authority_state,
                },
            ) if client.native_staging || cursor.advance(
                &authority,
                V2AttemptState::AuthorityReady,
                &authority_state.evidence_sha256,
                attempt.clone(),
            ) => {
                (authority_evidence_root, authority_state)
            }
            V2OperationResult::Authority(
                V2AuthorityResult::Terminalized {
                    attempt,
                    terminal_evidence,
                },
            ) if cursor.advance(
                &authority,
                V2AttemptState::Terminalized,
                &terminal_evidence.evidence_sha256,
                attempt.clone(),
            ) => {
                return Err(
                    ResponseObservationV2TransactionError::Denied,
                )
            }
            _ => {
                return Err(
                    ResponseObservationV2TransactionError::InvalidResponse,
                )
            }
        };

    let stage_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let credential_template = json!({
        "apiVersion":"serverware.responseObservationV2CredentialTemplate/v1",
        "injectionPlan":injection_plan,
        "credentialRequired":
            credential_binding_sha256.is_some(),
        "credentialBindingSha256":
            credential_binding_sha256,
    });
    let credential_template_bytes =
        custody_canonical_json_bytes(&credential_template)
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    let credential_free_request =
        response_observation_v2_http11_request(
            request,
            upstream_url,
            provider_headers,
        )?;
    // The selected real ledger requires its source-created content address;
    // the exact descriptor retained by Stage and target dispatch uses that ID.
    let staged_object_id=if client.native_staging {
        format!("obj:{}",&sha256_prefixed(&credential_free_request)[7..])
    }else{format!("{attempt_id}-credential-free-request")};
    let stage_objects = vec![
        response_observation_v2_exact_input(
            &format!("{attempt_id}-credential-template"),
            ExactObjectMediaType::CanonicalJson,
            0,
            &credential_template_bytes,
            lifecycle_deadline,
        )?,
        response_observation_v2_exact_input(
            &staged_object_id,
            ExactObjectMediaType::Http11Request,
            1,
            &credential_free_request,
            lifecycle_deadline,
        )?,
    ];
    let staged_input_original = stage_objects[1].descriptor.clone();
    let credential_reference = credential_id
        .zip(credential_generation)
        .map(|(credential_id, credential_generation)| {
            CredentialReference {
                credential_id: credential_id.to_owned(),
                credential_generation,
                credential_binding_sha256:
                    credential_binding_sha256
                        .clone()
                        .unwrap_or_default(),
            }
        });
    let stage = V2OperationRequest::Stage {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: stage_request_id.clone(),
        boot_id: Some(client.boot_id.clone()),
        params: V2StageParams {
            binding: cursor.operation_binding(
                &stage_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            authority_state,
            credential_template:
                stage_objects[0].descriptor.clone(),
            credential_reference,
            credential_free_request:
                stage_objects[1].descriptor.clone(),
        },
    };
    let stage_result=if client.native_staging {
        super::staging_client::execute(state,snapshot,decision,&session,&mut cursor,&stage,stage_objects,
            &mut staging_previous,&stable_resume_id)?
    }else{session.execute(&stage,stage_objects)?.result};
    let (staged_request, staging_evidence) =
        match stage_result {
            V2OperationResult::Stage(V2StageResult {
                attempt,
                staged_request,
                staging_evidence,
            }) if client.native_staging || cursor.advance(
                &stage,
                V2AttemptState::Staged,
                &staging_evidence.evidence_sha256,
                attempt.clone(),
            ) => {
                (staged_request, staging_evidence)
            }
            _ => {
                return Err(
                    ResponseObservationV2TransactionError::OutcomeUnknown,
                )
            }
        };

    let mut native_response_guard = None;
    let (dispatch_evidence, upstream_response) = if client.guest_listener.is_some() {
        let (evidence, object, guard) = super::target_dispatch_client::execute_native_capture(
            state, snapshot, decision, request, upstream_url, provider_headers, injection_plan,
            &session, &mut cursor, &stable_resume_id, &staged_request, &staged_input_original,
            &credential_free_request, shadow_finalization, shadow_dispatch_barrier_crossed,
        )?;
        native_response_guard = Some(guard);
        (evidence, object)
    } else {
    let live_authorization_evidence =
        response_observation_v2_dispatch_authorization(
            snapshot,
            release_authorization,
        )?;
    let live_authorization_evidence_bytes =
        custody_canonical_json_bytes(
            &live_authorization_evidence,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let policy_snapshot = json!({
        "apiVersion":"serverware.responseObservationV2PolicySnapshot/v1",
        "policyId":snapshot.policy_id,
        "policySha256":snapshot.hash,
        "policySequence":snapshot.policy_sequence,
        "rollbackEpoch":snapshot.rollback_epoch,
        "trustGeneration":snapshot.trust_generation,
        "policySigningKeyId":snapshot.policy_signing_key_id,
        "decision":decision,
        "authorityEvidenceRoot":authority_evidence_root,
    });
    let policy_snapshot_bytes =
        custody_canonical_json_bytes(&policy_snapshot)
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    let dispatch_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let dispatch_objects = vec![
        response_observation_v2_exact_input(
            &format!("{attempt_id}-live-policy"),
            ExactObjectMediaType::CanonicalJson,
            0,
            &policy_snapshot_bytes,
            lifecycle_deadline,
        )?,
        response_observation_v2_exact_input(
            &format!("{attempt_id}-live-authorization"),
            ExactObjectMediaType::EvidenceBundle,
            1,
            &live_authorization_evidence_bytes,
            lifecycle_deadline,
        )?,
    ];
    let dispatch = V2OperationRequest::Dispatch {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: dispatch_request_id.clone(),
        boot_id: Some(client.boot_id.clone()),
        params: V2DispatchParams {
            binding: cursor.operation_binding(
                &dispatch_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            staged_request: staged_request.clone(),
            staging_evidence: staging_evidence.clone(),
            live_policy_snapshot:
                dispatch_objects[0].descriptor.clone(),
            authorization_evidence:
                dispatch_objects[1].descriptor.clone(),
        },
    };
    let final_request_commitment =
        staged_request.object_sha256.clone();
    let mut shadow_dispatch_permit =
        match shadow_finalization {
            Some(finalization) => {
                let permit =
                    record_shadow_dispatch_barrier_with_commitment(
                        snapshot,
                        finalization,
                        decision,
                        true,
                        final_request_commitment.clone(),
                    )
                    .map_err(|_| {
                        ResponseObservationV2TransactionError::Unavailable
                    })?;
                if permit.as_ref().is_none_or(|permit| {
                    !permit.authorizes_credentialed_send(
                        &final_request_commitment,
                    )
                }) {
                    return Err(
                        ResponseObservationV2TransactionError::Unavailable,
                    );
                }
                permit
            }
            None => None,
        };
    *shadow_dispatch_barrier_crossed =
        shadow_dispatch_permit.is_some();
    let dispatch_reply =
        match session.execute(&dispatch, dispatch_objects) {
            Ok(reply) => reply,
            Err(error) => {
                if let Some(permit) =
                    shadow_dispatch_permit.take()
                {
                    let effect_sha256 =
                        digest_json_ensure_ascii(&json!({
                            "domain":"serverware.policyShadowCustodyDispatchResult/v1",
                            "requestSha256":final_request_commitment,
                            "outcome":"custody-dispatch-unknown",
                        }));
                    permit
                        .commit_provider_send(
                            ActiveEffectCommitState::OutcomeUnknown,
                            &effect_sha256,
                        )
                        .map_err(|_| {
                            ResponseObservationV2TransactionError::OutcomeUnknown
                        })?;
                }
                return Err(error);
            }
        };
    let (dispatch_evidence, upstream_response) =
        match dispatch_reply.result {
            V2OperationResult::Dispatch(V2DispatchResult {
                attempt,
                dispatch_evidence,
                upstream_response,
            }) if cursor.advance(
                &dispatch,
                V2AttemptState::Dispatched,
                &dispatch_evidence.evidence_sha256,
                attempt.clone(),
            ) => {
                if let Some(permit) =
                    shadow_dispatch_permit.take()
                {
                    let effect_sha256 =
                        digest_json_ensure_ascii(&json!({
                            "domain":"serverware.policyShadowCustodyDispatchResult/v1",
                            "requestSha256":&final_request_commitment,
                            "dispatchEvidenceSha256":
                                &dispatch_evidence.evidence_sha256,
                            "upstreamResponseSha256":
                                &upstream_response.object_sha256,
                            "outcome":"response-observed",
                        }));
                    permit
                        .commit_provider_send(
                            ActiveEffectCommitState::Committed,
                            &effect_sha256,
                        )
                        .map_err(|_| {
                            ResponseObservationV2TransactionError::OutcomeUnknown
                        })?;
                }
                (dispatch_evidence, upstream_response)
            }
            _ => {
                if let Some(permit) =
                    shadow_dispatch_permit.take()
                {
                    let effect_sha256 =
                        digest_json_ensure_ascii(&json!({
                            "domain":"serverware.policyShadowCustodyDispatchResult/v1",
                            "requestSha256":&final_request_commitment,
                            "outcome":"invalid-custody-terminal",
                        }));
                    let _ = permit.commit_provider_send(
                        ActiveEffectCommitState::OutcomeUnknown,
                        &effect_sha256,
                    );
                }
                return Err(
                    ResponseObservationV2TransactionError::OutcomeUnknown,
                )
            }
        };
    (dispatch_evidence, upstream_response)
    };
    transaction.upstream_response_sha256 =
        Some(upstream_response.object_sha256.clone());
    cursor.transaction = transaction.clone();

    let terminal_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let lifecycle_evidence = json!({
        "apiVersion":"serverware.responseObservationV2LifecycleState/v1",
        "transaction":transaction,
        "stagedRequest":staged_request,
        "stagingEvidence":staging_evidence,
        "dispatchEvidence":dispatch_evidence,
        "upstreamResponse":upstream_response,
        "terminalKind":"COMPLETED",
    });
    let lifecycle_evidence_bytes =
        custody_canonical_json_bytes(&lifecycle_evidence)
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    let terminal_objects = vec![
        response_observation_v2_exact_input(
            &format!("{attempt_id}-lifecycle"),
            ExactObjectMediaType::EvidenceBundle,
            0,
            &lifecycle_evidence_bytes,
            lifecycle_deadline,
        )?,
    ];
    let terminal = V2OperationRequest::Terminal {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: terminal_request_id.clone(),
        boot_id: Some(client.boot_id.clone()),
        params: V2TerminalParams {
            binding: cursor.operation_binding(
                &terminal_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            terminal_kind: V2TerminalKind::Completed,
            lifecycle_state:
                terminal_objects[0].descriptor.clone(),
            upstream_response: Some(upstream_response.clone()),
        },
    };
    let terminal_evidence =
        match session
            .execute(&terminal, terminal_objects)?
            .result
        {
            V2OperationResult::Terminal(V2TerminalResult {
                attempt,
                terminal_evidence,
            }) if cursor.advance(
                &terminal,
                V2AttemptState::Completed,
                &terminal_evidence.evidence_sha256,
                attempt.clone(),
            ) => terminal_evidence,
            _ => {
                return Err(
                    ResponseObservationV2TransactionError::InvalidResponse,
                )
            }
        };

    let transparency_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let transparency_trust_pin_sha256 =
        canonical_transparency_sha256(
            client.transparency_trust_pin.as_ref(),
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let append_transparency =
        V2ResponseDataRequest::AppendReleaseTransparency {
            api_version:
                RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id: transparency_request_id.clone(),
            boot_id: client.boot_id.clone(),
            params: V2AppendReleaseTransparencyParams {
                binding: cursor.operation_binding(
                    &transparency_request_id,
                    &client.boot_id,
                    &client.authenticated_client_identity_sha256,
                ),
                stable_resume_id: stable_resume_id.clone(),
                raw_response: upstream_response.clone(),
                transparency_trust_pin_sha256,
            },
        };
    let transparency_predecessor = cursor.attempt.clone();
    let mut first_transparency_attempt = true;
    let transparency_reply = loop {
        let result = if first_transparency_attempt {
            first_transparency_attempt = false;
            session.execute_response_data(
                &append_transparency,
                Vec::new(),
            )
        } else {
            session = ResponseObservationV2Session::open(
                client,
                lifecycle_deadline,
                monotonic_deadline.clone(),
                deadline_at_epoch_ms,
            )
            .map_err(|error| {
                error.with_resume(
                    &attempt_id,
                    &stable_resume_id,
                )
            })?;
            session.execute_response_data(
                &append_transparency,
                Vec::new(),
            )
        };
        match result {
            Ok(reply) => break reply,
            Err(
                ResponseObservationV2TransactionError::OutcomeUnknown
                | ResponseObservationV2TransactionError::Unavailable,
            ) if !lifecycle_deadline.expired() => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(error.with_resume(
                    &attempt_id,
                    &stable_resume_id,
                ))
            }
        }
    };
    let (
        transparency_attempt,
        transparency_evidence_id,
        appended_transparency_artifact,
        appended_transparency_artifact_sha256,
    ) = match transparency_reply {
        ResponseObservationV2ResponseDataReply {
            result:
                V2ResponseDataResult::AppendReleaseTransparency(
                    V2AppendReleaseTransparencyResult {
                        attempt,
                        evidence_id,
                        transparency_artifact,
                        transparency_artifact_sha256,
                    },
                ),
            exact_bytes,
            ..
        } if exact_bytes.is_empty() => (
            attempt,
            evidence_id,
            transparency_artifact,
            transparency_artifact_sha256,
        ),
        _ => {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            )
        }
    };
    let canonical_transparency_artifact_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(
            &appended_transparency_artifact,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    if transparency_attempt.attempt_id
            != transparency_predecessor.attempt_id
        || transparency_attempt.state != V2AttemptState::Completed
        || transparency_attempt.attempt_revision
            != transparency_predecessor
                .attempt_revision
                .saturating_add(1)
        || transparency_attempt.fencing_token
            != transparency_predecessor.fencing_token
        || !is_sha256_digest(&transparency_attempt.state_sha256)
        || transparency_evidence_id
            != format!(
                "{transparency_request_id}:release-transparency-evidence"
            )
        || appended_transparency_artifact_sha256
            != canonical_transparency_artifact_sha256
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    cursor.attempt = transparency_attempt;

    let inspect_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let inspect = V2ResponseDataRequest::InspectImmutableResponse {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: inspect_request_id.clone(),
        boot_id: client.boot_id.clone(),
        params: V2InspectImmutableResponseParams {
            binding: cursor.read_binding(
                &inspect_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            stable_resume_id: stable_resume_id.clone(),
            raw_response: upstream_response.clone(),
            request_method: request.method.clone(),
        },
    };
    let inspect_request_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(&inspect).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let inspect_reply =
        session.execute_response_data(&inspect, Vec::new())?;
    let inspection = match inspect_reply.result {
        V2ResponseDataResult::InspectImmutableResponse(
            V2InspectImmutableResponseResult { inspection },
        ) if inspect_reply.exact_bytes.is_empty() => inspection,
        _ => {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            )
        }
    };
    response_observation_v2_validate_immutable_inspection(
        client,
        &inspection,
        &inspect_request_sha256,
        &inspect_request_id,
        &cursor.attempt,
        &stable_resume_id,
        &upstream_response,
        &request.method,
    )?;
    if inspection
        .authority_proof_seed
        .authority_artifacts
        .last()
        != Some(&appended_transparency_artifact)
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }

    let authority_proof_seed_sha256 =
        inspection.authority_proof_seed.seed_sha256.clone();
    let authority_prerequisites_root_sha256 = inspection
        .authority_proof_seed
        .authority_artifacts_root_sha256
        .clone();
    if !is_sha256_digest(&authority_proof_seed_sha256)
        || !is_sha256_digest(
            &authority_prerequisites_root_sha256,
        )
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let exact_replay_key_sha256 =
        digest_json_ensure_ascii(&json!({
            "apiVersion":
                "serverware.responseObservationV2ExactReplayKey/v2",
            "generationId":&client.generation_id,
            "generation":client.provider_generation,
            "requestSha256":client_request_sha256,
            "attemptId":&attempt_id,
            "stableResumeId":&stable_resume_id,
            "rawResponseSha256":
                &upstream_response.object_sha256,
            "authorityProofSeedSha256":
                &authority_proof_seed_sha256,
            "authorityPrerequisitesRootSha256":
                &authority_prerequisites_root_sha256,
        }));
    let authorize_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let authorize = V2ResponseDataRequest::AuthorizeExactRelease {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: authorize_request_id.clone(),
        boot_id: client.boot_id.clone(),
        params: V2AuthorizeExactReleaseParams {
            binding: cursor.read_binding(
                &authorize_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            stable_resume_id: stable_resume_id.clone(),
            inspection: inspection.clone(),
            authority_proof_seed_sha256:
                authority_proof_seed_sha256.clone(),
            authority_prerequisites_root_sha256:
                authority_prerequisites_root_sha256.clone(),
            policy_decision_sha256:
                sha256_prefixed(&decision_bytes),
            exact_replay_key_sha256:
                exact_replay_key_sha256.clone(),
            expires_at_epoch_ms:
                execution
                    .context
                    .nonce_expires_at_epoch_ms
                    .min(deadline_at_epoch_ms),
        },
    };
    let authorize_request_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(&authorize).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let authorize_reply =
        session.execute_response_data(&authorize, Vec::new())?;
    let exact_release_authorization = match authorize_reply.result {
        V2ResponseDataResult::AuthorizeExactRelease(
            V2AuthorizeExactReleaseResult { authorization },
        ) if authorize_reply.exact_bytes.is_empty() => authorization,
        _ => {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            )
        }
    };
    response_observation_v2_validate_exact_release_authorization(
        client,
        &exact_release_authorization,
        &authorize_request_sha256,
        &authorize_request_id,
        &cursor.attempt,
        &stable_resume_id,
        &inspection,
        &authority_proof_seed_sha256,
        &authority_prerequisites_root_sha256,
        &sha256_prefixed(&decision_bytes),
        &exact_replay_key_sha256,
    )?;

    let prepare_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let prepare = V2ResponseDataRequest::ConsumeAndRetrieveExact {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: prepare_request_id.clone(),
        boot_id: client.boot_id.clone(),
        params: V2ConsumeAndRetrieveExactParams::Prepare {
            binding: cursor.operation_binding(
                &prepare_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            stable_resume_id: stable_resume_id.clone(),
            object: upstream_response.clone(),
            release_authorization:
                exact_release_authorization.clone(),
            inspection: inspection.clone(),
            exact_replay_key_sha256:
                exact_replay_key_sha256.clone(),
        },
    };
    let prepare_request_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(&prepare).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let prepare_predecessor = cursor.attempt.clone();
    let prepare_reply =
        session.execute_response_data(&prepare, Vec::new())?;
    let (prepared_attempt, release_preparation) =
        match prepare_reply.result {
            V2ResponseDataResult::ConsumeAndRetrieveExact(
                V2ConsumeAndRetrieveExactResult::Prepared {
                    attempt,
                    preparation,
                },
            ) if prepare_reply.exact_bytes.is_empty() => {
                (attempt, preparation)
            }
            _ => {
                return Err(
                    ResponseObservationV2TransactionError::
                        OutcomeUnknown,
                )
            }
        };
    response_observation_v2_validate_exact_release_preparation(
        client,
        &release_preparation,
        &prepare_request_sha256,
        &prepare_request_id,
        &prepare_predecessor,
        &prepared_attempt,
        &stable_resume_id,
        &inspection,
        &exact_release_authorization,
        &authority_proof_seed_sha256,
        &authority_prerequisites_root_sha256,
        &exact_replay_key_sha256,
    )?;
    cursor.attempt = prepared_attempt;

    let validate_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let transition_chain_bytes =
        custody_canonical_json_bytes(&json!({
            "domain":
                "serverware.responseObservationTransitionChain/v1",
            "attempt":&cursor.attempt,
            "authorityEvidenceRoot":&authority_evidence_root,
            "stagingEvidence":&staging_evidence,
            "dispatchEvidence":&dispatch_evidence,
            "terminalEvidence":&terminal_evidence,
            "releaseAuthorization":
                &exact_release_authorization,
            "releasePreparation":&release_preparation,
        }))
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let transition_chain_sha256 =
        sha256_prefixed(&transition_chain_bytes);
    let finalization_id =
        digest_json_ensure_ascii(&json!({
            "apiVersion":
                "serverware.responseObservationV2FinalizationId/v1",
            "generationId":&client.generation_id,
            "generation":client.provider_generation,
            "attemptId":&attempt_id,
            "stableResumeId":&stable_resume_id,
            "terminalRevision":cursor.attempt.attempt_revision,
            "fencingToken":cursor.attempt.fencing_token,
            "rawResponseObjectSha256":
                &upstream_response.object_sha256,
            "transitionChainRootSha256":
                &transition_chain_sha256,
            "releasePreparationReceiptSha256":
                &release_preparation
                    .state_mutation_receipt_sha256,
        }));
    let release_authorization_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(
            &exact_release_authorization.authority_receipt,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let mut proof_document = V2CanonicalFinalEnvelopeV1 {
        api_version:
            V2_CANONICAL_FINAL_ENVELOPE_VERSION.to_owned(),
        generation_id: client.generation_id.clone(),
        generation: client.provider_generation,
        request_id: validate_request_id.clone(),
        request_sha256: client_request_sha256.to_owned(),
        attempt_id: attempt_id.clone(),
        stable_resume_id: stable_resume_id.clone(),
        finalization_id,
        terminal_revision: cursor.attempt.attempt_revision,
        fencing_token: cursor.attempt.fencing_token,
        transition_chain_root_sha256:
            transition_chain_sha256,
        authority_artifacts_root_sha256: String::new(),
        raw_response_object_sha256:
            upstream_response.object_sha256.clone(),
        raw_response_byte_length:
            upstream_response.byte_length,
        framing_validation_sha256:
            inspection.framing_validation_sha256.clone(),
        parsed_response_sha256:
            inspection.parsed_response_sha256.clone(),
        exact_policy_decision_sha256:
            sha256_prefixed(&decision_bytes),
        released_projection_sha256:
            inspection.released_projection_sha256.clone(),
        release_authorization_sha256,
        evidence_root_sha256:
            authority_evidence_root.evidence_sha256.clone(),
        final_envelope_sha256: String::new(),
    };
    let (proof_document_bytes, authority_proof) =
        response_observation_v2_authority_proof_input(
            &inspection,
            &release_preparation,
            &proof_document,
        )?;
    let nested_preverification_epoch_ms =
        u64::try_from(crate::now_epoch_ms()).map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let verified_nested_authority_artifacts =
        response_observation_v2_preverify_nested_authority_artifacts(
            client,
            &release_preparation
                .authority_receipt
                .release_preparation_artifact,
            &inspection
                .authority_proof_seed
                .authority_artifacts,
            &attempt_id,
            cursor.attempt.attempt_revision,
            cursor.attempt.fencing_token,
            nested_preverification_epoch_ms,
        )?;
    response_observation_v2_preverify_nested_authority_semantics(
        client,
        &authority_proof,
        &inspection,
        &release_preparation,
    )?;
    let validation_objects = vec![
        response_observation_v2_exact_input(
            &format!("{attempt_id}-proof"),
            ExactObjectMediaType::CanonicalJson,
            0,
            &proof_document_bytes,
            lifecycle_deadline,
        )?,
    ];
    let validate = V2ResponseDataRequest::ValidateFinalEnvelope {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: validate_request_id.clone(),
        boot_id: client.boot_id.clone(),
        params: V2ValidateFinalEnvelopeParams {
            binding: cursor.operation_binding(
                &validate_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            stable_resume_id: stable_resume_id.clone(),
            terminal_evidence: terminal_evidence.clone(),
            inspection: inspection.clone(),
            release_preparation:
                release_preparation.clone(),
            http11_framing:
                inspection.http11_framing.clone(),
            parsed_response:
                inspection.parsed_response.clone(),
            authority_proof:
                validation_objects[0].descriptor.clone(),
        },
    };
    let validate_request_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(&validate).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let validation_predecessor = cursor.attempt.clone();
    let (
        envelope,
        finalization_checkpoint,
        finalized_response,
        final_envelope_verification,
    ) = match session
        .execute_response_data(&validate, validation_objects)?
    {
        ResponseObservationV2ResponseDataReply {
            result: V2ResponseDataResult::ValidateFinalEnvelope(
                V2ValidateFinalEnvelopeResult {
            attempt,
            envelope,
            persistence_evidence: _,
            finalization_checkpoint,
            finalized_response,
            canonical_authority_envelope,
            authority_artifacts_root_sha256,
            verification,
                },
            ),
            exact_bytes,
            ..
        } if exact_bytes.is_empty()
            && attempt.attempt_id == cursor.attempt.attempt_id
            && attempt.state == V2AttemptState::Finalized
            && attempt.attempt_revision
                == cursor.attempt.attempt_revision.saturating_add(1)
            && attempt.fencing_token == cursor.attempt.fencing_token
            && is_sha256_digest(&attempt.state_sha256)
            && finalized_response.object_sha256
                == upstream_response.object_sha256
            && finalized_response.byte_length
                == upstream_response.byte_length
            && authority_artifacts_root_sha256
                == canonical_authority_envelope
                    .authority_artifacts_root_sha256
            && authority_artifacts_root_sha256
                == canonical_authority_envelope
                    .public_envelope
                    .authority_artifacts_root_sha256 =>
        {
            let verification_epoch_ms =
                u64::try_from(crate::now_epoch_ms()).map_err(|_| {
                    ResponseObservationV2TransactionError::Unavailable
                })?;
            response_observation_v2_verify_nested_authority_envelope(
                client,
                &canonical_authority_envelope,
                &release_preparation
                    .authority_receipt
                    .release_preparation_artifact,
                &inspection
                    .authority_proof_seed
                    .authority_artifacts,
                &proof_document,
                &verified_nested_authority_artifacts,
                verification_epoch_ms,
            )?;
            response_observation_v2_verify_nested_authority_semantics(
                client,
                &canonical_authority_envelope,
                &inspection,
                &release_preparation,
            )?;
            proof_document =
                canonical_authority_envelope.public_envelope.clone();
            response_observation_v2_validate_final_verification(
                client,
                &verification,
                &validate_request_sha256,
                &validate_request_id,
                &validation_predecessor,
                attempt.attempt_revision,
                &stable_resume_id,
                &canonical_authority_envelope,
                &proof_document,
                &inspection,
            )?;
            cursor.attempt = attempt;
            (
            envelope,
            finalization_checkpoint,
            finalized_response,
            verification,
            )
        }
        _ => {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            )
        }
    };

    let retrieve_request_id =
        canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let retrieve = V2ResponseDataRequest::ConsumeAndRetrieveExact {
        api_version: RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: retrieve_request_id.clone(),
        boot_id: client.boot_id.clone(),
        params: V2ConsumeAndRetrieveExactParams::Retrieve {
            binding: cursor.read_binding(
                &retrieve_request_id,
                &client.boot_id,
                &client.authenticated_client_identity_sha256,
            ),
            stable_resume_id: stable_resume_id.clone(),
            object: finalized_response.clone(),
            preparation: release_preparation.clone(),
            final_envelope_verification:
                final_envelope_verification.clone(),
            exact_replay_key_sha256:
                exact_replay_key_sha256.clone(),
        },
    };
    let retrieve_request_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(&retrieve).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let mut retrieve_reply =
        session.execute_response_data(&retrieve, Vec::new())?;
    let consumption = match &retrieve_reply.result {
        V2ResponseDataResult::ConsumeAndRetrieveExact(
            V2ConsumeAndRetrieveExactResult::Retrieved {
                object,
                exact_bytes,
                consumption,
                ..
            },
        ) if object == &finalized_response
            && exact_bytes == &consumption.exact_object =>
        {
            consumption.clone()
        }
        _ => {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            )
        }
    };
    response_observation_v2_validate_exact_release_consumption(
        client,
        &consumption,
        &retrieve_request_sha256,
        &retrieve_request_id,
        &cursor.attempt,
        &stable_resume_id,
        &release_preparation,
        &inspection,
        &final_envelope_verification,
        &exact_replay_key_sha256,
    )?;
    if retrieve_reply.exact_bytes.len() != 1 {
        return Err(
            ResponseObservationV2TransactionError::OutcomeUnknown,
        );
    }
    let response_bytes = retrieve_reply
        .exact_bytes
        .remove(&consumption.exact_object.fd_index)
        .ok_or(
            ResponseObservationV2TransactionError::OutcomeUnknown,
        )?;
    let parsed = response_observation_v2_parse_immutable_http11(
        &response_bytes,
        &finalized_response,
        &request.method,
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::OutcomeUnknown
            .with_resume(&attempt_id, &stable_resume_id)
    })?;
    if parsed.status != inspection.response_status
        || parsed.framing != inspection.http11_framing
        || parsed.parsed_response != inspection.parsed_response
        || parsed.framing.canonical_framing_sha256
            != inspection.framing_validation_sha256
        || sha256_prefixed(
            &custody_canonical_json_bytes(
                &parsed.parsed_response,
            )
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?,
        ) != inspection.parsed_response_sha256
        || sha256_prefixed(&parsed.entity_body)
            != inspection.response_body_sha256
        || digest_json_ensure_ascii(&json!({
            "apiVersion":
                "serverware.responseObservationV2ReleasedProjection/v2",
            "rawResponseSha256":
                &inspection.raw_response.object_sha256,
            "rawResponseByteLength":
                inspection.raw_response.byte_length,
            "requestMethod":&request.method,
            "responseStatus":parsed.status,
            "framingValidationSha256":
                &inspection.framing_validation_sha256,
            "parsedResponseSha256":
                &inspection.parsed_response_sha256,
            "responseBodySha256":
                sha256_prefixed(&parsed.entity_body),
        })) != inspection.released_projection_sha256
    {
        return Err(
            ResponseObservationV2TransactionError::OutcomeUnknown
                .with_resume(&attempt_id, &stable_resume_id),
        );
    }
    if native_response_guard.as_ref().is_some_and(|guard|
        guard.detects(&response_bytes) || guard.detects(&parsed.entity_body)) {
        return Err(ResponseObservationV2TransactionError::Denied);
    }
    if let Some(release) = release_authorization.as_mut() {
        let response_evidence = vec![json!({
            "type":"responseObservationV2FinalizedRelease",
            "attemptId":attempt_id,
            "envelope":envelope,
            "finalizationCheckpoint":finalization_checkpoint,
            "releasedObject":finalized_response,
            "inspectionReceiptSha256":
                inspection.inspection_receipt_sha256,
            "finalEnvelopeVerificationSha256":
                final_envelope_verification
                    .verification_result_sha256,
            "releaseAuthorizationId":
                exact_release_authorization.authorization_id,
            "releasePreparationReceiptSha256":
                release_preparation
                    .state_mutation_receipt_sha256,
            "releaseRetrievalReceiptSha256":
                consumption.retrieval_receipt_sha256,
            "exactReplayKeySha256":
                exact_replay_key_sha256,
            "responseSha256":sha256_prefixed(&response_bytes),
        })];
        let completion = DurablePolicyCompletionEvidence {
            validated: true,
            response_evidence_digest:
                digest_json_ensure_ascii(&Value::Array(
                    response_evidence.clone(),
                )),
            response_evidence,
            response_body_sha256:
                sha256_prefixed(&parsed.entity_body),
        };
        let releasable = if release.requires_response_evidence() {
            release.complete_forwarded_with_evidence(&completion)
        } else {
            release.complete_forwarded()
        }
        .map_err(|_| {
            ResponseObservationV2TransactionError::OutcomeUnknown
        })?;
        if !releasable {
            return Err(ResponseObservationV2TransactionError::Denied);
        }
    }
    Ok(SensitiveResponseBytes::new(response_bytes.to_vec()))
    })();
    match outcome {
        Ok(response) => Ok(response),
        Err(error) => Err(
            response_observation_v2_terminalize_failure(
                client,
                &mut cursor,
                &attempt_id,
                &stable_resume_id,
                error,
            ),
        ),
    }
}

pub(super) fn response_observation_v2_validate_response_data_provider_scope(
    client: &ResponseObservationV2Client,
    scope: &ProviderAuthorityScopeV2,
    expected_service_role: CustodyServiceRole,
    expected_logical_role: &str,
    expected_service_operation: ServiceOperationV1,
    expected_public_operation: &str,
    expected_operation_id: &str,
    expected_attempt_id: &str,
    expected_attempt_revision: u64,
    expected_fencing_token: u64,
    expected_binding_sha256: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    let pin = client
        .role_keys
        .get(expected_logical_role)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    let expected_allowed_operations: &[ServiceOperationV1] =
        match expected_service_role {
            CustodyServiceRole::CustodyRouter => {
                &[ServiceOperationV1::Readiness]
            }
            CustodyServiceRole::StateAuthority => &[
                ServiceOperationV1::Readiness,
                ServiceOperationV1::StateCas,
                ServiceOperationV1::ReplayResolve,
                ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
                ServiceOperationV1::Reconcile,
            ],
            CustodyServiceRole::CredentialTransport => {
                &[ServiceOperationV1::Readiness]
            }
            CustodyServiceRole::PolicyProofVerifier => &[
                ServiceOperationV1::Readiness,
                ServiceOperationV1::FinalEnvelopeVerify,
            ],
            CustodyServiceRole::ImmutableArtifactLedger => &[
                ServiceOperationV1::Readiness,
                ServiceOperationV1::InspectImmutableRaw,
            ],
            CustodyServiceRole::ReleaseAttestorPublisher => &[
                ServiceOperationV1::Readiness,
                ServiceOperationV1::AuthorizeRelease,
                ServiceOperationV1::Publish,
            ],
            CustodyServiceRole::CleanupWatchdog => &[
                ServiceOperationV1::Readiness,
                ServiceOperationV1::Reconcile,
                ServiceOperationV1::Cleanup,
            ],
        };
    let mut unsigned_scope = scope.clone();
    unsigned_scope.operation_binding_sha256.clear();
    let canonical_binding_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(&unsigned_scope).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    if scope.api_version
            != serverware_decision_gate::
                AUTHORITY_SCOPE_API_VERSION
        || scope.generation_id != client.generation_id
        || scope.generation != client.provider_generation
        || pin.role != expected_logical_role
        || pin.generation_id != client.generation_id
        || pin.provider_generation != client.provider_generation
        || scope.service_role != expected_service_role
        || scope.service_id != pin.provider_id
        || scope.logical_role != expected_logical_role
        || scope.role_identity_root_sha256
            != client.role_identity_root_sha256
        || scope.key_id != pin.key_id
        || scope.key_material_sha256
            != pin.key_material_sha256
        || scope.key_material_sha256 != pin.public_key_sha256
        || scope.operation != expected_service_operation
        || scope.operation_id != expected_operation_id
        || scope.attempt_id != expected_attempt_id
        || scope.attempt_revision != expected_attempt_revision
        || scope.fencing_token != expected_fencing_token
        || scope.executable_sha256
            != pin.executable_measurement_sha256
        || scope.configuration_sha256
            != pin.provider_config_sha256
        || scope.allowed_operations.as_slice()
            != expected_allowed_operations
        || !pin
            .allowed_operations
            .iter()
            .any(|operation| operation == expected_public_operation)
        || scope.operation_binding_sha256
            != canonical_binding_sha256
        || expected_binding_sha256 != canonical_binding_sha256
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    Ok(())
}

fn response_observation_v2_validate_immutable_inspection(
    client: &ResponseObservationV2Client,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    request_sha256: &str,
    request_id: &str,
    attempt: &AttemptStateReference,
    stable_resume_id: &str,
    raw_response: &ImmutableObjectReference,
    request_method: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    if inspection.api_version
        != V2_IMMUTABLE_RESPONSE_INSPECTION_VERSION
        || inspection.generation_id != client.generation_id
        || inspection.generation != client.provider_generation
        || inspection.operation
            != V2ResponseDataOperation::InspectImmutableResponse
        || inspection.request_id != request_id
        || inspection.request_sha256 != request_sha256
        || inspection.attempt_id != attempt.attempt_id
        || inspection.attempt_revision
            != attempt.attempt_revision
        || inspection.stable_resume_id != stable_resume_id
        || inspection.fencing_token != attempt.fencing_token
        || inspection.raw_response != *raw_response
        || inspection.exact_object.object_id
            != raw_response.retrieval_id
        || inspection.exact_object.sha256
            != raw_response.object_sha256
        || inspection.exact_object.byte_length
            != raw_response.byte_length
        || inspection.request_method != request_method
        || !inspection.immutable
        || inspection.consumed
        || inspection.inspection_sequence == 0
        || inspection.response_status < 100
        || !is_sha256_digest(
            &inspection.framing_validation_sha256,
        )
        || inspection.http11_framing.canonical_framing_sha256
            != inspection.framing_validation_sha256
        || inspection.parsed_response.raw_response_sha256
            != raw_response.object_sha256
        || inspection.parsed_response.raw_response_byte_length
            != raw_response.byte_length
        || inspection.parsed_response.framing_validation_sha256
            != inspection.framing_validation_sha256
        || inspection.parsed_response.final_status
            != inspection.response_status
        || !is_sha256_digest(
            &inspection.parsed_response_sha256,
        )
        || !is_sha256_digest(
            &inspection.released_projection_sha256,
        )
        || !is_sha256_digest(
            &inspection.response_body_sha256,
        )
        || !is_sha256_digest(
            &inspection.inspection_receipt_sha256,
        )
        || inspection.signer_logical_role != "persistence"
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    response_observation_v2_validate_response_data_provider_scope(
        client,
        &inspection.provider_scope,
        CustodyServiceRole::ImmutableArtifactLedger,
        "persistence",
        ServiceOperationV1::InspectImmutableRaw,
        V2_INSPECT_IMMUTABLE_RESPONSE_OPERATION,
        request_id,
        &attempt.attempt_id,
        attempt.attempt_revision,
        attempt.fencing_token,
        &inspection.provider_operation_binding_sha256,
    )?;
    let mut unsigned = inspection.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature(
        client,
        "persistence",
        V2_INSPECT_IMMUTABLE_RESPONSE_OPERATION,
        &inspection.signer_provider_id,
        inspection.generation,
        &inspection.signer_key_id,
        &inspection.signer_key_material_sha256,
        &signature,
        &unsigned,
    )
}

fn response_observation_v2_validate_final_verification(
    client: &ResponseObservationV2Client,
    verification: &SignedV2FinalEnvelopeVerificationV1,
    request_sha256: &str,
    request_id: &str,
    predecessor: &AttemptStateReference,
    finalized_revision: u64,
    stable_resume_id: &str,
    canonical_authority_envelope:
        &serverware_decision_gate::
            CanonicalAuthorityEnvelopeDescriptorV2,
    envelope: &V2CanonicalFinalEnvelopeV1,
    inspection: &SignedV2ImmutableResponseInspectionV1,
) -> Result<(), ResponseObservationV2TransactionError> {
    serverware_decision_gate::validate_canonical_authority_envelope(
        canonical_authority_envelope,
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    let canonical_envelope_bytes_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(
            canonical_authority_envelope,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let final_envelope_sha256 =
        serverware_decision_gate::
            canonical_authority_envelope_preimage_sha256(
                canonical_authority_envelope,
            )
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    if verification.api_version
        != V2_FINAL_ENVELOPE_VERIFICATION_VERSION
        || verification.generation_id != client.generation_id
        || verification.generation != client.provider_generation
        || verification.operation
            != V2ResponseDataOperation::ValidateFinalEnvelope
        || verification.request_id != request_id
        || verification.request_sha256 != request_sha256
        || verification.attempt_id != predecessor.attempt_id
        || verification.attempt_revision != finalized_revision
        || verification.stable_resume_id != stable_resume_id
        || verification.fencing_token
            != predecessor.fencing_token
        || verification.final_envelope_sha256
            != envelope.final_envelope_sha256
        || canonical_authority_envelope.public_envelope
            != *envelope
        || verification.authority_artifacts_root_sha256
            != envelope.authority_artifacts_root_sha256
        || envelope.final_envelope_sha256
            != final_envelope_sha256
        || verification.canonical_envelope_bytes_sha256
            != canonical_envelope_bytes_sha256
        || verification.transition_chain_root_sha256
            != envelope.transition_chain_root_sha256
        || verification.raw_response_sha256
            != inspection.raw_response.object_sha256
        || verification.framing_validation_sha256
            != inspection.framing_validation_sha256
        || verification.parsed_response_sha256
            != inspection.parsed_response_sha256
        || !verification.verified
        || verification.verification_sequence == 0
        || !is_sha256_digest(
            &verification.verification_result_sha256,
        )
        || verification.signer_logical_role
            != "live-proof-verifier"
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    response_observation_v2_validate_response_data_provider_scope(
        client,
        &verification.provider_scope,
        CustodyServiceRole::PolicyProofVerifier,
        "live-proof-verifier",
        ServiceOperationV1::FinalEnvelopeVerify,
        V2_VALIDATE_FINAL_ENVELOPE_OPERATION,
        request_id,
        &predecessor.attempt_id,
        predecessor.attempt_revision,
        predecessor.fencing_token,
        &verification.provider_operation_binding_sha256,
    )?;
    let mut unsigned = verification.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature(
        client,
        "live-proof-verifier",
        V2_VALIDATE_FINAL_ENVELOPE_OPERATION,
        &verification.signer_provider_id,
        verification.generation,
        &verification.signer_key_id,
        &verification.signer_key_material_sha256,
        &signature,
        &unsigned,
    )
}

fn response_observation_v2_validate_exact_release_authorization(
    client: &ResponseObservationV2Client,
    authorization: &SignedV2ExactReleaseAuthorizationV2,
    request_sha256: &str,
    request_id: &str,
    attempt: &AttemptStateReference,
    stable_resume_id: &str,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    authority_proof_seed_sha256: &str,
    authority_prerequisites_root_sha256: &str,
    policy_decision_sha256: &str,
    exact_replay_key_sha256: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    if authorization.api_version
        != V2_EXACT_RELEASE_AUTHORIZATION_VERSION
        || authorization.generation_id != client.generation_id
        || authorization.generation != client.provider_generation
        || authorization.operation
            != V2ResponseDataOperation::AuthorizeExactRelease
        || authorization.request_id != request_id
        || authorization.request_sha256 != request_sha256
        || authorization.attempt_id != attempt.attempt_id
        || authorization.attempt_revision
            != attempt.attempt_revision
        || authorization.stable_resume_id != stable_resume_id
        || authorization.fencing_token != attempt.fencing_token
        || authorization.authorization_id.is_empty()
        || authorization.inspection_receipt_sha256
            != inspection.inspection_receipt_sha256
        || authorization.authority_proof_seed_sha256
            != authority_proof_seed_sha256
        || authorization.authority_prerequisites_root_sha256
            != authority_prerequisites_root_sha256
        || authorization.raw_response_sha256
            != inspection.raw_response.object_sha256
        || authorization.policy_decision_sha256
            != policy_decision_sha256
        || authorization.exact_replay_key_sha256
            != exact_replay_key_sha256
        || authorization.expires_at_epoch_ms == 0
        || !is_sha256_digest(
            &authorization.authorization_result_sha256,
        )
        || authorization.signer_logical_role != "public-release"
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    response_observation_v2_validate_response_data_provider_scope(
        client,
        &authorization.provider_scope,
        CustodyServiceRole::ReleaseAttestorPublisher,
        "public-release",
        ServiceOperationV1::AuthorizeRelease,
        V2_AUTHORIZE_EXACT_RELEASE_OPERATION,
        request_id,
        &attempt.attempt_id,
        attempt.attempt_revision,
        attempt.fencing_token,
        &authorization.provider_operation_binding_sha256,
    )?;
    let mut unsigned = authorization.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature(
        client,
        "public-release",
        V2_AUTHORIZE_EXACT_RELEASE_OPERATION,
        &authorization.signer_provider_id,
        authorization.generation,
        &authorization.signer_key_id,
        &authorization.signer_key_material_sha256,
        &signature,
        &unsigned,
    )
}

fn response_observation_v2_validate_exact_release_preparation(
    client: &ResponseObservationV2Client,
    preparation: &SignedV2ExactReleasePreparationV1,
    request_sha256: &str,
    request_id: &str,
    predecessor: &AttemptStateReference,
    prepared_attempt: &AttemptStateReference,
    stable_resume_id: &str,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    authorization: &SignedV2ExactReleaseAuthorizationV2,
    authority_proof_seed_sha256: &str,
    authority_prerequisites_root_sha256: &str,
    exact_replay_key_sha256: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    let preauthorization_artifact_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(
            &preparation
                .authority_receipt
                .preauthorization
                .preauthorization_artifact,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let state_mutation_receipt_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(
            &preparation
                .authority_receipt
                .state_authority_receipt,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let release_preparation_artifact_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(
            &preparation
                .authority_receipt
                .release_preparation_artifact,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    if preparation.api_version
            != V2_EXACT_RELEASE_PREPARATION_VERSION
        || preparation.generation_id != client.generation_id
        || preparation.generation != client.provider_generation
        || preparation.operation
            != V2ResponseDataOperation::ConsumeAndRetrieveExact
        || preparation.request_id != request_id
        || preparation.request_sha256 != request_sha256
        || preparation.attempt_id != predecessor.attempt_id
        || preparation.predecessor_revision
            != predecessor.attempt_revision
        || preparation.prepared_revision
            != predecessor.attempt_revision.saturating_add(1)
        || prepared_attempt.attempt_id != predecessor.attempt_id
        || prepared_attempt.state != V2AttemptState::ReleasePrepared
        || prepared_attempt.attempt_revision
            != preparation.prepared_revision
        || prepared_attempt.fencing_token
            != predecessor.fencing_token
        || !is_sha256_digest(&prepared_attempt.state_sha256)
        || preparation.stable_resume_id != stable_resume_id
        || preparation.fencing_token != predecessor.fencing_token
        || preparation.authorization_id
            != authorization.authorization_id
        || preparation.inspection_receipt_sha256
            != inspection.inspection_receipt_sha256
        || preparation.authority_proof_seed_sha256
            != authority_proof_seed_sha256
        || preparation.authority_prerequisites_root_sha256
            != authority_prerequisites_root_sha256
        || preparation.exact_replay_key_sha256
            != exact_replay_key_sha256
        || preparation.raw_response_sha256
            != inspection.raw_response.object_sha256
        || preparation.raw_response_byte_length
            != inspection.raw_response.byte_length
        || preparation.preauthorization_artifact_sha256
            != preauthorization_artifact_sha256
        || preparation.state_mutation_receipt_sha256
            != state_mutation_receipt_sha256
        || preparation.release_preparation_artifact_sha256
            != release_preparation_artifact_sha256
        || preparation.authority_receipt.generation_id
            != preparation.generation_id
        || preparation.authority_receipt.generation
            != preparation.generation
        || preparation.authority_receipt.request_id
            != preparation.request_id
        || preparation.authority_receipt.request_sha256
            != preparation.request_sha256
        || preparation.authority_receipt.attempt_id
            != preparation.attempt_id
        || preparation.authority_receipt.stable_resume_id
            != preparation.stable_resume_id
        || preparation.authority_receipt.fencing_token
            != preparation.fencing_token
        || preparation
            .authority_receipt
            .release_authorization_id
            != preparation.authorization_id
        || preparation.authority_receipt.inspection_receipt_sha256
            != preparation.inspection_receipt_sha256
        || preparation
            .authority_receipt
            .exact_replay_key_sha256
            != preparation.exact_replay_key_sha256
        || preparation.authority_receipt.release_object_sha256
            != preparation.raw_response_sha256
        || preparation.authority_receipt.predecessor_revision
            != preparation.predecessor_revision
        || preparation.authority_receipt.predecessor_state
            != "OBSERVED"
        || preparation.authority_receipt.successor_revision
            != preparation.prepared_revision
        || preparation.authority_receipt.successor_state
            != "RELEASE_PREPARED"
        || !is_sha256_digest(
            &preparation.durable_canonical_result_sha256,
        )
        || preparation.signer_logical_role
            != "public-release-consumption"
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    response_observation_v2_validate_response_data_provider_scope(
        client,
        &preparation.provider_scope,
        CustodyServiceRole::StateAuthority,
        "public-release-consumption",
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION,
        request_id,
        &prepared_attempt.attempt_id,
        prepared_attempt.attempt_revision,
        prepared_attempt.fencing_token,
        &preparation.provider_operation_binding_sha256,
    )?;
    let mut unsigned = preparation.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature_in_domain(
        client,
        "public-release-consumption",
        V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION,
        &preparation.signer_provider_id,
        preparation.generation,
        &preparation.signer_key_id,
        &preparation.signer_key_material_sha256,
        &signature,
        &unsigned,
        serverware_decision_gate::
            V2_EXACT_RELEASE_PREPARATION_SIGNATURE_DOMAIN,
    )
}

fn response_observation_v2_validate_exact_release_consumption(
    client: &ResponseObservationV2Client,
    consumption: &SignedV2ExactReleaseConsumptionV2,
    request_sha256: &str,
    request_id: &str,
    attempt: &AttemptStateReference,
    stable_resume_id: &str,
    preparation: &SignedV2ExactReleasePreparationV1,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    verification: &SignedV2FinalEnvelopeVerificationV1,
    exact_replay_key_sha256: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    let preparation_receipt_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(preparation).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    let final_verification_sha256 = sha256_prefixed(
        &custody_canonical_json_bytes(verification).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?,
    );
    if consumption.api_version
        != V2_EXACT_RELEASE_CONSUMPTION_VERSION
        || consumption.generation_id != client.generation_id
        || consumption.generation != client.provider_generation
        || consumption.operation
            != V2ResponseDataOperation::ConsumeAndRetrieveExact
        || consumption.request_id != request_id
        || consumption.request_sha256 != request_sha256
        || consumption.attempt_id != attempt.attempt_id
        || consumption.attempt_revision
            != attempt.attempt_revision
        || consumption.stable_resume_id != stable_resume_id
        || consumption.fencing_token != attempt.fencing_token
        || consumption.preparation_receipt_sha256
            != preparation_receipt_sha256
        || consumption.final_envelope_verification_sha256
            != final_verification_sha256
        || consumption.exact_replay_key_sha256
            != exact_replay_key_sha256
        || consumption.raw_response_sha256
            != inspection.raw_response.object_sha256
        || consumption.raw_response_byte_length
            != inspection.raw_response.byte_length
        || consumption.exact_object != inspection.exact_object
        || consumption.retrieval_sequence == 0
        || !is_sha256_digest(
            &consumption.retrieval_receipt_sha256,
        )
        || !is_sha256_digest(
            &consumption.canonical_result_sha256,
        )
        || consumption.signer_logical_role
            != "public-release-consumption"
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    response_observation_v2_validate_response_data_provider_scope(
        client,
        &consumption.provider_scope,
        CustodyServiceRole::StateAuthority,
        "public-release-consumption",
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION,
        request_id,
        &attempt.attempt_id,
        attempt.attempt_revision,
        attempt.fencing_token,
        &consumption.provider_operation_binding_sha256,
    )?;
    let mut unsigned = consumption.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature(
        client,
        "public-release-consumption",
        V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION,
        &consumption.signer_provider_id,
        consumption.generation,
        &consumption.signer_key_id,
        &consumption.signer_key_material_sha256,
        &signature,
        &unsigned,
    )
}

fn response_observation_v2_terminalize_failure(
    client: &ResponseObservationV2Client,
    cursor: &mut ResponseObservationV2AttemptCursor,
    attempt_id: &str,
    stable_resume_id: &str,
    error: ResponseObservationV2TransactionError,
) -> ResponseObservationV2TransactionError {
    let (terminal_kind, error_class) = match &error {
        ResponseObservationV2TransactionError::OutcomeUnknown
        | ResponseObservationV2TransactionError::OutcomeUnknownWithAttempt(
            _,
        ) => (V2TerminalKind::OutcomeUnknown, "OUTCOME_UNKNOWN"),
        ResponseObservationV2TransactionError::Denied
        | ResponseObservationV2TransactionError::DeniedWithAttempt(_) => (
            V2TerminalKind::Failed,
            "DENIED",
        ),
        ResponseObservationV2TransactionError::Unavailable
        | ResponseObservationV2TransactionError::UnavailableWithAttempt(
            _,
        ) => (
            V2TerminalKind::Failed,
            "UNAVAILABLE",
        ),
        ResponseObservationV2TransactionError::InvalidResponse
        | ResponseObservationV2TransactionError::InvalidResponseWithAttempt(
            _,
        ) => (
            V2TerminalKind::Failed,
            "INVALID_RESPONSE",
        ),
    };
    let terminalized = (|| {
        const CLEANUP_DEADLINE_MS: u64 = 5_000;
        let cleanup_started_at_boottime_ns =
            response_observation_v2_boottime_ns().map_err(|_| ())?;
        let cleanup_deadline_at_boottime_ns =
            cleanup_started_at_boottime_ns
                .checked_add(
                    CLEANUP_DEADLINE_MS
                        .checked_mul(1_000_000)
                        .ok_or(())?,
                )
                .ok_or(())?;
        let cleanup_started_at_epoch_ms =
            u64::try_from(now_epoch_ms()).map_err(|_| ())?;
        let cleanup_deadline_at_epoch_ms =
            cleanup_started_at_epoch_ms
                .checked_add(CLEANUP_DEADLINE_MS)
                .ok_or(())?;
        let cleanup_monotonic_deadline = V2MonotonicDeadlineV1 {
            api_version:
                V2_MONOTONIC_DEADLINE_VERSION.to_owned(),
            custody_boot_id: client.boot_id.clone(),
            clock_id: V2MonotonicClockId::ClockBoottime,
            absolute_boottime_ns:
                cleanup_deadline_at_boottime_ns.to_string(),
        };
        let cleanup_session = ResponseObservationV2Session::open(
            client,
            ResponseObservationV2Deadline::from_absolute(
                cleanup_deadline_at_boottime_ns,
            ),
            cleanup_monotonic_deadline.clone(),
            cleanup_deadline_at_epoch_ms,
        )
        .map_err(|_| ())?;
        let request_id = canonical_custody_request_id().map_err(|_| ())?;
        let request = V2ResponseDataRequest::SettleAttempt {
            api_version:
                RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id: request_id.clone(),
            boot_id: client.boot_id.clone(),
            params: V2SettleAttemptParams {
                stable_resume_id: stable_resume_id.to_owned(),
                attempt: cursor.attempt.clone(),
                transaction: cursor.transaction.clone(),
                lifecycle_deadline:
                    cursor.monotonic_deadline.clone(),
                lifecycle_deadline_at_epoch_ms:
                    cursor.deadline_at_epoch_ms,
                settlement_deadline:
                    cleanup_monotonic_deadline,
                settlement_deadline_at_epoch_ms:
                    cleanup_deadline_at_epoch_ms,
                terminal_kind,
                error_class: error_class.to_owned(),
                upstream_response: None,
            },
        };
        let request_sha256 = sha256_prefixed(
            &custody_canonical_json_bytes(&request).map_err(|_| ())?,
        );
        let reply = cleanup_session
            .execute_response_data(&request, Vec::new())
            .map_err(|_| ())?;
        let V2ResponseDataResult::SettleAttempt(
            V2SettleAttemptResult { receipt },
        ) = reply.result
        else {
            return Err(());
        };
        let expected_deadline_expired =
            cleanup_started_at_boottime_ns
                >= cursor
                    .monotonic_deadline
                    .absolute_boottime_ns
                    .parse::<u64>()
                    .map_err(|_| ())?;
        let reconciliation_evidence_sha256 = sha256_prefixed(
            &custody_canonical_json_bytes(
                &receipt.reconciliation_evidence,
            )
            .map_err(|_| ())?,
        );
        let recovery_evidence_sha256 = receipt
            .recovery_evidence
            .as_ref()
            .map(|evidence| {
                custody_canonical_json_bytes(evidence)
                    .map(|bytes| sha256_prefixed(&bytes))
                    .map_err(|_| ())
            })
            .transpose()?;
        if !reply.exact_bytes.is_empty()
            || receipt.api_version
                != V2_DURABLE_SETTLEMENT_VERSION
            || receipt.generation_id != client.generation_id
            || receipt.generation != client.provider_generation
            || receipt.operation
                != V2ResponseDataOperation::SettleAttempt
            || receipt.request_id != request_id
            || receipt.request_sha256 != request_sha256
            || receipt.attempt_id != attempt_id
            || receipt.stable_resume_id != stable_resume_id
            || receipt.predecessor_revision
                != cursor.attempt.attempt_revision
            || receipt.predecessor_fencing_token
                != cursor.attempt.fencing_token
            || receipt.deadline_expired
                != expected_deadline_expired
            || receipt.terminal_attempt.attempt_id != attempt_id
            || !matches!(
                receipt.terminal_attempt.state,
                V2AttemptState::Denied
                    | V2AttemptState::Cancelled
                    | V2AttemptState::Failed
                    | V2AttemptState::OutcomeUnknown
                    | V2AttemptState::Terminalized
            )
            || receipt.terminal_attempt.attempt_revision
                < cursor.attempt.attempt_revision
            || receipt.terminal_attempt.fencing_token == 0
            || !is_sha256_digest(
                &receipt.terminal_attempt.state_sha256,
            )
            || !is_sha256_digest(
                &receipt.terminal_receipt_sha256,
            )
            || receipt.reconciliation_id.is_empty()
            || !is_sha256_digest(
                &receipt.reconciliation_record_sha256,
            )
            || receipt.reconciliation_record_sha256
                != reconciliation_evidence_sha256
            || receipt.recovery_evidence_sha256
                != recovery_evidence_sha256
            || receipt
                .recovery_evidence_sha256
                .as_ref()
                .is_some_and(|digest| !is_sha256_digest(digest))
            || receipt.authority_sequence == 0
        {
            return Err(());
        }
        let mut unsigned = receipt.clone();
        let signature = std::mem::take(&mut unsigned.signature);
        response_observation_v2_validate_response_data_provider_scope(
            client,
            &receipt.provider_scope,
            CustodyServiceRole::CleanupWatchdog,
            "outcome-reconciliation",
            ServiceOperationV1::Reconcile,
            V2_SETTLE_ATTEMPT_OPERATION,
            &request_id,
            attempt_id,
            cursor.attempt.attempt_revision,
            cursor.attempt.fencing_token,
            &receipt.provider_operation_binding_sha256,
        )
        .map_err(|_| ())?;
        verify_response_observation_v2_role_signature(
            client,
            "outcome-reconciliation",
            V2_SETTLE_ATTEMPT_OPERATION,
            &receipt.signer_provider_id,
            receipt.generation,
            &receipt.signer_key_id,
            &receipt.signer_key_material_sha256,
            &signature,
            &unsigned,
        )
        .map_err(|_| ())?;
        cursor.attempt = receipt.terminal_attempt;
        Ok(())
    })();
    if terminalized.is_err() {
        ResponseObservationV2TransactionError::OutcomeUnknown
            .with_resume(attempt_id, stable_resume_id)
    } else {
        error.with_resume(attempt_id, stable_resume_id)
    }
}

fn response_observation_v2_authority_proof_input(
    inspection: &SignedV2ImmutableResponseInspectionV1,
    preparation: &SignedV2ExactReleasePreparationV1,
    incomplete_public_envelope: &V2CanonicalFinalEnvelopeV1,
) -> Result<
    (
        Vec<u8>,
        serverware_decision_gate::
            CanonicalAuthorityEnvelopeProofInputV2,
    ),
    ResponseObservationV2TransactionError,
> {
    if !incomplete_public_envelope
        .authority_artifacts_root_sha256
        .is_empty()
        || !incomplete_public_envelope
            .final_envelope_sha256
            .is_empty()
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let proof =
        serverware_decision_gate::
            build_canonical_authority_proof_input_from_seed(
                &inspection.authority_proof_seed,
                &preparation.authority_receipt,
                incomplete_public_envelope.clone(),
            )
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
    let canonical = custody_canonical_json_bytes(&proof).map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    Ok((canonical, proof))
}

pub(super) fn response_observation_v2_authority_plan(
    decision: &Value,
    release: Option<&ReleaseAuthorizationGuard<'_>>,
) -> Value {
    let reservation = release.map(|release| {
        json!({
            "attemptId":release.reservation.attempt_id,
            "bindingSha256":release.reservation.binding_digest,
            "principalId":release.reservation.principal_id,
            "routeId":release.reservation.route_id,
            "credentialId":release.reservation.credential_id,
            "credentialGeneration":
                release.reservation.credential_version,
            "policySha256":release.reservation.policy_hash,
            "requestSha256":release.reservation.request_digest,
            "operationSha256":
                release.reservation.operation_digest,
            "grantId":release.reservation.grant_id,
            "approvalRequestId":
                release.reservation.approval_request_id,
            "expiresAtEpochMs":
                release.reservation
                    .reservation_expires_at_epoch_ms,
        })
    });
    json!({
        "apiVersion":"serverware.responseObservationV2AuthorityPlan/v1",
        "required":release.is_some(),
        "reservation":reservation,
        "jit":decision
            .get("jit")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

pub(super) fn response_observation_v2_dispatch_authorization(
    snapshot: &Arc<Snapshot>,
    release: &mut Option<ReleaseAuthorizationGuard<'_>>,
) -> Result<Value, ResponseObservationV2TransactionError> {
    let Some(release) = release.as_mut() else {
        return Ok(json!({
            "apiVersion":
                "serverware.responseObservationV2DispatchAuthorization/v1",
            "required":false,
        }));
    };
    let dispatch = release.dispatch(snapshot).map_err(|_| {
        ResponseObservationV2TransactionError::OutcomeUnknown
    })?;
    Ok(json!({
        "apiVersion":
            "serverware.responseObservationV2DispatchAuthorization/v1",
        "required":true,
        "observedAtEpochMs":dispatch.observed_at_epoch_ms,
        "reservationExpiresAtEpochMs":
            dispatch.reservation_expires_at_epoch_ms,
        "dispatchExpiresAtEpochMs":
            dispatch.dispatch_expires_at_epoch_ms,
        "controlPlaneAuthorizationReceipt":
            dispatch.evidence.receipt,
        "policySha256":snapshot.hash,
    }))
}

pub(super) fn response_observation_v2_request_deadline(
    request: &V2OperationRequest,
) -> Option<(&V2MonotonicDeadlineV1, u64)> {
    if let Some(binding) = request.mutation_binding() {
        return Some((
            &binding.monotonic_deadline,
            binding.deadline_at_epoch_ms,
        ));
    }
    if let Some(binding) = request.read_binding() {
        return Some((
            &binding.monotonic_deadline,
            binding.deadline_at_epoch_ms,
        ));
    }
    match request {
        V2OperationRequest::Recover { params, .. } => Some((
            &params.monotonic_deadline,
            params.deadline_at_epoch_ms,
        )),
        _ => None,
    }
}
