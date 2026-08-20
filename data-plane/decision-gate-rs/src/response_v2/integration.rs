use super::*;

pub(super) fn start_response_observation_v2_health_probe(
    client: Option<ResponseObservationV2Client>,
) {
    let Some(client) = client else {
        return;
    };
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let healthy = ResponseObservationV2Deadline::after(
            Duration::from_secs(2),
        )
            .and_then(|deadline| {
                let probe_config =
                    ResponseObservationV2ClientConfig {
                        socket_path:
                            client.socket_path.clone(),
                        expected_uid: client.expected_uid,
                        startup_timeout:
                            Duration::from_secs(2),
                        attestation_mode:
                            client.attestation_mode,
                        signer_key_sha256:
                            client.signer_key_sha256.clone(),
                        role_identity_root_sha256:
                            client
                                .role_identity_root_sha256
                                .clone(),
                        proof_pins_root_sha256:
                            client
                                .proof_pins_root_sha256
                                .clone(),
                        tee_verify_command:
                            client.tee_verify_command.clone(),
                        tee_topology_profile:
                            client.tee_topology_profile,
                        transparency_trust_pin:
                            client.transparency_trust_pin.clone(),
                        role_keys: client.role_keys.clone(),
                        generation_id:
                            client.generation_id.clone(),
                        expected_source_commit_sha256:
                            client
                                .expected_source_commit_sha256
                                .clone(),
                        expected_source_tree_sha256:
                            client
                                .expected_source_tree_sha256
                                .clone(),
                        expected_provider_generation:
                            Some(client.provider_generation),
                        expected_trust_root_sha256:
                            Some(client.trust_root_sha256.clone()),
                        expected_trust_checkpoint_sha256:
                            Some(
                                client
                                    .trust_checkpoint_sha256
                                    .clone(),
                            ),
                        minimum_revocation_epoch:
                            client.revocation_epoch,
                    };
                response_observation_v2_hello_once(
                    &probe_config,
                    deadline,
                )
            })
            .map(|status| {
                status.boot_id == client.boot_id
                    && status.providers_ready
                    && status.provider_generation
                        == client.provider_generation
                    && status.attestation.trust_checkpoint_sha256
                        == client.trust_checkpoint_sha256
                    && status.attestation.revocation_epoch
                        >= client.revocation_epoch
            })
            .unwrap_or(false);
        client
            .healthy
            .store(u64::from(healthy), Ordering::Release);
    });
}
