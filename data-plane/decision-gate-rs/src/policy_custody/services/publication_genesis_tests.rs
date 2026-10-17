//! Deterministic public-format/signature controls. Synthetic key/guest/proof
//! data is not an admitted owner, durable write, fs-verity observation, or trust.
use super::*;
use super::super::ledger_spool_values::StoredPayload;

fn digest(label: &str) -> Sha256Digest { Sha256Digest::compute(label.as_bytes()) }
fn epoch(key: &SigningKey, role: HistoricalServiceRoleV3) -> AuthorityEpochRefV3 {
    AuthorityEpochRefV3 { api_version: "catchplate.policyCustodyAuthorityHistory/v3".into(),
        authority_role: HistoricalAuthorityRoleV3::IsolatedService(role), authority_epoch_sequence: 1,
        authority_epoch_sha256: digest("epoch"), checkpoint_sequence: 1, checkpoint_sha256: digest("checkpoint"),
        checkpoint_authority_key_id: digest("checkpoint-key"), checkpoint_authority_key_spki_sha256: digest("checkpoint-spki"),
        service_signing_key_id: digest("service-key"), service_signing_key_spki_sha256: verifying_key_spki_sha256(&key.verifying_key()).unwrap(),
        endpoint_process_identity_sha256: digest("process"), endpoint_generation: 1, service_generation: 1,
        operation_generation: 1, durable_epoch: 1, durable_epoch_head_sha256: digest("durable"), deployment_generation_sha256: digest("deployment") }
}
fn role(key: &SigningKey, role: AuthorityRole, label: &str) -> RoleKey {
    RoleKey { role, key_id: digest(label), key_spki_sha256: verifying_key_spki_sha256(&key.verifying_key()).unwrap(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()), grant_sha256: digest(&format!("{label}-grant")) }
}
fn scope() -> Scope {
    let keydata = |role| serde_json::json!({"role":role,"key_id":digest("proof-key"),
        "key_spki_sha256":digest("proof-spki"),"key_material_sha256":digest("proof-material")});
    let proof = serde_json::json!({"assignment_id":digest("assignment-id"),"assignment_payload_sha256":digest("assignment"),
        "assignment_revision":1,"authority_id":digest("authority"),"storage_realm_sha256":digest("storage"),
        "retrieval_namespace_sha256":digest("namespace"),"authority_key_independence_sha256":digest("independence"),
        "production_configuration_binding_sha256":digest("configuration"),"asserted_custody_key_set_root_sha256":digest("keys"),
        "execution_closure_manifest_sha256":digest("closure"),"structurally_verified_seccomp_policy_sha256":digest("seccomp"),
        "store_response_authority":keydata(AuthorityRole::CustodyStoreResponse),
        "retrieval_response_authority":keydata(AuthorityRole::CustodyRetrievalResponse),"binding_sha256":digest("binding")});
    Scope { api_version: "catchplate.nativePublicationGenesisScope/v1".into(), commissioning_id_sha256: digest("commissioning"),
        production_configuration_binding_sha256: digest("configuration"), assignment_payload_sha256: digest("assignment"), assignment_revision: 1,
        proof_scope_original: text(&proof).unwrap(), retrieval_namespace_sha256: digest("namespace"), initial_publication_revision: 1,
        boot_id_base64url: URL_SAFE_NO_PAD.encode([1u8;16]), time_namespace_device: 1, time_namespace_inode: 2,
        issued_at_boottime_nanos: 10, expires_at_boottime_nanos: 100 }
}
struct Fixture { scope: Scope, native: RoleKey, retrieval: RoleKey, durable_key: SigningKey, current_key: SigningKey,
    native_key: SigningKey, retrieval_key: SigningKey, bundle: Bundle }
fn fixture() -> Fixture {
    let scope = scope(); let durable_key = SigningKey::from_bytes(&[11;32]); let current_key = SigningKey::from_bytes(&[12;32]);
    let native_key = SigningKey::from_bytes(&[13;32]); let retrieval_key = SigningKey::from_bytes(&[14;32]);
    let native = role(&native_key, AuthorityRole::CustodyPublicationReconciliation, "native");
    let retrieval = role(&retrieval_key, AuthorityRole::CustodyRetrievalResponse, "retrieval");
    let drs = epoch(&durable_key, HistoricalServiceRoleV3::DurableRecoveryStore);
    let csa = epoch(&current_key, HistoricalServiceRoleV3::CurrentSignatureAuthority);
    let genesis = GenesisEvidence::sign(scope.clone(), digest("DRS-grant"), drs.clone(), 12, &durable_key).unwrap();
    let core = Core::new(&scope, genesis, &native, 1_000, digest("trust-checkpoint")).unwrap();
    let mut prepared = Prepared { core, prepared_at_boottime_nanos: 15, signature: CanonicalEd25519Signature(String::new()) };
    prepared.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(native_key.sign(&prepared.preimage().unwrap()).to_bytes()));
    let guest = guest::GuestClosureBinding { configuration_sha256: digest("retrieval-config"), delivery_sha256: digest("retrieval-delivery"),
        runtime_configuration_sha256: digest("retrieval-runtime"), service_role: "production-bridge".into(), uid: 1001, gid: 1001,
        boot_id_base64url: scope.boot_id_base64url.clone(), time_namespace_device: 1, time_namespace_inode: 2,
        issued_at_boottime_ns: "10".into(), startup_deadline_boottime_ns: "90".into(), lifetime_deadline_boottime_ns: "100".into(),
        invocation_id: "11111111111111111111111111111111".into() };
    let id = prepared.core.retrieval_id(&scope.retrieval_namespace_sha256).unwrap();
    let mut stored = Stored { payload: StoredPayload { api_version: STORAGE_API.into(), guest,
        grant_sha256: retrieval.grant_sha256.clone(), core_sha256: prepared.core.identity().unwrap(), object_sha256: sha(&prepared.core).unwrap(),
        fsverity_sha256: digest("synthetic-verity-not-observed"), retrieval_id_sha256: id.clone(),
        retrieval_proof_sha256: prepared.core.retrieval_proof(scope.proof_scope_original.as_bytes(), &id).unwrap(),
        previous_head_sha256: digest("synthetic-storage-genesis-not-observed"), sequence: 1, stored_at_boottime_nanos: 20,
        original_deadline_boottime_nanos: 100, signing_key_id: retrieval.key_id.clone(), signing_key_spki_sha256: retrieval.key_spki_sha256.clone() },
        signature: CanonicalEd25519Signature(String::new()) };
    stored.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(retrieval_key.sign(&signature_preimage(STORAGE_DOMAIN,
        &encode_canonical_frame(&stored.payload).unwrap())).to_bytes()));
    let receipt_original = final_receipt(&prepared.core, &stored, |payload| {
        let authority = super::super::guest::native_keys::admission::publication::authority_payload(&scope.proof_scope_original, payload).unwrap();
        Ok(URL_SAFE_NO_PAD.encode(native_key.sign(&signature_preimage(Role::PublicationReconciliation.signature_domain(), &authority)).to_bytes()))
    }).unwrap();
    let mut completion = Completion { api_version: "catchplate.nativePublicationGenesisCompletion/v1".into(),
        prepared, stored, receipt_original, completed_at_boottime_nanos: 25, signature: CanonicalEd25519Signature(String::new()) };
    completion.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(native_key.sign(&signature_preimage(COMPLETION_DOMAIN,
        &completion.payload().unwrap())).to_bytes()));
    let durable = Witness::sign(&scope, &completion, sha(&completion.prepared.core.genesis).unwrap(), digest("DRS-grant"), drs, 30, &durable_key).unwrap();
    let current = Witness::sign(&scope, &completion, sha(&durable).unwrap(), digest("CSA-grant"), csa, 35, &current_key).unwrap();
    Fixture { scope, native, retrieval, durable_key, current_key, native_key, retrieval_key, bundle: Bundle { completion, durable, current } }
}
fn checked(f: &Fixture, bundle: &Bundle) -> Result<(), ServiceError> {
    bundle.verify(&f.scope, &f.native, &f.retrieval, &epoch(&f.durable_key, HistoricalServiceRoleV3::DurableRecoveryStore),
        &f.durable_key.verifying_key(), &epoch(&f.current_key, HistoricalServiceRoleV3::CurrentSignatureAuthority), &f.current_key.verifying_key())
}

#[test]
fn initial_state_has_fixed_empty_semantics_and_independent_roots() {
    let scope = scope(); let state = InitialState::new(&scope).unwrap();
    assert_eq!(state.state, PublicationReconciliationState::Uninstalled); assert_eq!(state.ledger_event_ordinal, 0);
    assert!(state.first_ingress_sequence.is_none() && state.last_ingress_sequence.is_none() && state.committed_generation_sha256.is_none());
    let (ledger, spool) = state.roots().unwrap(); assert_ne!(ledger, spool);
    let mut other = scope.clone(); other.commissioning_id_sha256 = digest("another-commissioning");
    assert_ne!(state.roots().unwrap(), InitialState::new(&other).unwrap().roots().unwrap());
    let mut json = serde_json::to_value(&scope).unwrap(); json["generationId"] = serde_json::json!(digest("future"));
    assert!(serde_json::from_value::<Scope>(json).is_err());
}

#[test]
fn genesis_signature_binds_exact_initial_record_and_approved_scope() {
    let f = fixture(); checked(&f, &f.bundle).unwrap();
    let genesis = &f.bundle.completion.prepared.core.genesis;
    let mut changed = genesis.clone(); changed.genesis_original.push('\n');
    assert!(changed.verify(&f.scope, &epoch(&f.durable_key, HistoricalServiceRoleV3::DurableRecoveryStore), &f.durable_key.verifying_key()).is_err());
    let mut changed = genesis.clone(); changed.grant_sha256 = digest("another-grant");
    assert!(changed.verify(&f.scope, &epoch(&f.durable_key, HistoricalServiceRoleV3::DurableRecoveryStore), &f.durable_key.verifying_key()).is_err());
}

#[test]
fn even_signed_storage_cannot_change_sequence_grant_or_original_deadline() {
    let f = fixture(); let prepared = &f.bundle.completion.prepared;
    for variant in 0..3 {
        let mut stored = f.bundle.completion.stored.clone();
        match variant { 0 => stored.payload.sequence = 2, 1 => stored.payload.grant_sha256 = digest("wrong-grant"),
            _ => stored.payload.original_deadline_boottime_nanos = 101 }
        stored.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(f.retrieval_key.sign(&signature_preimage(STORAGE_DOMAIN,
            &encode_canonical_frame(&stored.payload).unwrap())).to_bytes()));
        assert!(stored_verify(&stored, prepared, &f.scope, &f.retrieval).is_err());
    }
}

#[test]
fn completion_contains_real_bound_uninstalled_receipt_not_future_generation() {
    let f = fixture(); let receipt: Receipt = original(&f.bundle.completion.receipt_original).unwrap();
    assert_eq!(receipt.state, PublicationReconciliationState::Uninstalled);
    assert!(receipt.predecessor_generation_sha256.is_none() && receipt.committed_generation_sha256.is_none()
        && receipt.published_generation_sha256.is_none() && receipt.prepared_publication_sha256.is_none());
    let mut changed = f.bundle.completion.clone(); changed.receipt_original = "{}".into();
    changed.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(f.native_key.sign(&signature_preimage(COMPLETION_DOMAIN,
        &changed.payload().unwrap())).to_bytes()));
    assert!(changed.verify(&f.scope, &f.native, &f.retrieval, &epoch(&f.durable_key, HistoricalServiceRoleV3::DurableRecoveryStore),
        &f.durable_key.verifying_key()).is_err());
}

#[test]
fn independent_mirror_must_bind_exact_durable_finalization_and_order() {
    let f = fixture(); checked(&f, &f.bundle).unwrap();
    let mut changed = f.bundle.clone();
    changed.current = Witness::sign(&f.scope, &changed.completion, digest("unrelated-finalization"), digest("CSA-grant"),
        epoch(&f.current_key, HistoricalServiceRoleV3::CurrentSignatureAuthority), 35, &f.current_key).unwrap();
    assert!(checked(&f, &changed).is_err());
    let mut changed = f.bundle.clone();
    changed.current = Witness::sign(&f.scope, &changed.completion, sha(&changed.durable).unwrap(), digest("CSA-grant"),
        epoch(&f.current_key, HistoricalServiceRoleV3::CurrentSignatureAuthority), 29, &f.current_key).unwrap();
    assert!(checked(&f, &changed).is_err());
}

#[test]
fn original_clock_window_and_legacy_domains_do_not_widen() {
    let f = fixture();
    for now in [0, 9, 100, 101] { assert!(f.scope.live(now).is_err()); }
    let mut changed = f.bundle.completion.clone(); changed.api_version = "catchplate.nativePublicationProposal/v1".into();
    assert!(changed.verify(&f.scope, &f.native, &f.retrieval, &epoch(&f.durable_key, HistoricalServiceRoleV3::DurableRecoveryStore),
        &f.durable_key.verifying_key()).is_err());
    let mut scope = f.scope.clone(); scope.initial_publication_revision = 0; assert!(scope.validate().is_err());
}
