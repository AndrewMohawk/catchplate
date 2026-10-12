//! Real signed-policy reload and shared publication/dispatch guards on private
//! temporary files. This does not initialize custody or claim OAuth consent.
use super::*;
use crate::*;
use crate::operator_audit_publication::{Owner,LOCK_NAME};
use std::os::fd::AsRawFd;

fn document(configured: bool) -> Value {
    let mut value=operator_x_profile::tests::manifest(configured);
    value["effective_settings"]["allowed_upstreams"]=json!(["https://api.example.com","https://api.x.com"]);
    value["effective_settings_digest"]=json!(digest_json_ensure_ascii(&value["effective_settings"]));
    value
}

fn publish(scratch: &Scratch, value: &Value) {
    let lock=fs::File::open(scratch.0.join(LOCK_NAME)).unwrap();
    assert_eq!(unsafe {libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0);
    let next=scratch.0.join("next-x.json"); fs::write(&next,value.to_string()).unwrap();
    fs::set_permissions(&next,fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(next,scratch.0.join("operator-x-configuration.json")).unwrap();
    assert_eq!(unsafe {libc::flock(lock.as_raw_fd(),libc::LOCK_UN)},0);
}

#[test]
fn operator_x_reload_first_save_same_policy_keeps_snapshot_and_existing_caches() {
    let scratch=Scratch::new(); let path=scratch.0.join("policy-bundle.json");
    let trust_path=scratch.0.join("trust.pem"); let high_water=scratch.0.join("high-water.json");
    let (key,pem,key_id)=response_proof_signing_material().unwrap(); fs::write(&trust_path,pem).unwrap();
    let trust=PolicyTrustRootSource::File(trust_path.to_string_lossy().into_owned());
    let original=signed_policy(&key,&key_id,1,false); fs::write(&path,original.to_string()).unwrap();
    let snapshot=Arc::new(load_snapshot(path.to_str().unwrap(),&trust,"sha256:test-binary").unwrap());
    let lock=scratch.0.join(LOCK_NAME); fs::write(&lock,[]).unwrap();
    fs::set_permissions(&lock,fs::Permissions::from_mode(0o600)).unwrap();
    publish(&scratch,&document(false)); let owner=Arc::new(Owner::open(&path).unwrap());
    let configuration={let permit=owner.acquire(Instant::now()+Duration::from_secs(2)).unwrap();
        operator_x_profile::test_load(&scratch.0.join("operator-x-configuration.json"),&permit).unwrap()};
    let mut admitted=profile(&snapshot,configuration.deployment);
    let selection=Arc::new(RwLock::new(configuration.state)); admitted.managed_x=Some(Arc::clone(&selection));
    admitted.validate_snapshot(&snapshot).unwrap();
    assert!(admitted.prepare_reload(&snapshot,&snapshot).is_err(),"managed reload needs real publication ownership");
    let mut state=test_gate_state(Arc::clone(&snapshot));
    state.policy_path=path.to_string_lossy().into_owned(); state.policy_trust_root_source=trust;
    state.policy_high_water_path=Some(high_water); state.operator_audit_publication=Some(owner);
    state.policy_shadow=ShadowRuntime::new_operator_demo(admitted);
    *state.policy_mtime.lock().unwrap()=file_mtime(path.to_str().unwrap());
    *state.policy_trust_refresh_due.lock().unwrap()=Instant::now()+Duration::from_secs(60);
    // An unrelated retained cache entry makes accidental whole-cache clearing
    // observable; it is not used as an admitted lease in this component test.
    let scope=CredentialLeaseScope::new("agent:test","route:test","unrelated-google-cache");
    let metadata=BTreeMap::from([("provider".into(),json!("google"))]);
    state.credential_generations.lock().unwrap().insert(scope.clone(),CredentialLeaseGeneration {
        profile:ReleaseProfile::Legacy,policy_hash:snapshot.hash.clone(),version:7,
        metadata_sha256:credential_lease_metadata_sha256(&metadata),metadata,
        expires_at_epoch_ms:now_epoch_ms()+60_000,expires_at_monotonic:Instant::now()+Duration::from_secs(60)});
    let unchanged=fs::read(&path).unwrap(); let mtime=file_mtime(path.to_str().unwrap());
    assert!(!refresh_policy_snapshot(&state,false).unwrap());
    publish(&scratch,&document(true));
    assert!(!refresh_policy_snapshot(&state,false).unwrap(),"first save is not a policy-version advance");
    assert!(selection.read().unwrap().profile.is_some());
    assert!(Arc::ptr_eq(&current_snapshot(&state),&snapshot));
    assert_eq!(fs::read(&path).unwrap(),unchanged); assert_eq!(file_mtime(path.to_str().unwrap()),mtime);
    assert_eq!(state.credential_generations.lock().unwrap()[&scope].version,7);
    assert!(!refresh_policy_snapshot(&state,false).unwrap());
    publish(&scratch,&document(true)); // Exact repeated identity is idempotent.
    assert!(!refresh_policy_snapshot(&state,false).unwrap());
    for mode in ["disable","client","owner","settings"] {
        let mut changed=document(mode!="disable");
        match mode {
            "client"=>{changed["profile_binding"]["client_id"]=json!("different-client");
                changed["profile_binding_digest"]=json!(digest_json_ensure_ascii(&changed["profile_binding"]));},
            "owner"=>changed["operation"]["owner_id"]=json!("c3333333-3333-4333-8333-333333333333"),
            "settings"=>{changed["effective_settings"]["allowed_upstreams"]=json!(["https://api.example.com"]);
                changed["effective_settings_digest"]=json!(digest_json_ensure_ascii(&changed["effective_settings"]));},
            _=>{}
        }
        publish(&scratch,&changed); assert!(refresh_policy_snapshot(&state,false).is_err(),"{mode}");
        assert!(Arc::ptr_eq(&current_snapshot(&state),&snapshot));
        assert_eq!(selection.read().unwrap().identity.status()["operation"],document(true)["operation"]);
    }
}
