//! Reuses the real signed-policy, X25519/AES-GCM lease and signed durable ACK
//! loopback fixture. Synthetic control-plane authority only: no X contact,
//! consent, database quota, native admission or live rollout is claimed.
use super::*;

fn x_fixture() -> Fixture { Fixture::for_provider(60_000,true) }

fn x_calls(calls: &[(String,Value)], material: &[&str]) {
    let mut expected=vec!["attestation","audit"]; expected.extend_from_slice(material);
    assert_eq!(calls.iter().map(|(kind,_)|kind.as_str()).collect::<Vec<_>>(),expected);
    let events=calls[1].1["events"].as_array().unwrap(); assert_eq!(events.len(),1);
    assert_eq!(events[0]["event"]["credential_ref"],"x-account");
    assert_eq!(events[0]["event"]["credential_version"],7);
    assert!(!serde_json::to_string(events).unwrap().contains("synthetic-google-release-secret"));
}

#[test]
fn operator_x_release_actual_decision_ack_then_fresh_same_generation() {
    let fixture=x_fixture();
    let (owner,decision)=fixture.request(Instant::now()+Duration::from_secs(5));
    assert_eq!(decision["operation"]["operation"],"tweets.write");
    assert_eq!(decision["canonical_request"]["v"],2);
    seed(&fixture,250);
    let old=credential_lease_for_release(&fixture.state,&fixture.snapshot,&decision,"x-account",7).unwrap();
    let old_binding=credential_lease_release_binding(&old);
    let receiver=Receiver::start(&fixture,"ok");
    let (result,worker)=launch(&fixture,owner,decision.clone());
    receiver.entered.recv_timeout(WAIT).unwrap(); no_material(&fixture);
    wait_past(old_binding.expires_at_monotonic); receiver.release.send(()).unwrap();
    let (mut owner,result)=result.recv_timeout(WAIT).unwrap(); worker.join().unwrap();
    let fresh=result.unwrap().unwrap();
    assert_eq!(fresh.version,7); assert_eq!(fresh.metadata,old.metadata); assert_eq!(fresh.scope,fixture.scope);
    assert!(!fresh.metadata.contains_key("oauth_profile_binding_digest"));
    assert!(!fresh.metadata.contains_key("operator_x_account"));
    assert!(fresh.expires_at_monotonic>old.expires_at_monotonic);
    assert!(!credential_lease_still_releasable(&fixture.state,&fixture.snapshot,&old_binding));
    assert!(owner.prepare_release_if_admitted(&fixture.state,&fixture.snapshot,&decision,
        "POST",&Url::parse("https://api.x.com/2/tweets").unwrap(),false).is_err());
    x_calls(&receiver.finish(),&["dispatchSecret"]);
}

#[test]
fn operator_x_release_predecision_signed_advance_reconciles_once_not_google() {
    let fixture=x_fixture(); seed(&fixture,0);
    let original=Instant::now()+Duration::from_secs(5);
    let receiver=Receiver::start(&fixture,"predecision-advance");
    let (_owner,decision)=fixture.request_expected(original,8);
    assert_eq!(decision["canonical_request"]["credential_version"],"8");
    assert!(Instant::now()<original);
    let calls=receiver.finish();
    assert_eq!(calls.iter().map(|(kind,_)|kind.as_str()).collect::<Vec<_>>(),
        ["dispatchSecret","generationMetadata","dispatchSecret"]);
    assert_eq!(fixture.state.credential_generations.lock().unwrap()[&fixture.scope].version,8);
    // An authentically signed Google-labelled receipt cannot activate the X
    // reconciliation branch, even when every generic request binding matches.
    let fixture=x_fixture(); seed(&fixture,0);
    let receiver=Receiver::start(&fixture,"cross-provider");
    let mut owner=Request::new(Instant::now()+Duration::from_secs(5));
    assert!(owner.acquire_if_admitted(&fixture.state,&fixture.snapshot,&fixture.scope,false).is_err());
    let calls=receiver.finish(); assert_eq!(calls.len(),1); assert_eq!(calls[0].0,"dispatchSecret");
    assert_eq!(fixture.state.credential_generations.lock().unwrap()[&fixture.scope].version,7);
}

#[test]
fn operator_x_release_postcanonical_advance_and_failed_ack_are_terminal() {
    for mode in ["advanced","cross-provider","failed-ack"] {
        let fixture=x_fixture(); let (owner,decision)=fixture.request(Instant::now()+Duration::from_secs(5));
        seed(&fixture,0); let receiver=Receiver::start(&fixture,mode);
        let (result,worker)=launch(&fixture,owner,decision.clone());
        receiver.entered.recv_timeout(WAIT).unwrap(); receiver.release.send(()).unwrap();
        let (mut owner,result)=result.recv_timeout(WAIT).unwrap(); worker.join().unwrap(); assert!(result.is_err());
        assert!(owner.prepare_release_if_admitted(&fixture.state,&fixture.snapshot,&decision,
            "POST",&Url::parse("https://api.x.com/2/tweets").unwrap(),false).is_err());
        x_calls(&receiver.finish(),if mode=="failed-ack" {&[]} else {&["dispatchSecret"]});
        assert_eq!(fixture.state.credential_generations.lock().unwrap()[&fixture.scope].version,7);
    }
}

#[test]
fn operator_x_release_original_deadline_and_native_guards_unchanged() {
    let fixture=x_fixture(); let original=Instant::now()+Duration::from_millis(350);
    let (owner,decision)=fixture.request(original); seed(&fixture,0);
    let receiver=Receiver::start(&fixture,"ok"); let (result,worker)=launch(&fixture,owner,decision);
    receiver.entered.recv_timeout(WAIT).unwrap(); wait_past(original);
    assert!(result.recv_timeout(Duration::from_millis(500)).unwrap().1.is_err()); worker.join().unwrap();
    receiver.release.send(()).unwrap(); x_calls(&receiver.finish(),&[]); no_material(&fixture);
    let mut fixture=x_fixture(); let state=Arc::get_mut(&mut fixture.state).unwrap();
    state.is_production=true;
    assert!(operator_google_reconciliation::admitted(state,&fixture.snapshot,&fixture.scope,None,None).is_err());
    state.is_production=false; state.atomic_release_authorization_enabled=true;
    assert!(operator_google_reconciliation::admitted(state,&fixture.snapshot,&fixture.scope,None,None).is_err());
}
