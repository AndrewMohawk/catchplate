//! Public synthetic configuration and temporary files; no env mutation,
//! provider traffic, custody, consent or native admission is represented here.
use super::*;
use crate::operator_audit_publication::{Owner, LOCK_NAME};
use std::os::unix::fs::{symlink, PermissionsExt};

pub(crate) const CLIENT: &str = "synthetic-X-client_123";
pub(crate) const SUBJECT: &str = "123456789";

pub(crate) fn manifest(configured: bool) -> Value {
    let binding = json!({"schema":"catchplate.operatorXOAuthProfile/v1","profile":CAPABILITY,
        "provider_id":"x","client_id":CLIENT,"redirect_uri":"https://console.example.com/api/oauth/callback/x",
        "client_auth_method":"client_secret_basic","permission_preset":"x_text_post_v1",
        "scopes":x_post::SCOPES,"api_origins":["https://api.x.com"],
        "authorization_url":"https://x.com/i/oauth2/authorize","token_url":"https://api.x.com/2/oauth2/token",
        "revocation_url":"https://api.x.com/2/oauth2/revoke","identity_url":"https://api.x.com/2/users/me"});
    let settings = json!({"allowed_upstreams":["https://api.x.com"],"fixture_cidrs":[]});
    json!({"schema":SCHEMA,"operation":if configured { json!({
        "operation_id":"a1111111-1111-4111-8111-111111111111",
        "owner_id":"b2222222-2222-4222-8222-222222222222","config_version":1}) } else {Value::Null},
        "profile_binding":if configured {binding.clone()} else {Value::Null},
        "profile_binding_digest":if configured {json!(digest_json_ensure_ascii(&binding))} else {Value::Null},
        "effective_settings":settings,"effective_settings_digest":digest_json_ensure_ascii(&settings)})
}

fn parsed(value: &Value) -> Result<Configuration, String> { parse(value.to_string().as_bytes()) }

#[test]
fn operator_x_profile_closed_flag_manifest_and_fixed_public_profile() {
    assert!(!selected(None, false, true).unwrap());
    assert!(!selected(Some("0"), false, true).unwrap());
    assert!(selected(Some("1"), true, false).unwrap());
    for (flag,ordinary,external) in [("",true,false),("true",true,false),("01",true,false),
        ("1",false,false),("1",true,true)] { assert!(selected(Some(flag),ordinary,external).is_err()); }
    let base = manifest(true);
    let configured = parsed(&base).unwrap();
    assert_eq!(configured.state.profile.unwrap().binding_digest(),base["profile_binding_digest"].as_str().unwrap());
    assert_eq!(gate_capability(),json!({"schema":"catchplate.operatorXPostGate/v1",
        "adapter":"x.post.v1","operation":"tweets.write"}));
    for pointer in ["/profile_binding/provider_id","/profile_binding/token_url","/profile_binding/client_auth_method",
        "/profile_binding/redirect_uri","/profile_binding/permission_preset"] {
        let mut changed=base.clone(); *changed.pointer_mut(pointer).unwrap()=json!("wrong");
        changed["profile_binding_digest"]=json!(digest_json_ensure_ascii(&changed["profile_binding"]));
        assert!(parsed(&changed).is_err(),"{pointer}");
    }
    for key in ["operation","profile_binding","profile_binding_digest"] {
        let mut changed=base.clone(); changed[key]=Value::Null; assert!(parsed(&changed).is_err());
    }
    for version in [json!(0),json!(2),json!(1.0),json!(true)] {
        let mut changed=base.clone(); changed["operation"]["config_version"]=version;
        assert!(parsed(&changed).is_err());
    }
    let mut changed=base.clone(); changed["secret"]=json!("not permitted"); assert!(parsed(&changed).is_err());
    assert!(parse(base.to_string().replacen('{',"{\"schema\":\"duplicate\",",1).as_bytes()).is_err());
    assert!(parse(&vec![b' ';MAX_BYTES as usize+1]).is_err());
}

#[test]
fn operator_x_profile_first_save_is_monotonic_without_origin_widening() {
    let empty=parsed(&manifest(false)).unwrap().state;
    let configured=parsed(&manifest(true)).unwrap().state;
    empty.require_successor(&empty).unwrap(); empty.require_successor(&configured).unwrap();
    configured.require_successor(&configured).unwrap();
    assert!(configured.require_successor(&empty).is_err());
    for pointer in ["/operation/owner_id","/operation/operation_id","/profile_binding/client_id"] {
        let mut changed=manifest(true);
        *changed.pointer_mut(pointer).unwrap()=json!(if pointer.contains("client_id") {"other-client"}
            else {"c3333333-3333-4333-8333-333333333333"});
        changed["profile_binding_digest"]=json!(digest_json_ensure_ascii(&changed["profile_binding"]));
        assert!(configured.require_successor(&parsed(&changed).unwrap().state).is_err());
    }
    let mut pending=manifest(true);
    pending["effective_settings"]["allowed_upstreams"]=json!(["https://api.example.com"]);
    pending["effective_settings_digest"]=json!(digest_json_ensure_ascii(&pending["effective_settings"]));
    let pending=parsed(&pending).unwrap(); // Configuration is not destination approval.
    assert!(empty.require_successor(&pending.state).is_err());
}

#[test]
fn operator_x_profile_exact_signed_identity_and_no_ordinary_shared_quota() {
    let profile=parsed(&manifest(true)).unwrap().state.profile.unwrap();
    let credential=Credential {provider:"x".into(),provider_subject:Some(SUBJECT.into()),
        injection:json!({"type":"bearer","header":"Authorization","field":"access_token",
            "__catchplateCredentialType":"oauth2","__catchplateOAuthClientId":CLIENT,
            "__catchplateGrantedScopes":x_post::SCOPES})};
    assert!(profile.x_credential(&credential).unwrap());
    for (key,value) in [("__catchplateOAuthClientId",json!("other")),
        ("__catchplateGrantedScopes",json!(["tweet.read"])),("field",json!("refresh_token")),
        ("unknown",json!(true))] {
        let mut changed=credential.clone(); changed.injection[key]=value;
        assert!(profile.x_credential(&changed).is_err());
    }
    for value in ["0","0123","18446744073709551616","username"] {
        let mut changed=credential.clone(); changed.provider_subject=Some(value.into());
        assert!(profile.x_credential(&changed).is_err());
    }
    let mut route=crate::tests::test_snapshot(1).routes[0].clone();
    route.adapter_type=x_post::ADAPTER.into(); route.host="api.x.com".into();
    route.methods=HashSet::from(["POST".into()]); route.paths=vec![compile_template("/2/tweets").unwrap()];
    route.credential_ref=Some("x-account".into());
    route.credential_header=Some(json!({"mode":"replaceExact","expectedValue":x_post::PLACEHOLDER}));
    route.discard_headers=x_post::DISCARD.iter().map(|item|item.to_string()).collect();
    route.adapter_config=json!({"credentialBinding":{"credentialType":"oauth2","provider":"x",
        "subjects":[SUBJECT],"clientIds":[CLIENT],"requiredScopes":x_post::SCOPES},
        "request":x_post::request_config(),"response":x_post::response_profile(false)});
    route.constraints=vec![x_post::envelope("x-envelope")]; route.jit=json!({});
    profile.route(&route).unwrap();
    route.constraints.push(x_post::quota(20));
    x_post::validate_route(&route).unwrap(); // Transport contract is not a SQLite quota owner.
    assert!(profile.route(&route).is_err());
    route.constraints.pop(); route.adapter_config["credentialBinding"]["clientIds"]=json!(["other"]);
    assert!(profile.route(&route).is_err());
}

#[test]
fn operator_x_profile_real_shared_permit_file_modes_and_expiry() {
    let path=env::temp_dir().join(format!("catchplate-x-public-{}-{}",std::process::id(),now_epoch_ms()));
    fs::create_dir(&path).unwrap(); fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
    struct Cleanup(PathBuf); impl Drop for Cleanup {fn drop(&mut self){fs::remove_dir_all(&self.0).unwrap();}}
    let _cleanup=Cleanup(path.clone());
    let lock=path.join(LOCK_NAME); fs::write(&lock,[]).unwrap();
    fs::set_permissions(&lock,fs::Permissions::from_mode(0o600)).unwrap();
    let file=path.join("operator-x-configuration.json"); fs::write(&file,manifest(true).to_string()).unwrap();
    fs::set_permissions(&file,fs::Permissions::from_mode(0o600)).unwrap();
    let owner=Owner::open(&path.join("policy-bundle.json")).unwrap();
    let deadline=Instant::now()+Duration::from_millis(100);
    let permit=owner.acquire(deadline).unwrap();
    assert!(load_at(&file,&permit).unwrap().state.profile.is_some());
    fs::set_permissions(&file,fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_at(&file,&permit).is_err());
    fs::set_permissions(&file,fs::Permissions::from_mode(0o600)).unwrap();
    let link=path.join("alias"); symlink(&file,&link).unwrap(); assert!(load_at(&link,&permit).is_err());
    let (_held,wait)=std::sync::mpsc::channel::<()>();
    let _=wait.recv_timeout(deadline.saturating_duration_since(Instant::now())+Duration::from_millis(2));
    assert!(load_at(&file,&permit).is_err());
}
