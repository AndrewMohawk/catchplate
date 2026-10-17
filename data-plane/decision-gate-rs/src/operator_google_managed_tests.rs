//! Public synthetic records and private temporary files only. No environment
//! mutation, provider traffic, custody/key access or fixed /data writes.
use super::*;
use crate::operator_audit_publication::Owner;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn manifest(active: bool) -> Value {
    let binding = json!({"schema":"catchplate.operatorGoogleProfile/v1",
        "profile":"operator-google-v1","provider_id":"google",
        "client_id":"synthetic-client.apps.googleusercontent.com",
        "redirect_uri":"https://console.example.com/api/oauth/callback/google",
        "permission_preset":"gmail_readonly",
        "scopes":["email","https://www.googleapis.com/auth/gmail.readonly","openid"],
        "api_origins":["https://gmail.googleapis.com"],
        "authorization_url":"https://accounts.google.com/o/oauth2/v2/auth",
        "token_url":"https://oauth2.googleapis.com/token",
        "revocation_url":"https://oauth2.googleapis.com/revoke",
        "identity_url":"https://openidconnect.googleapis.com/v1/userinfo"});
    let settings = json!({"allowed_upstreams":["https://demo-upstream:8443","https://gmail.googleapis.com"],
        "fixture_cidrs":["172.16.249.18/32"]});
    json!({"schema":SCHEMA,
        "operation":if active {json!({"operation_id":"a1111111-1111-4111-8111-111111111111",
            "owner_id":"b2222222-2222-4222-8222-222222222222","config_version":1})} else {Value::Null},
        "profile_binding":if active {binding.clone()} else {Value::Null},
        "profile_binding_digest":if active {json!(digest_json_ensure_ascii(&binding))} else {Value::Null},
        "effective_settings":settings,"effective_settings_digest":digest_json_ensure_ascii(&settings)})
}

fn parsed(value: &Value) -> Result<Configuration, String> {
    parse(value.to_string().as_bytes())
}

#[test]
fn operator_google_managed_flag_is_closed_development_only_and_exclusive() {
    for flag in [None, Some("0")] {
        assert!(!selected(flag, false, true).unwrap());
    }
    assert!(selected(Some("1"), true, false).unwrap());
    for flag in [Some(""), Some("true"), Some(" 1"), Some("01"), Some("2")] {
        assert!(selected(flag, true, false).is_err());
    }
    assert!(selected(Some("1"), false, false).is_err());
    assert!(selected(Some("1"), true, true).is_err());
}

#[test]
fn operator_google_managed_raw_namespace_is_exclusive_even_when_empty() {
    for name in [
        "CATCHPLATE_GOOGLE_OAUTH_CLIENT_ID",
        "CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI",
        "CATCHPLATE_GOOGLE_UNKNOWN",
        "CATCHPLATE_OPERATOR_GOOGLE_PROFILE",
    ] {
        for value in ["", "synthetic"] {
            let environment = [(name, value)];
            let present = environment.iter().any(|(key, _)| external_google_key(key));
            assert!(present);
            assert!(selected(Some("1"), true, present).is_err());
        }
    }
    for name in [
        FLAG,
        "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED",
        "UNRELATED",
    ] {
        assert!(!external_google_key(name));
    }
}

#[test]
fn operator_google_managed_disabled_is_explicit_and_keeps_settings_identity() {
    let value = manifest(false);
    let result = parsed(&value).unwrap();
    assert!(result.google.is_none());
    assert_eq!(
        result.identity.status(),
        json!({"operation":null,"profile_binding_digest":null,
        "effective_settings_digest":value["effective_settings_digest"]})
    );
}

#[test]
fn operator_google_managed_active_joins_python_canonical_digest_vectors() {
    let value = manifest(true);
    // Independently computed with Python setup._digest's exact JSON options.
    assert_eq!(
        value["effective_settings_digest"],
        "sha256:dff2524a7470edca9bc3bd98cd73210d922bb52a6292be5b9057a34b7f4bb315"
    );
    assert_eq!(
        value["profile_binding_digest"],
        "sha256:88853a79b2ea989e8b59e99d5e433ab47fb27742e1553875e92cb535b12f1626"
    );
    let result = parsed(&value).unwrap();
    assert_eq!(
        result.google.unwrap().binding_digest(),
        value["profile_binding_digest"].as_str().unwrap()
    );
    assert_eq!(result.identity.status()["operation"], value["operation"]);
}

#[test]
fn operator_google_managed_manifest_rejects_ambiguity_and_unknown_fields() {
    let base = manifest(true);
    for name in [
        "operation",
        "profile_binding",
        "profile_binding_digest",
        "schema",
    ] {
        let mut value = base.clone();
        value.as_object_mut().unwrap().remove(name);
        assert!(parsed(&value).is_err());
    }
    for name in ["operation", "profile_binding", "profile_binding_digest"] {
        let mut value = base.clone();
        value[name] = Value::Null;
        assert!(parsed(&value).is_err());
    }
    for name in [
        "secret",
        "activation_receipt",
        "policy_hash",
        "catalog_revision",
        "target_settings",
    ] {
        let mut value = base.clone();
        value[name] = json!("not accepted");
        assert!(parsed(&value).is_err());
    }
    let duplicated = base
        .to_string()
        .replacen("{", "{\"schema\":\"duplicate\",", 1);
    assert!(parse(duplicated.as_bytes()).is_err());
    assert!(parse(format!("{} null", base).as_bytes()).is_err());
    assert!(parse(b"").is_err());
    assert!(parse(&vec![b' '; MAX_BYTES as usize + 1]).is_err());
}

#[test]
fn operator_google_managed_operation_uses_exact_uuid_and_version() {
    for key in ["operation_id", "owner_id"] {
        for invalid in [
            "A1111111-1111-4111-8111-111111111111",
            "a1111111111141118111111111111111",
            "latest",
            "",
        ] {
            let mut value = manifest(true);
            value["operation"][key] = json!(invalid);
            assert!(parsed(&value).is_err());
        }
    }
    for invalid in [
        json!(0),
        json!(17),
        json!(-1),
        json!(true),
        json!(1.0),
        json!("1"),
    ] {
        let mut value = manifest(true);
        value["operation"]["config_version"] = invalid;
        assert!(parsed(&value).is_err());
    }
    let mut value = manifest(true);
    value["operation"]["key_source"] = json!("not part of public runtime identity");
    assert!(parsed(&value).is_err());
}

#[test]
fn operator_google_managed_profile_cannot_change_fixed_endpoints_or_scopes() {
    for (name, replacement) in [
        ("token_url", json!("https://other.example.com/token")),
        ("scopes", json!(["openid"])),
        ("unexpected", json!(true)),
        ("client_id", json!("invalid")),
        (
            "redirect_uri",
            json!("https://127.0.0.1/api/oauth/callback/google"),
        ),
    ] {
        let mut value = manifest(true);
        value["profile_binding"][name] = replacement;
        value["profile_binding_digest"] =
            json!(digest_json_ensure_ascii(&value["profile_binding"]));
        assert!(parsed(&value).is_err());
    }
    let mut value = manifest(true);
    value["profile_binding_digest"] = json!("sha256:bad");
    assert!(parsed(&value).is_err());
}

#[test]
fn operator_google_managed_settings_use_current_ordered_state_not_google_target() {
    let mut current = manifest(true);
    let original = parsed(&current).unwrap().identity.status();
    current["effective_settings"]["allowed_upstreams"]
        .as_array_mut()
        .unwrap()
        .push(json!("https://registry.npmjs.org"));
    current["effective_settings_digest"] =
        json!(digest_json_ensure_ascii(&current["effective_settings"]));
    let changed = parsed(&current).unwrap().identity.status();
    assert_eq!(changed["operation"], original["operation"]);
    assert_eq!(
        changed["profile_binding_digest"],
        original["profile_binding_digest"]
    );
    assert_ne!(
        changed["effective_settings_digest"],
        original["effective_settings_digest"]
    );
    current["effective_settings"]["allowed_upstreams"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(
        parsed(&current).is_err(),
        "ordering change needs its exact current digest"
    );
    current["effective_settings_digest"] =
        json!(digest_json_ensure_ascii(&current["effective_settings"]));
    assert!(parsed(&current).is_ok());
}

#[test]
fn operator_google_managed_settings_refuse_invalid_origins_cidrs_and_aliases() {
    for settings in [
        json!({"allowed_upstreams":[],"fixture_cidrs":[]}),
        json!({"allowed_upstreams":["https://gmail.googleapis.com/"],"fixture_cidrs":[]}),
        json!({"allowed_upstreams":["https://gmail.googleapis.com:443"],"fixture_cidrs":[]}),
        json!({"allowed_upstreams":["https://gmail.googleapis.com","https://gmail.googleapis.com"],"fixture_cidrs":[]}),
        json!({"allowed_upstreams":["https://169.254.169.254"],"fixture_cidrs":[]}),
        json!({"allowed_upstreams":["https://demo-upstream:8443","https://gmail.googleapis.com"],"fixture_cidrs":["172.16.249.0/24"]}),
        json!({"allowed_upstreams":["https://gmail.googleapis.com"],"fixture_cidrs":["172.16.249.18/32"]}),
        json!({"allowed_upstreams":["https://other.example.com"],"fixture_cidrs":[]}),
        json!({"allowed_upstreams":["https://gmail.googleapis.com"],"fixture_cidrs":[],"unknown":true}),
    ] {
        let mut value = manifest(true);
        value["effective_settings"] = settings;
        value["effective_settings_digest"] =
            json!(digest_json_ensure_ascii(&value["effective_settings"]));
        assert!(parsed(&value).is_err());
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = env::temp_dir().join(format!(
            "catchplate-managed-google-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let result = Self(path);
        result.write(".operator-publication.lock", b"");
        result
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn owner(&self) -> Owner {
        Owner::open(&self.0.join("policy-bundle.json")).unwrap()
    }
    fn path(&self) -> PathBuf {
        self.0.join("operator-google-configuration.json")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove exact synthetic managed-Google scratch");
    }
}

#[test]
fn operator_google_managed_file_load_uses_real_retained_shared_permit() {
    let scratch = Scratch::new();
    let value = manifest(true);
    scratch.write(
        "operator-google-configuration.json",
        value.to_string().as_bytes(),
    );
    let owner = scratch.owner();
    let permit = owner
        .acquire(Instant::now() + Duration::from_secs(2))
        .unwrap();
    let loaded = load_at(&scratch.path(), &permit).unwrap();
    assert_eq!(loaded.identity.status()["operation"], value["operation"]);
    scratch.write(
        "operator-google-configuration.json",
        manifest(false).to_string().as_bytes(),
    );
    assert_eq!(
        loaded.identity.status()["operation"],
        value["operation"],
        "cold identity is not hot-mutated"
    );
}

#[test]
fn operator_google_managed_file_refuses_missing_modes_links_fifo_and_size() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let permit = owner
        .acquire(Instant::now() + Duration::from_secs(2))
        .unwrap();
    assert!(load_at(&scratch.path(), &permit).is_err());
    scratch.write(
        "operator-google-configuration.json",
        manifest(true).to_string().as_bytes(),
    );
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_at(&scratch.path(), &permit).is_err());
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(scratch.path(), scratch.0.join("alias")).unwrap();
    assert!(load_at(&scratch.path(), &permit).is_err());
    fs::remove_file(scratch.path()).unwrap();
    symlink("alias", scratch.path()).unwrap();
    assert!(load_at(&scratch.path(), &permit).is_err());
    fs::remove_file(scratch.path()).unwrap();
    let name = CString::new(scratch.path().as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(load_at(&scratch.path(), &permit).is_err());
    fs::remove_file(scratch.path()).unwrap();
    for bytes in [
        Vec::new(),
        vec![b' '; MAX_BYTES as usize + 1],
        b"not JSON".to_vec(),
    ] {
        scratch.write("operator-google-configuration.json", &bytes);
        assert!(load_at(&scratch.path(), &permit).is_err());
    }
}

#[test]
fn operator_google_managed_file_refuses_replaced_publication_owner() {
    let scratch = Scratch::new();
    scratch.write(
        "operator-google-configuration.json",
        manifest(true).to_string().as_bytes(),
    );
    let owner = scratch.owner();
    let permit = owner
        .acquire(Instant::now() + Duration::from_secs(2))
        .unwrap();
    fs::rename(
        scratch.0.join(".operator-publication.lock"),
        scratch.0.join("retained-lock"),
    )
    .unwrap();
    scratch.write(".operator-publication.lock", b"");
    assert!(load_at(&scratch.path(), &permit).is_err());
}
