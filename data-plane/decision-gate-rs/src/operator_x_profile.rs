//! Public-only ordinary X admission. Configuration grants neither consent nor
//! posting authority; signed routes, runtime OAuth identity and leases still do.
use super::*;
use std::fs::{self, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) const CAPABILITY: &str = "operator-x-oauth-v1";
const PATH: &str = "/data/operator-x-configuration.json";
const SCHEMA: &str = "catchplate.operatorXGateConfiguration/v1";
const MAX_BYTES: u64 = 32_768;

fn refused() -> String { "operator X public configuration refused".to_owned() }

fn selected(flag: Option<&str>, operator: bool, external: bool) -> Result<bool, String> {
    match flag {
        None | Some("0") => Ok(false),
        Some("1") if operator && !external => Ok(true),
        _ => Err(refused()),
    }
}

pub(super) fn from_environment(operator: bool) -> Result<bool, String> {
    let raw = env::var_os("CATCHPLATE_OPERATOR_MANAGED_X_ENABLED");
    let flag = raw.as_ref().map(|value| value.to_str().ok_or_else(refused)).transpose()?;
    let external = env::vars_os().any(|(name, _)| {
        let name = name.to_string_lossy();
        name.starts_with("CATCHPLATE_X_OAUTH_") || name.starts_with("CATCHPLATE_TWITTER_OAUTH_")
            || name == "CATCHPLATE_OPERATOR_X_PROFILE"
    });
    selected(flag, operator, external)
}

pub(super) fn gate_capability() -> Value {
    json!({"schema":"catchplate.operatorXPostGate/v1","adapter":x_post::ADAPTER,"operation":"tweets.write"})
}

#[derive(Clone)]
pub(super) struct Profile { client_id: String, binding_digest: String, quota_enabled: bool }

impl Profile {
    fn parse(binding: &Value) -> Result<Self, String> {
        let client = binding.get("client_id").and_then(Value::as_str).ok_or_else(refused)?;
        if !(1..=256).contains(&client.len()) || !client.bytes().all(|byte| (33..=126).contains(&byte)) {
            return Err(refused());
        }
        let redirect = binding.get("redirect_uri").and_then(Value::as_str).ok_or_else(refused)?;
        let host = redirect.strip_prefix("https://")
            .and_then(|raw| raw.strip_suffix("/api/oauth/callback/x")).ok_or_else(refused)?;
        if host.len() > 253 || !host.contains('.') || host.parse::<IpAddr>().is_ok()
            || host.split('.').any(|label| label.is_empty() || label.len() > 63
                || label.starts_with('-') || label.ends_with('-')
                || !label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
            || ["localhost", "local", "internal", "invalid", "test"].iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}"))) {
            return Err(refused());
        }
        let expected = json!({"schema":"catchplate.operatorXOAuthProfile/v1","profile":CAPABILITY,
            "provider_id":"x","client_id":client,"redirect_uri":redirect,
            "client_auth_method":"client_secret_basic","permission_preset":"x_text_post_v1",
            "scopes":x_post::SCOPES,"api_origins":["https://api.x.com"],
            "authorization_url":"https://x.com/i/oauth2/authorize",
            "token_url":"https://api.x.com/2/oauth2/token",
            "revocation_url":"https://api.x.com/2/oauth2/revoke",
            "identity_url":"https://api.x.com/2/users/me"});
        if *binding != expected { return Err(refused()); }
        Ok(Self { client_id: client.to_owned(), binding_digest: digest_json_ensure_ascii(&expected),
            quota_enabled: operator_x_quota::selected_flag()? })
    }

    pub(super) fn binding_digest(&self) -> &str { &self.binding_digest }

    fn x_credential(&self, credential: &Credential) -> Result<bool, String> {
        if credential.kind() != "oauth2" || normalized_credential_provider(&credential.provider) != "x" {
            return Ok(false);
        }
        x_post::validate_credential(credential)?;
        let subject = credential.provider_subject.as_deref().ok_or_else(refused)?;
        if subject.parse::<u64>().ok().filter(|value| *value > 0).is_none_or(|value| value.to_string() != subject)
            || credential.oauth_client_id() != Some(self.client_id.as_str())
            || credential.scopes().collect::<Vec<_>>() != x_post::SCOPES {
            return Err(refused());
        }
        Ok(true)
    }

    pub(super) fn validate_snapshot(&self, snapshot: &Snapshot) -> Result<(), String> {
        for credential in snapshot.credentials.values() { self.x_credential(credential)?; }
        for route in &snapshot.routes {
            if route.credential_ref.as_ref().and_then(|id| snapshot.credentials.get(id))
                .map(|credential| self.x_credential(credential)).transpose()?.unwrap_or(false) {
                self.route(route)?;
            }
        }
        Ok(())
    }

    fn route(&self, route: &Route) -> Result<(), String> {
        x_post::validate_route(route)?;
        // Route syntax is not a dispatch permit. Limited routes additionally
        // require the separately installed ordinary one-use quota owner.
        if (route.constraints.len() != 1 && !self.quota_enabled)
            || route.adapter_config["credentialBinding"]["clientIds"] != json!([self.client_id])
            || route.adapter_config["credentialBinding"]["requiredScopes"] != json!(x_post::SCOPES) {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn scope_admitted(&self, snapshot: &Snapshot, scope: &CredentialLeaseScope) -> Result<bool, String> {
        let credential = snapshot.credentials.get(&scope.credential_id).ok_or_else(refused)?;
        if !self.x_credential(credential)? { return Ok(false); }
        validate_credential_lease_scope(snapshot, scope)?;
        let route = snapshot.routes.iter().find(|route| route.id == scope.route_id).ok_or_else(refused)?;
        self.route(route)?;
        if route.adapter_config["credentialBinding"]["subjects"] != json!([credential.provider_subject.as_deref().ok_or_else(refused)?]) {
            return Err(refused());
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Operation { operation_id: String, owner_id: String, config_version: u64 }

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Identity {
    operation: Option<Operation>, profile_binding_digest: Option<String>, effective_settings_digest: String,
}
impl Identity {
    pub(super) fn status(&self) -> Value {
        json!({"operation":self.operation,"profile_binding_digest":self.profile_binding_digest,
            "effective_settings_digest":self.effective_settings_digest})
    }
    pub(super) fn settings_digest(&self) -> &str { &self.effective_settings_digest }
}

#[derive(Clone)]
pub(super) struct State {
    pub(super) profile: Option<Arc<Profile>>,
    pub(super) identity: Identity,
    file_identity: Option<(u64,u64,u64,i64,i64,i64,i64)>,
    // Production construction fixes this to PATH; only the test loader can
    // select a temporary publication directory. Reload never accepts a caller path.
    path: PathBuf,
    #[cfg(test)]
    test_quota_selection: Option<bool>,
}
impl State {
    pub(super) fn require_successor(&self, next: &Self) -> Result<(), String> {
        if self.identity.effective_settings_digest != next.identity.effective_settings_digest
            || (self.profile.is_some() && self.identity != next.identity) {
            return Err(refused());
        }
        Ok(())
    }
    pub(super) fn validate_snapshot(&self, snapshot: &Snapshot) -> Result<(), String> {
        if let Some(profile) = &self.profile { return profile.validate_snapshot(snapshot); }
        if snapshot.credentials.values().any(|credential| credential.kind() == "oauth2"
            && normalized_credential_provider(&credential.provider) == "x") { return Err(refused()); }
        Ok(())
    }
    pub(super) fn publication_changed(&self, permit: &operator_audit_publication::Permit<'_>) -> Result<bool, String> {
        permit.check()?;
        let current = identity(&fs::symlink_metadata(&self.path).map_err(|_| refused())?)?;
        permit.check()?;
        Ok(self.file_identity != Some(current))
    }
    pub(super) fn reload(&self, permit: &operator_audit_publication::Permit<'_>) -> Result<Configuration, String> {
        #[cfg(test)]
        if self.test_quota_selection == Some(true) {
            return test_load_with_quota(&self.path, permit);
        }
        load_at(&self.path, permit)
    }
}

pub(super) struct Configuration { pub(super) deployment: operator_demo::Deployment, pub(super) state: State }

pub(super) fn parse(bytes: &[u8]) -> Result<Configuration, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES { return Err(refused()); }
    let value = strict_json_value_from_slice(bytes).map_err(|_| refused())?;
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != 6 || ["schema","operation","profile_binding","profile_binding_digest",
        "effective_settings","effective_settings_digest"].iter().any(|key| !object.contains_key(*key))
        || value["schema"] != SCHEMA { return Err(refused()); }
    let digest = value["effective_settings_digest"].as_str().ok_or_else(refused)?;
    if digest_json_ensure_ascii(&value["effective_settings"]) != digest { return Err(refused()); }
    let deployment = operator_demo::Deployment::managed(&value["effective_settings"])?;
    let (operation, profile, binding_digest) = if value["operation"].is_null()
        && value["profile_binding"].is_null() && value["profile_binding_digest"].is_null() {
        (None, None, None)
    } else {
        let operation: Operation = serde_json::from_value(value["operation"].clone()).map_err(|_| refused())?;
        let uuid = |raw: &str| raw.len() == 36 && raw.bytes().enumerate().all(|(index, byte)|
            if [8,13,18,23].contains(&index) { byte == b'-' }
            else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) });
        if !uuid(&operation.operation_id) || !uuid(&operation.owner_id) || operation.config_version != 1 {
            return Err(refused());
        }
        let profile = Profile::parse(&value["profile_binding"])?;
        if value["profile_binding_digest"].as_str() != Some(profile.binding_digest()) { return Err(refused()); }
        let binding = profile.binding_digest().to_owned();
        (Some(operation), Some(Arc::new(profile)), Some(binding))
    };
    Ok(Configuration { deployment, state: State { profile, file_identity: None, path: PathBuf::from(PATH),
        #[cfg(test)] test_quota_selection: None,
        identity: Identity {
        operation, profile_binding_digest: binding_digest, effective_settings_digest: digest.to_owned() } } })
}

fn identity(info: &Metadata) -> Result<(u64,u64,u64,i64,i64,i64,i64), String> {
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o7777 != 0o600
        || info.nlink() != 1 || info.len() == 0 || info.len() > MAX_BYTES { return Err(refused()); }
    Ok((info.dev(),info.ino(),info.len(),info.mtime(),info.mtime_nsec(),info.ctime(),info.ctime_nsec()))
}

pub(super) fn load(permit: &operator_audit_publication::Permit<'_>) -> Result<Configuration, String> {
    load_at(Path::new(PATH), permit)
}
fn load_at(path: &Path, permit: &operator_audit_publication::Permit<'_>) -> Result<Configuration, String> {
    permit.check()?;
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|_| refused())?;
    let before = identity(&file.metadata().map_err(|_| refused())?)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|_| refused())?;
    let mut value = parse(&bytes)?;
    if bytes.len() as u64 != before.2 || identity(&file.metadata().map_err(|_| refused())?)? != before
        || identity(&fs::symlink_metadata(path).map_err(|_| refused())?)? != before { return Err(refused()); }
    permit.check()?;
    value.state.file_identity = Some(before);
    value.state.path = path.to_path_buf();
    Ok(value)
}

#[cfg(test)]
pub(crate) fn test_load(path: &Path, permit: &operator_audit_publication::Permit<'_>) -> Result<Configuration, String> {
    load_at(path, permit)
}

#[cfg(test)]
pub(crate) fn test_load_with_quota(path: &Path, permit: &operator_audit_publication::Permit<'_>) -> Result<Configuration, String> {
    let mut configuration = load_at(path, permit)?;
    Arc::get_mut(configuration.state.profile.as_mut().ok_or_else(refused)?).ok_or_else(refused)?.quota_enabled = true;
    configuration.state.test_quota_selection = Some(true);
    Ok(configuration)
}

#[cfg(test)]
#[path = "operator_x_profile_tests.rs"]
pub(crate) mod tests;
