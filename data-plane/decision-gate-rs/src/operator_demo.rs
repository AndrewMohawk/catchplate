//! Explicit non-production operator demo. This is not native custody authority.
//! Deployment pins origins and (optionally) one synthetic fixture IP. Signed
//! policy can narrow that set, never expand it. Unknown/expired clients fail
//! existing bearer authentication; no raw header becomes an identity.

use super::{
    audit_enabled, current_snapshot, is_sha256_digest, policy_high_water_for,
    validate_policy_high_water, GateState, Principal, ProxyAuthorizationPolicy,
    ResolvedAddressPolicy, Snapshot,
};
use ipnet::IpNet;
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, RwLock};
use url::{Host, Url};

const MARKER: &[u8] = b"{\"schema\": \"catchplate.operatorDemo/v1\", \"syntheticOnly\": false}\n";
const O_NOFOLLOW: i32 = 0x20000;
pub(crate) const INGRESS_MODE: &str = "operator-demo-tls-edge";
unsafe extern "C" {
    fn geteuid() -> u32;
}

fn refused() -> String {
    "operator demo admission refused".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Target {
    host: String,
    port: u16,
}

impl Target {
    fn parse(origin: &str) -> Result<Self, String> {
        if origin.len() > 2048
            || !origin.is_ascii()
            || origin.trim() != origin
            || origin
                .bytes()
                .any(|b| b.is_ascii_control() || b"@\\%".contains(&b))
        {
            return Err(refused());
        }
        let url = Url::parse(origin).map_err(|_| refused())?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(refused());
        }
        let Some(Host::Domain(host)) = url.host() else {
            return Err(refused());
        };
        let port = url.port_or_known_default().ok_or_else(refused)?;
        let fixture = host == "demo-upstream" && port == 8443;
        let canonical = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };
        if host.len() > 253
            || !(origin == canonical
                || origin == format!("{canonical}/")
                || port == 443
                    && (origin == format!("{canonical}:443")
                        || origin == format!("{canonical}:443/")))
        {
            return Err(refused());
        }
        if !fixture
            && (port != 443
                || !host.contains('.')
                || host.ends_with('.')
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
                || ["localhost", "local", "internal", "invalid", "test"]
                    .iter()
                    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}"))))
        {
            return Err(refused());
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    fn from_parts(scheme: &str, host: &str, port: u16) -> Result<Self, String> {
        if scheme != "https" {
            return Err(refused());
        }
        let target = Self::parse(&format!("https://{host}:{port}"))?;
        if target.host != host || target.port != port {
            return Err(refused());
        }
        Ok(target)
    }

    fn fixture(&self) -> bool {
        self.host == "demo-upstream" && self.port == 8443
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct Deployment {
    origins: BTreeSet<Target>,
    fixture_cidrs: Vec<IpNet>,
}

impl Deployment {
    pub(super) fn managed(settings: &Value) -> Result<Self, String> {
        let object = settings.as_object().ok_or_else(refused)?;
        if object.len() != 2 || !object.contains_key("allowed_upstreams")
            || !object.contains_key("fixture_cidrs") {
            return Err(refused());
        }
        let origins = object["allowed_upstreams"].as_array().ok_or_else(refused)?;
        for origin in origins {
            let raw = origin.as_str().ok_or_else(refused)?;
            let target = Target::parse(raw)?;
            let canonical = if target.port == 443 { format!("https://{}", target.host) }
                else { format!("https://{}:{}", target.host, target.port) };
            if raw != canonical { return Err(refused()); }
        }
        Self::parse(&object["allowed_upstreams"].to_string(),
            Some(&object["fixture_cidrs"].to_string()))
    }

    pub(super) fn require_google(&self, enabled: bool) -> Result<(), String> {
        if enabled && !self.origins.contains(&Target::parse(super::operator_google_profile::ORIGIN)?) {
            return Err(refused());
        }
        Ok(())
    }

    fn parse(origins: &str, fixture: Option<&str>) -> Result<Self, String> {
        if origins.len() > 16 * 1024 || fixture.is_some_and(|value| value.len() > 256) {
            return Err(refused());
        }
        let raw: Vec<String> = serde_json::from_str(origins).map_err(|_| refused())?;
        if !(1..=32).contains(&raw.len()) {
            return Err(refused());
        }
        let origins = raw
            .iter()
            .map(|value| Target::parse(value))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if origins.len() != raw.len() {
            return Err(refused());
        }
        let cidrs: Vec<String> =
            serde_json::from_str(fixture.unwrap_or("[]")).map_err(|_| refused())?;
        if cidrs.len() > 1 {
            return Err(refused());
        }
        let fixture_cidrs = cidrs
            .iter()
            .map(|raw| {
                let cidr: IpNet = raw.parse().map_err(|_| refused())?;
                let allowed = match cidr.addr() {
                    IpAddr::V4(ip) => {
                        cidr.prefix_len() == 32 && (ip.is_private() || ip.is_loopback())
                    }
                    IpAddr::V6(ip) => {
                        cidr.prefix_len() == 128 && (ip.is_unique_local() || ip.is_loopback())
                    }
                };
                if !allowed || cidr.to_string() != *raw {
                    return Err(refused());
                }
                Ok(cidr)
            })
            .collect::<Result<Vec<_>, String>>()?;
        if origins.iter().any(Target::fixture) != !fixture_cidrs.is_empty() {
            return Err(refused());
        }
        Ok(Self {
            origins,
            fixture_cidrs,
        })
    }
}

pub(crate) struct Selection {
    // None exists only between managed mode selection and the guarded cold load.
    deployment: Option<Arc<Deployment>>,
    google: Option<super::operator_google_profile::Profile>,
    managed_google: Option<super::operator_google_managed::Identity>,
    managed_x: bool,
    x: Option<super::operator_x_profile::State>,
}

fn selected(
    flag: Option<&str>,
    channel: Option<&str>,
    production: Option<&str>,
    synthetic: Option<&str>,
    native_arguments: bool,
    forbidden: bool,
) -> Result<bool, String> {
    match flag {
        None | Some("0") => Ok(false),
        Some("1")
            if channel == Some("dev")
                && matches!(production, None | Some("0"))
                && matches!(synthetic, None | Some("0"))
                && !native_arguments
                && !forbidden =>
        {
            Ok(true)
        }
        _ => Err(refused()),
    }
}

pub(crate) fn from_environment() -> Result<Option<Selection>, String> {
    let forbidden = env::vars_os().any(|(name, value)| {
        let name = name.to_string_lossy();
        !value.is_empty()
            && name.starts_with("CATCHPLATE_")
            && ([
                "CATCHPLATE_NATIVE_",
                "CATCHPLATE_NITRO_",
                "CATCHPLATE_AUTHORITY_",
                "CATCHPLATE_AWS_KMS_",
                "CATCHPLATE_POLICY_SHADOW_",
                "CATCHPLATE_MASTER_KEY_UNSEAL_COMMAND",
                "CATCHPLATE_WORKLOAD_IDENTITY_",
                "CATCHPLATE_CONTROL_PLANE_CUSTODY_",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
                || name.ends_with("_FD")
                || name.contains("_FD_"))
    });
    let operator = selected(
        env::var("CATCHPLATE_OPERATOR_DEMO").ok().as_deref(),
        env::var("CATCHPLATE_RELEASE_CHANNEL").ok().as_deref(),
        env::var("CATCHPLATE_PRODUCTION_IMAGE").ok().as_deref(),
        env::var("CATCHPLATE_DEVELOPMENT_SANDBOX").ok().as_deref(),
        env::args_os().nth(1).is_some(),
        forbidden,
    )?;
    let managed = super::operator_google_managed::from_environment(operator)?;
    let managed_x = super::operator_x_profile::from_environment(operator)?;
    let google = if managed { None }
        else { super::operator_google_profile::Profile::from_environment(operator)? };
    if !operator {
        return Ok(None);
    }
    if managed {
        return Ok(Some(Selection { deployment: None, google: None, managed_google: None,
            managed_x, x: None }));
    }
    let deployment = Deployment::parse(
        &env::var("CATCHPLATE_OPERATOR_DEMO_UPSTREAMS").map_err(|_| refused())?,
        env::var("CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS")
            .ok()
            .as_deref(),
    )?;
    deployment.require_google(google.is_some())?;
    Ok(Some(Selection {
        deployment: Some(Arc::new(deployment)),
        google,
        managed_google: None,
        managed_x,
        x: None,
    }))
}

fn validate_marker(directory: &Path) -> Result<(), String> {
    let owner = unsafe { geteuid() };
    let metadata = fs::symlink_metadata(directory).map_err(|_| refused())?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err(refused());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(directory.join(".catchplate-operator-demo.json"))
        .map_err(|_| refused())?;
    let before = file.metadata().map_err(|_| refused())?;
    if !before.is_file()
        || before.uid() != owner
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() != MARKER.len() as u64
    {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(513)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    let after = file.metadata().map_err(|_| refused())?;
    if bytes != MARKER
        || before.ino() != after.ino()
        || before.dev() != after.dev()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.ctime() != after.ctime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(refused());
    }
    Ok(())
}

fn authenticated_principal(principal: &Principal) -> bool {
    principal.required_headers.is_empty()
        && principal.mtls.is_none()
        && matches!(&principal.proxy_authorization,
            Some(ProxyAuthorizationPolicy::BearerToken { token_sha256, expires_at_ms: Some(expiry), .. })
                if is_sha256_digest(token_sha256) && *expiry > 0 && *expiry <= u128::from(u64::MAX))
}

#[derive(Clone)]
struct ApprovedPolicy {
    high_water: super::PolicyHighWater,
    targets: BTreeSet<Target>,
}

pub(crate) struct Profile {
    deployment: Arc<Deployment>,
    active: Arc<RwLock<ApprovedPolicy>>,
    google: Option<super::operator_google_profile::Profile>,
    managed_google: Option<super::operator_google_managed::Identity>,
    managed_x: Option<Arc<RwLock<super::operator_x_profile::State>>>,
}
pub(crate) struct PreparedReload {
    previous_hash: String,
    approved: ApprovedPolicy,
    x: Option<super::operator_x_profile::State>,
}

impl Selection {
    pub(crate) fn load_committed(mut self, permit: &super::operator_audit_publication::Permit<'_>)
        -> Result<Self, String> {
        if self.deployment.is_none() {
            let configuration = super::operator_google_managed::load(permit)?;
            self.deployment = Some(Arc::new(configuration.deployment));
            self.google = configuration.google;
            self.managed_google = Some(configuration.identity);
        }
        if self.managed_x {
            let configuration = super::operator_x_profile::load(permit)?;
            if self.deployment.as_deref() != Some(&configuration.deployment)
                || self.managed_google.as_ref().is_some_and(|google|
                    google.status()["effective_settings_digest"].as_str()
                        != Some(configuration.state.identity.settings_digest())) {
                return Err(refused());
            }
            self.x = Some(configuration.state);
        }
        Ok(self)
    }

    pub(crate) fn admit(self, state: &GateState) -> Result<Profile, String> {
        let deployment = self.deployment.ok_or_else(refused)?;
        if state.is_production
            || state.native_serving_privileges.is_some()
            || state.native_secret_broker.is_some()
            || state.measured_canary_delivery.is_some()
            || state.native_policy_bytes.is_some()
            || state.policy_shadow_generation_control.is_some()
            || state.atomic_release_authorization_enabled
            || state.proxy_ingress_attestation.mode != INGRESS_MODE
            || state.policy_path != "/data/policy-bundle.json"
            || state.credential_lease_url.as_deref()
                != Some("http://catchplate:3000/api/data-plane/credential-leases")
            || state.audit_url.as_deref() != Some("http://catchplate:3000/api/data-plane/audit")
            || state.server_instance_id.as_deref()
                != Some("spiffe://operator-demo.catchplate/decision-gate/local")
            || !audit_enabled(state)
            || state.policy_high_water_path.is_none()
            || ((self.google.is_some() || self.x.is_some()) && (state.credential_currentness.enabled()
                || state.credential_lease_recipient_attestation_command.is_some()
                || state.response_proof_signer.release_profile() != super::ReleaseProfile::Legacy))
        {
            return Err(refused());
        }
        validate_marker(Path::new("/data"))?;
        let snapshot = current_snapshot(state);
        let profile = Profile {
            deployment,
            google: self.google,
            managed_google: self.managed_google,
            managed_x: self.x.map(|x| Arc::new(RwLock::new(x))),
            active: Arc::new(RwLock::new(ApprovedPolicy {
                high_water: policy_high_water_for(&snapshot),
                targets: BTreeSet::new(),
            })),
        };
        let approved = profile.validate_snapshot(&snapshot)?;
        *profile.active.write().map_err(|_| refused())? = approved;
        Ok(profile)
    }
}

impl Profile {
    fn validate_snapshot(&self, snapshot: &Snapshot) -> Result<ApprovedPolicy, String> {
        let x = self.managed_x.as_ref().map(|state|
            state.read().map(|state| state.clone()).map_err(|_| refused())).transpose()?;
        self.validate_snapshot_with_x(snapshot, x.as_ref())
    }

    fn validate_snapshot_with_x(&self, snapshot: &Snapshot, x: Option<&super::operator_x_profile::State>)
        -> Result<ApprovedPolicy, String> {
        if let Some(x) = x { x.validate_snapshot(snapshot)?; }
        if let Some(google) = &self.google { google.validate_snapshot(snapshot)?; }
        // A disabled managed cold admission cannot acquire Google authority
        // through a later policy-only reload, even if Gmail was already allowed.
        if self.managed_google.is_some() && self.google.is_none()
            && snapshot.credentials.values().any(|credential| credential.kind() == "oauth2"
                && super::normalized_credential_provider(&credential.provider) == "google") {
            return Err(refused());
        }
        if snapshot.policy_id != "catchplate-operator-demo"
            || !is_sha256_digest(&snapshot.hash)
            || snapshot.policy_sequence == 0
            || snapshot.rollback_epoch == 0
            || snapshot.principals.is_empty()
            || !snapshot.principals.iter().all(authenticated_principal)
        {
            return Err(refused());
        }
        let mut targets = BTreeSet::new();
        for route in &snapshot.routes {
            let target = Target::from_parts(&route.scheme, &route.host, route.port)?;
            if !self.deployment.origins.contains(&target) {
                return Err(refused());
            }
            match &route.resolved_address_policy {
                ResolvedAddressPolicy::PublicOnly if !target.fixture() => {}
                ResolvedAddressPolicy::ExplicitCidrs(cidrs)
                    if target.fixture()
                        && cidrs == &self.deployment.fixture_cidrs
                        && !cidrs.is_empty() => {}
                _ => return Err(refused()),
            }
            targets.insert(target);
        }
        Ok(ApprovedPolicy {
            high_water: policy_high_water_for(snapshot),
            targets,
        })
    }

    pub(crate) fn prepare_reload(
        &self,
        previous: &Snapshot,
        next: &Snapshot,
    ) -> Result<PreparedReload, String> {
        self.prepare_reload_with_publication(previous, next, None)
    }

    pub(crate) fn prepare_reload_with_publication(
        &self, previous: &Snapshot, next: &Snapshot,
        publication: Option<&super::operator_audit_publication::Permit<'_>>,
    ) -> Result<PreparedReload, String> {
        let x = if let Some(current) = &self.managed_x {
            let current = current.read().map_err(|_| refused())?.clone();
            let configuration = current.reload(publication.ok_or_else(refused)?)?;
            if configuration.deployment != *self.deployment
                || self.managed_google.as_ref().is_some_and(|google|
                    google.status()["effective_settings_digest"].as_str()
                        != Some(configuration.state.identity.settings_digest())) { return Err(refused()); }
            current.require_successor(&configuration.state)?;
            Some(configuration.state)
        } else { None };
        let approved = self.validate_snapshot_with_x(next, x.as_ref())?;
        let active = self.active.read().map_err(|_| refused())?;
        if active.high_water.policy_hash != previous.hash {
            return Err(refused());
        }
        validate_policy_high_water(next, &active.high_water)?;
        Ok(PreparedReload {
            previous_hash: previous.hash.clone(),
            approved,
            x,
        })
    }

    /// Called only while the caller owns the dispatch mutation and snapshot write guards.
    pub(crate) fn commit_reload(&self, prepared: PreparedReload) -> Result<(), String> {
        let mut active = self.active.write().map_err(|_| refused())?;
        if active.high_water.policy_hash != prepared.previous_hash {
            return Err(refused());
        }
        match (&self.managed_x, prepared.x) {
            (Some(current), Some(next)) => {
                let mut current = current.write().map_err(|_| refused())?;
                current.require_successor(&next)?;
                *current = next;
            }
            (None, None) => {}
            _ => return Err(refused()),
        }
        *active = prepared.approved;
        Ok(())
    }

    pub(crate) fn matches(&self, policy_hash: &str) -> bool {
        self.active
            .read()
            .is_ok_and(|active| active.high_water.policy_hash == policy_hash)
    }

    pub(crate) fn configuration_changed(&self, publication: Option<&super::operator_audit_publication::Permit<'_>>)
        -> Result<bool, String> {
        match &self.managed_x {
            Some(state) => state.read().map_err(|_| refused())?
                .publication_changed(publication.ok_or_else(refused)?),
            None => Ok(false),
        }
    }

    pub(crate) fn google_profile(&self, snapshot: &Snapshot, scope: &super::CredentialLeaseScope)
        -> Result<Option<&super::operator_google_profile::Profile>, String> {
        let Some(google) = &self.google else { return Ok(None); };
        if !self.matches(&snapshot.hash) { return Err(refused()); }
        Ok(if google.scope_admitted(snapshot, scope)? { Some(google) } else { None })
    }

    pub(crate) fn x_profile(&self, snapshot: &Snapshot, scope: &super::CredentialLeaseScope)
        -> Result<Option<Arc<super::operator_x_profile::Profile>>, String> {
        let Some(state) = &self.managed_x else { return Ok(None); };
        if !self.matches(&snapshot.hash) { return Err(refused()); }
        let profile = state.read().map_err(|_| refused())?.profile.clone();
        match profile {
            Some(profile) if profile.scope_admitted(snapshot, scope)? => Ok(Some(profile)),
            _ => Ok(None),
        }
    }

    pub(crate) fn status(&self) -> Value {
        let hash = self
            .active
            .read()
            .ok()
            .map(|active| active.high_water.policy_hash.clone());
        let mut value = serde_json::json!({"api_version":"catchplate.policyShadowRuntimeStatus/v2",
            "mode":"operator-demo", "enabled":false, "readiness":false,
            "readiness_reason":"intentionally_uncommissioned_operator_demo",
            "production_custody_bound":false, "active_generation":null,
            "operator_policy_sha256":hash, "upstream_origin_count":self.deployment.origins.len()});
        if let Some(identity) = &self.managed_google {
            value["managed_google"] = identity.status();
        }
        if let Some(state) = &self.managed_x {
            value["managed_x"] = state.read().map(|state| state.identity.status()).unwrap_or(Value::Null);
        }
        value
    }

    pub(crate) fn effect(
        &self,
        snapshot: &Snapshot,
        route_id: &str,
    ) -> Result<EffectPermit, String> {
        let route = snapshot
            .routes
            .iter()
            .find(|route| route.id == route_id)
            .ok_or_else(refused)?;
        self.effect_for_target(&snapshot.hash, &route.scheme, &route.host, route.port)
    }

    pub(crate) fn effect_for_target(
        &self,
        policy_hash: &str,
        scheme: &str,
        host: &str,
        port: u16,
    ) -> Result<EffectPermit, String> {
        let target = Target::from_parts(scheme, host, port)?;
        let active = self.active.read().map_err(|_| refused())?;
        if active.high_water.policy_hash != policy_hash
            || !active.targets.contains(&target)
            || !self.deployment.origins.contains(&target)
        {
            return Err(refused());
        }
        Ok(EffectPermit {
            active: Arc::clone(&self.active),
            policy_hash: policy_hash.to_owned(),
            target,
        })
    }
}

/// Non-custody authority scoped to one admitted origin and current policy hash.
pub(crate) struct EffectPermit {
    active: Arc<RwLock<ApprovedPolicy>>,
    policy_hash: String,
    target: Target,
}
pub(crate) struct DispatchPermit {
    effect: EffectPermit,
    request_commitment: String,
}

impl EffectPermit {
    pub(crate) fn validate(&self, policy_hash: &str) -> Result<(), String> {
        if policy_hash != self.policy_hash
            || !self
                .active
                .read()
                .is_ok_and(|active| active.high_water.policy_hash == self.policy_hash)
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn execute<T>(
        &self,
        policy_hash: &str,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        self.validate(policy_hash)?;
        operation()
    }
    pub(crate) fn bind_dispatch(
        self,
        policy_hash: &str,
        scheme: &str,
        host: &str,
        port: u16,
        request_commitment: &str,
    ) -> Result<DispatchPermit, String> {
        self.validate(policy_hash)?;
        if self.target != Target::from_parts(scheme, host, port)?
            || !is_sha256_digest(request_commitment)
        {
            return Err(refused());
        }
        Ok(DispatchPermit {
            effect: self,
            request_commitment: request_commitment.to_owned(),
        })
    }
}

impl DispatchPermit {
    pub(crate) fn validate(
        &self,
        policy_hash: &str,
        request_commitment: &str,
    ) -> Result<(), String> {
        self.effect.validate(policy_hash)?;
        if request_commitment != self.request_commitment {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "operator_demo_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::test_publish_dispatch_profile;
