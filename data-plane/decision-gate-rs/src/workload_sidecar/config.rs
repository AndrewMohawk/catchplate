//! Exact pinned cold scope. Configuration hashes are not independent approval.
use super::{ensure, is_sha256_digest, json, lifetime::{ConnectionBounds, Lifetime, NamespaceSettings},
    originals::{ArtifactV1, HeldOriginal}, upstream};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

const MAX_CONFIGURATION: usize = 32 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Settings {
    api_version: String,
    profile: String,
    pub(super) workload_id: String,
    pub(super) listen_port: u16,
    local_token_sha256: String,
    pub(super) allowed_destinations: Vec<String>,
    namespace: NamespaceSettings,
    issued_at_epoch_ns: u64,
    expires_at_epoch_ns: u64,
    pub(super) maximum_connections: u16,
    pub(super) maximum_connection_seconds: u64,
    pub(super) header_timeout_milliseconds: u64,
    pub(super) maximum_tunnel_bytes: u64,
    upstream: upstream::Configuration,
}

fn destination(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else { return false; };
    !host.is_empty() && host.len() <= 253 && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|part| !part.is_empty() && part.len() <= 63
            && !part.starts_with('-') && !part.ends_with('-')
            && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        && port.parse::<u16>().is_ok_and(|number| number > 0 && number.to_string() == port)
}
impl Settings {
    fn validate(&self) -> Result<(), String> {
        ensure(self.api_version == "serverware.nativeWorkloadSidecar/v1"
            && self.profile == "native-attested-local-connect-v1", "sidecar profile differs")?;
        ensure(!self.workload_id.is_empty() && self.workload_id.len() <= 128
            && self.workload_id.as_bytes()[0].is_ascii_alphanumeric()
            && self.workload_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && self.listen_port >= 1024 && is_sha256_digest(&self.local_token_sha256),
            "sidecar workload identity or local listener scope is invalid")?;
        ensure((1..=64).contains(&self.allowed_destinations.len())
            && self.allowed_destinations.iter().enumerate().all(|(index, value)| destination(value)
                && !self.allowed_destinations[..index].contains(value)), "sidecar destination inventory is invalid")?;
        ensure((1..=16).contains(&self.maximum_connections)
            && (1..=120).contains(&self.maximum_connection_seconds)
            && (1..=5000).contains(&self.header_timeout_milliseconds)
            && (4096..=1_073_741_824).contains(&self.maximum_tunnel_bytes), "sidecar resource bounds differ")
    }
}

pub(super) struct Service {
    pub(super) settings: Settings,
    pub(super) token_digest: [u8; 32],
    pub(super) upstream: upstream::UpstreamOwner,
    lifetime: Arc<Lifetime>,
    original: Mutex<HeldOriginal>,
    poisoned: AtomicBool,
}
impl Service {
    pub(super) fn open(path: PathBuf, pin: String) -> Result<Arc<Self>, String> {
        ensure(is_sha256_digest(&pin), "sidecar requires an independent original pin")?;
        let (mut original, raw) = HeldOriginal::read_private(ArtifactV1 { path, sha256: pin }, MAX_CONFIGURATION)?;
        let value = json::parse(&raw, MAX_CONFIGURATION)?;
        let settings: Settings = serde_json::from_value(value)
            .map_err(|_| "sidecar configuration is not its exact closed schema")?;
        settings.validate()?;
        let mut token_digest = [0u8; 32];
        hex::decode_to_slice(&settings.local_token_sha256[7..], &mut token_digest)
            .map_err(|_| "sidecar local token digest invalid")?;
        // Retain the selected namespace values in both owners. Only Lifetime
        // holds and checks the actual namespace descriptor.
        let namespace = NamespaceSettings { device: settings.namespace.device, inode: settings.namespace.inode,
            boot_id: settings.namespace.boot_id.clone(), uid: settings.namespace.uid, gid: settings.namespace.gid };
        let lifetime = Arc::new(Lifetime::open(settings.issued_at_epoch_ns, settings.expires_at_epoch_ns, namespace)?);
        original.require_private()?;
        original.recheck()?;
        let upstream = upstream::UpstreamOwner::open(&settings.upstream, Arc::clone(&lifetime))?;
        let owner = Arc::new(Self { settings, token_digest, upstream, lifetime,
            original: Mutex::new(original), poisoned: AtomicBool::new(false) });
        owner.check()?;
        Ok(owner)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        let result = (|| {
            ensure(!self.poisoned.load(Ordering::Acquire), "sidecar service scope is poisoned")?;
            self.lifetime.check()?;
            let mut original = self.original.lock().map_err(|_| "sidecar cold owner poisoned")?;
            original.require_private()?;
            original.recheck()?;
            original.require_private()?;
            drop(original);
            self.upstream.check()?;
            self.lifetime.check()
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }
    pub(super) fn connection_bounds(&self) -> Result<ConnectionBounds, String> {
        self.check()?;
        self.lifetime.connection_bounds(self.settings.maximum_connection_seconds)
    }
}
