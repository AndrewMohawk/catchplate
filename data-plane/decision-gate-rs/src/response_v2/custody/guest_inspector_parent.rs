//! Source-owned inspector launch. Neither the configuration DTO nor sealed
//! consistency metadata is permission: actual root preparation and signed
//! router delivery originals are retained before the sole child creation.
use super::{guest_delivery, guest_inspector_parent_image as image,
    guest_inspector_parent_process as process};
use crate::native_serving_privileges::{Association, Owner, Prepared};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::{os::fd::{AsFd, BorrowedFd, OwnedFd}, path::Path,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact { path: String, sha256: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestInspectorConfiguration {
    api_version: String,
    executable: Artifact,
    configuration: Artifact,
    delivery: Artifact,
}
impl GuestInspectorConfiguration {
    pub fn validate(&self) -> Result<(), String> {
        if self.api_version != "serverware.nativeGuestInspector/v1" || self.executable.path != image::EXECUTABLE
            || !image::hash(&self.executable.sha256) || !image::hash(&self.configuration.sha256)
            || !image::hash(&self.delivery.sha256) || !image::path(&self.configuration.path)
            || !image::path(&self.delivery.path) || self.configuration.path == self.delivery.path
            || self.configuration.path == self.executable.path || self.delivery.path == self.executable.path {
            return Err("native guest inspector configuration differs from its closed profile".into());
        }
        Ok(())
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bootstrap<'a> {
    api_version: &'static str,
    configuration_path: &'a str,
    configuration_sha256: &'a str,
    delivery_path: &'a str,
    delivery_sha256: &'a str,
    gate_lifetime_deadline_boottime_ns: String,
    channel_nonce: &'a str,
}

pub struct PreparedGuestInspector {
    originals: guest_delivery::InspectionOriginals,
    association: Association,
    image: image::Image,
    bootstrap: image::Sealed,
    nonce: String,
    deadline: u64,
    admission_deadline: u64,
    configuration_path: String,
    delivery_path: String,
}
pub struct InitializedGuestInspector {
    prepared: PreparedGuestInspector,
    child: process::Process,
    router: Mutex<Option<OwnedFd>>,
    exported: AtomicBool,
}
impl PreparedGuestInspector {
    pub fn launch(configuration: GuestInspectorConfiguration, prepared: &Prepared)
        -> Result<Arc<InitializedGuestInspector>, String> {
        configuration.validate()?; prepared.check()?;
        let admitted = guest_delivery::ListenerPreparation::open(Path::new(&configuration.configuration.path),
            Path::new(&configuration.delivery.path), &configuration.delivery.sha256).map_err(|e| e.to_string())?;
        if admitted.binding().configuration_sha256 != configuration.configuration.sha256 {
            return Err("inspector configuration pin differs from genuine signed delivery".into());
        }
        let admission_deadline = admitted.binding().deadline_boottime_ns.parse::<u64>()
            .map_err(|_| "inspector original admission deadline invalid")?;
        let originals = admitted.into_inspection().map_err(|e| e.to_string())?;
        let image = image::Image::open(&configuration.executable.path, &configuration.executable.sha256)?;
        let mut nonce = [0u8; 32];
        if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) } != nonce.len() as isize || nonce == [0; 32] {
            return Err("inspector channel nonce unavailable".into());
        }
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let raw = crate::canonical_json_bytes(&Bootstrap {
            api_version: "serverware.responseV2.guestInspectorBootstrap/v1",
            configuration_path: &configuration.configuration.path, configuration_sha256: &configuration.configuration.sha256,
            delivery_path: &configuration.delivery.path, delivery_sha256: &configuration.delivery.sha256,
            gate_lifetime_deadline_boottime_ns: prepared.deadline().to_string(), channel_nonce: &nonce,
        }).map_err(|_| "inspector bootstrap encoding failed")?;
        let bootstrap = image::Sealed::new(&raw, false)?;
        let owner = Self { originals, association: Association::capture(prepared)?, image, bootstrap,
            nonce, deadline: prepared.deadline(), admission_deadline,
            configuration_path: configuration.configuration.path, delivery_path: configuration.delivery.path };
        owner.originals.check().map_err(|e| e.to_string())?;
        if process::now()? >= owner.admission_deadline { return Err("inspector original startup grant expired".into()); }
        let (child, router) = process::Process::spawn(&owner.image.sealed, &owner.bootstrap, prepared)?;
        let result = Arc::new(InitializedGuestInspector { prepared: owner, child, router: Mutex::new(Some(router)),
            exported: AtomicBool::new(false) });
        result.child.initialized(&result.prepared.nonce, result.prepared.bootstrap.sha256(),
            result.prepared.admission_deadline)?;
        prepared.check()?;
        result.check()?;
        Ok(result)
    }
}
impl InitializedGuestInspector {
    pub fn deadline_boottime_ns(&self) -> u64 { self.prepared.deadline }
    pub(crate) fn require_preparation(&self, prepared: &Prepared) -> Result<(), String> {
        self.prepared.association.require_preparation(prepared)?;
        self.check()
    }
    pub fn require_serving(&self, owner: &Owner) -> Result<(), String> {
        self.prepared.association.require(owner)?;
        self.check()
    }
    pub fn require_response_client(&self, generation: &str, router_uid: u32) -> Result<(), String> {
        self.check()?;
        let binding = self.prepared.originals.binding();
        if binding.generation_id != generation || binding.router_uid != router_uid {
            return Err("inspector original router differs from native response client".into());
        }
        Ok(())
    }
    pub fn check(&self) -> Result<(), String> {
        self.child.idle()?;
        self.prepared.originals.check().map_err(|e| e.to_string())?;
        self.prepared.image.check()?;
        self.prepared.bootstrap.check()
    }
    pub fn request_stop(&self) { self.child.stop(); }
    /// A real waitid reap before the original bound, not initialized/readiness
    /// evidence. Emergency stop is attempted even if that bound has passed.
    pub fn stop_and_reap(&self) -> Result<(), String> { self.child.stop_and_reap() }
    pub fn take_router_endpoint(self: &Arc<Self>) -> Result<GuestInspectorRouterEndpoint, String> {
        self.check()?;
        if self.exported.swap(true, Ordering::AcqRel) { return Err("inspector router endpoint was already consumed".into()); }
        let channel = self.router.lock().map_err(|_| "inspector endpoint owner poisoned")?
            .take().ok_or("inspector router endpoint absent")?;
        Ok(GuestInspectorRouterEndpoint { channel, owner: Arc::clone(self) })
    }
}
// No Clone, generic FD constructor, raw public descriptor or owner back-cycle.
pub struct GuestInspectorRouterEndpoint { channel: OwnedFd, owner: Arc<InitializedGuestInspector> }
pub(crate) struct GuestInspectorRouterBorrow<'a> { endpoint: &'a GuestInspectorRouterEndpoint }
impl GuestInspectorRouterEndpoint {
    pub(crate) fn inheritance(&self) -> Result<GuestInspectorRouterBorrow<'_>, String> {
        self.owner.check()?;
        Ok(GuestInspectorRouterBorrow { endpoint: self })
    }
}
impl GuestInspectorRouterBorrow<'_> {
    pub(crate) fn check(&self) -> Result<(), String> { self.endpoint.owner.check() }
    pub(crate) fn require_delivery(&self, configuration_path: &Path, configuration_sha256: &str,
        delivery_path: &Path, delivery_sha256: &str) -> Result<(), String> {
        self.check()?;
        let held = &self.endpoint.owner.prepared;
        let binding = held.originals.binding();
        if configuration_path != Path::new(&held.configuration_path) || delivery_path != Path::new(&held.delivery_path)
            || configuration_sha256 != binding.configuration_sha256 || delivery_sha256 != binding.delivery_sha256 {
            return Err("inspector endpoint differs from actual cohort router originals".into());
        }
        Ok(())
    }
    pub(crate) fn channel(&self) -> BorrowedFd<'_> { self.endpoint.channel.as_fd() }
    pub(crate) fn inspector_pidfd(&self) -> BorrowedFd<'_> { self.endpoint.owner.child.pidfd.as_fd() }
    pub(crate) fn bootstrap(&self) -> BorrowedFd<'_> { self.endpoint.owner.prepared.bootstrap.file().as_fd() }
    pub(crate) fn bootstrap_sha256(&self) -> &str { self.endpoint.owner.prepared.bootstrap.sha256() }
    pub(crate) fn nonce(&self) -> &str { &self.endpoint.owner.prepared.nonce }
    pub(crate) fn deadline_boottime_ns(&self) -> u64 { self.endpoint.owner.prepared.deadline }
}
