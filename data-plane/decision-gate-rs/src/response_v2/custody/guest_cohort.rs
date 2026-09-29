//! Fixed seven-role guest launch. Passive child progress is not independent
//! generation readiness: the ordinary signed readiness/client checks still run.
use super::{config::CustodyServiceRole as Role, guest_delivery,
    guest_inspector_parent::InitializedGuestInspector,
    guest_inspector_parent_image as image, guest_inspector_parent_process as kernel,
    guest_listener::PreparedGuestResponseV2Listener, guest_cohort_process::RoleProcess};
use crate::native_serving_privileges::{Association, Owner, Prepared};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, os::fd::BorrowedFd, path::Path, sync::Arc};

const EXECUTABLE: &str = "/usr/local/bin/serverware-response-v2-guest-role";
const NONROUTER: [Role; 5] = [Role::CredentialTransport, Role::PolicyProofVerifier,
    Role::ImmutableArtifactLedger, Role::ReleaseAttestorPublisher, Role::CleanupWatchdog];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact { path: String, sha256: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delivery { service_role: Role, path: String, sha256: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestCohortConfiguration {
    api_version: String,
    executable: Artifact,
    configuration: Artifact,
    deliveries: Vec<Delivery>,
}
impl GuestCohortConfiguration {
    pub fn validate(&self) -> Result<(), String> {
        if self.api_version != "serverware.nativeGuestCohort/v1"
            || self.executable.path != EXECUTABLE || !image::hash(&self.executable.sha256)
            || !image::path(&self.configuration.path) || !image::hash(&self.configuration.sha256)
            || self.configuration.path == self.executable.path || self.deliveries.len() != Role::ALL.len() {
            return Err("guest cohort is not the exact fixed seven-role profile".into());
        }
        let mut roles = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for delivery in &self.deliveries {
            if !roles.insert(delivery.service_role) || !paths.insert(delivery.path.as_str())
                || !image::path(&delivery.path) || !image::hash(&delivery.sha256)
                || delivery.path == self.configuration.path || delivery.path == self.executable.path {
                return Err("guest cohort delivery roles or original paths differ".into());
            }
        }
        if roles != Role::ALL.into_iter().collect() {
            return Err("guest cohort delivery inventory is incomplete".into());
        }
        Ok(())
    }
    fn delivery(&self, role: Role) -> Result<&Delivery, String> {
        self.deliveries.iter().find(|entry| entry.service_role == role)
            .ok_or_else(|| "guest cohort lost an exact role delivery".into())
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
    service_role: Role,
    gate_lifetime_deadline_boottime_ns: String,
    channel_nonce: &'a str,
}
struct PendingRole {
    role: Role,
    original: guest_delivery::PreparedRoleDelivery,
    bootstrap: image::Sealed,
    nonce: String,
}
struct StartedRole {
    original: guest_delivery::RoleDeliveryOriginals,
    bootstrap: image::Sealed,
}

// This guard also owns partial startup failures before a cohort can be returned
// to the native lifetime. Drop attempts exact reaping but grants no success.
struct LaunchChildren { processes: Vec<RoleProcess> }
impl Drop for LaunchChildren {
    fn drop(&mut self) {
        for process in &self.processes { process.stop(); }
        for process in &self.processes { let _ = process.stop_and_reap(); }
    }
}

pub struct StartedGuestCohort {
    association: Association,
    image: image::Image,
    roles: Vec<StartedRole>,
    children: Vec<RoleProcess>,
    inspector: Arc<InitializedGuestInspector>,
    public_artifacts: super::guest_public_artifacts::Owner,
    role_keys: Option<super::guest_role_provisioning::Owner>,
    deadline: u64,
}

impl StartedGuestCohort {
    /// Consumes the once-only inspector endpoint and launches one child per
    /// genuinely signed role. No root role-key read or caller readiness bit.
    pub fn launch(configuration: GuestCohortConfiguration, prepared: &Prepared,
        inspector: Arc<InitializedGuestInspector>)
        -> Result<Arc<Self>, String> {
        Self::launch_inner(configuration,None,prepared,inspector)
    }
    /// Explicit additive boot path. No missing-file detection or fallback
    /// silently promotes the old preprovisioned launch profile.
    pub fn launch_with_role_keys(configuration: GuestCohortConfiguration,
        provisioner: super::guest_role_provisioning::GuestRoleKeyProvisionerConfiguration,
        prepared:&Prepared,inspector:Arc<InitializedGuestInspector>) -> Result<Arc<Self>,String> {
        Self::launch_inner(configuration,Some(provisioner),prepared,inspector)
    }
    fn launch_inner(configuration:GuestCohortConfiguration,
        provisioner:Option<super::guest_role_provisioning::GuestRoleKeyProvisionerConfiguration>,
        prepared:&Prepared,inspector:Arc<InitializedGuestInspector>)->Result<Arc<Self>,String>{
        configuration.validate()?;
        prepared.check()?;
        inspector.require_preparation(prepared)?;
        if inspector.deadline_boottime_ns() != prepared.deadline() {
            return Err("guest cohort and inspector have different original lifetimes".into());
        }
        let association = Association::capture(prepared)?;
        let image = image::Image::open_guest_role(&configuration.executable.path, &configuration.executable.sha256)?;
        let mut pending = Vec::with_capacity(Role::ALL.len());
        let mut startup_deadline = prepared.deadline();
        let mut cohort_binding = None;
        for role in Role::ALL {
            let delivery = configuration.delivery(role)?;
            let original = guest_delivery::PreparedRoleDelivery::open(Path::new(&configuration.configuration.path),
                &configuration.configuration.sha256, role, Path::new(&delivery.path), &delivery.sha256)
                .map_err(|error| error.to_string())?;
            let scoped = original.scoped();
            if scoped.role != role || scoped.process.service_role != role
                || scoped.process.executable_sha256 != configuration.executable.sha256 {
                return Err("guest cohort fixed worker differs from signed role executable".into());
            }
            let binding = (scoped.generation_id.clone(), scoped.generation,
                scoped.trust_checkpoint_sha256.clone(), original.boot_id().to_owned());
            if cohort_binding.as_ref().is_some_and(|expected| expected != &binding) {
                return Err("guest cohort deliveries differ in generation, trust or boot".into());
            }
            cohort_binding = Some(binding);
            startup_deadline = startup_deadline.min(original.startup_deadline_boottime_ns().map_err(|e| e.to_string())?);
            let mut nonce = [0u8; 32];
            if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) } != nonce.len() as isize
                || nonce == [0; 32] { return Err("guest role channel nonce unavailable".into()); }
            let nonce = URL_SAFE_NO_PAD.encode(nonce);
            let raw = crate::canonical_json_bytes(&Bootstrap {
                api_version: "serverware.responseV2.guestRoleBootstrap/v1",
                configuration_path: &configuration.configuration.path,
                configuration_sha256: original.configuration_sha256(),
                delivery_path: &delivery.path, delivery_sha256: original.delivery_sha256(),
                service_role: role, gate_lifetime_deadline_boottime_ns: prepared.deadline().to_string(),
                channel_nonce: &nonce,
            }).map_err(|_| "guest role bootstrap encoding failed")?;
            pending.push(PendingRole { role, original, bootstrap: image::Sealed::new(&raw, false)?, nonce });
        }
        let router_delivery = configuration.delivery(Role::CustodyRouter)?;
        // Only public signed generation metadata is shared. Private state and
        // credential directories keep their existing exact 0700 boundaries.
        let originals: Vec<_> = pending.iter().map(|entry| &entry.original).collect();
        let role_keys=match provisioner {
            Some(configuration)=>Some(super::guest_role_provisioning::Owner::provision(configuration,prepared,&originals)?),
            None=>None,
        };
        let public_artifacts = super::guest_public_artifacts::Owner::prepare(prepared, &originals)
            .map_err(|e| e.to_string())?;
        drop(originals);
        let endpoint = inspector.take_router_endpoint()?;
        let inherited = endpoint.inheritance()?;
        inherited.require_delivery(Path::new(&configuration.configuration.path), &configuration.configuration.sha256,
            Path::new(&router_delivery.path), &router_delivery.sha256)?;
        if inherited.deadline_boottime_ns() != prepared.deadline() {
            return Err("guest router inherited endpoint lost its original deadline".into());
        }
        // The source owner creates the fresh bound listener exactly once. It
        // never treats existing paths as restart/recovery permission.
        let listener = PreparedGuestResponseV2Listener::prepare(Path::new(&configuration.configuration.path),
            Path::new(&router_delivery.path), &router_delivery.sha256).map_err(|e| e.to_string())?;
        let mut children = LaunchChildren { processes: Vec::with_capacity(Role::ALL.len()) };
        spawn_role(Role::StateAuthority, &pending, &mut children.processes, &image, prepared, &[])?;
        wait_for(&children.processes, &[Role::StateAuthority], false, prepared, &inspector, startup_deadline)?;
        for role in NONROUTER { spawn_role(role, &pending, &mut children.processes, &image, prepared, &[])?; }
        wait_for(&children.processes, &NONROUTER, false, prepared, &inspector, startup_deadline)?;
        inherited.check()?;
        let (socket, handoff) = listener.descriptors().map_err(|e| e.to_string())?;
        let router_fds = [socket, handoff, inherited.channel(), inherited.inspector_pidfd(), inherited.bootstrap()];
        spawn_role(Role::CustodyRouter, &pending, &mut children.processes, &image, prepared, &router_fds)?;
        // Child owns inherited copies. No parent pre-listen check after actual
        // router listen; no parent copy may keep an abandoned channel alive.
        drop(listener);
        drop(endpoint);
        wait_for(&children.processes, &Role::ALL, true, prepared, &inspector, startup_deadline)?;
        let mut roles = Vec::with_capacity(Role::ALL.len());
        for pending_role in pending {
            let process = children.processes.iter().find(|child| child.role() == pending_role.role)
                .ok_or("guest cohort lost an owned child")?;
            process.idle()?;
            let original = pending_role.original.into_lifetime().map_err(|e| e.to_string())?;
            roles.push(StartedRole { original, bootstrap: pending_role.bootstrap });
        }
        prepared.check()?;
        if kernel::now()? >= startup_deadline { return Err("guest cohort completion exceeded original startup admission".into()); }
        let result = Arc::new(Self { association, image, roles, inspector, public_artifacts, role_keys, deadline: prepared.deadline(),
            children: std::mem::take(&mut children.processes) });
        result.check()?;
        Ok(result)
    }
    pub fn deadline_boottime_ns(&self) -> u64 { self.deadline }
    pub fn require_serving(&self, owner: &Owner) -> Result<(), String> {
        self.association.require(owner)?;
        if let Some(keys)=&self.role_keys {keys.require_serving(owner)?;}
        self.inspector.require_serving(owner)?;
        self.check()
    }
    pub fn check(&self) -> Result<(), String> {
        if kernel::now()? >= self.deadline { return Err("guest cohort original serving lifetime expired".into()); }
        if let Some(keys)=&self.role_keys {keys.check()?;}
        self.inspector.check()?;
        self.image.check()?;
        self.public_artifacts.check().map_err(|e| e.to_string())?;
        for child in &self.children { child.idle()?; }
        for role in &self.roles {
            role.original.check().map_err(|e| e.to_string())?;
            role.bootstrap.check()?;
        }
        if kernel::now()? >= self.deadline { return Err("guest cohort lifetime ended during check".into()); }
        Ok(())
    }
    pub fn request_stop(&self) {
        for child in &self.children { child.stop(); }
    }
    pub fn stop_and_reap(&self) -> Result<(), String> {
        // Stop ALL before awaiting any one role. Reaping does not establish
        // generation recovery, path cleanup or permission for another start.
        self.request_stop();
        let mut failure = None;
        for child in &self.children {
            if let Err(error) = child.stop_and_reap() { failure.get_or_insert(error); }
        }
        match failure { Some(error) => Err(error), None => Ok(()) }
    }
}
impl Drop for StartedGuestCohort { fn drop(&mut self) { let _ = self.stop_and_reap(); } }

fn spawn_role(role: Role, pending: &[PendingRole], children: &mut Vec<RoleProcess>,
    image: &image::Image, prepared: &Prepared, router: &[BorrowedFd<'_>]) -> Result<(), String> {
    if children.iter().any(|child| child.role() == role) { return Err("guest role launch cannot be repeated".into()); }
    let entry = pending.iter().find(|entry| entry.role == role).ok_or("signed guest role preparation absent")?;
    entry.original.check().map_err(|e| e.to_string())?;
    image.check()?;
    let process = RoleProcess::spawn(&image.sealed, &entry.bootstrap, &entry.nonce,
        entry.original.scoped(), prepared, router)?;
    children.push(process);
    Ok(())
}
fn wait_for(children: &[RoleProcess], roles: &[Role], started: bool, prepared: &Prepared,
    inspector: &InitializedGuestInspector, startup_deadline: u64) -> Result<(), String> {
    loop {
        prepared.check()?;
        inspector.check()?;
        if kernel::now()? >= startup_deadline { return Err("guest cohort startup exceeded original signed admission".into()); }
        for child in children { child.observe_progress(startup_deadline)?; }
        if roles.iter().all(|role| children.iter().any(|child| child.role() == *role && child.reached(started))) {
            if kernel::now()? >= startup_deadline { return Err("guest cohort progress arrived outside original admission".into()); }
            return Ok(());
        }
        // Wait only on actual child progress/PIDFDs; no provider retry, file
        // absence inference, polling sleep protocol or renewed allowance.
        let mut descriptors = Vec::with_capacity(children.len() * 2);
        for child in children { child.poll_descriptors(&mut descriptors); }
        let sample = kernel::now()?;
        if sample >= startup_deadline { return Err("guest role progress wait expired".into()); }
        let timeout = ((startup_deadline - sample) / 1_000_000).clamp(1, 25) as i32;
        if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as libc::nfds_t, timeout) } < 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err("guest role progress wait failed".into());
        }
    }
}
