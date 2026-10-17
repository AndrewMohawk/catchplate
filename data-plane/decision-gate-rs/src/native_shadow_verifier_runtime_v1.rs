//! External verifier runtime/root custody only: no claimant NSM, keys or exec.
pub(crate) mod originals;
mod mounts;
mod time_issuer;
mod origin_issuer;
pub(crate) mod setup_issuer;
#[path = "native_verifier/json.rs"]
mod json;
use crate::native_response_profile_v1::canonical_ascii_bytes;
use crate::native_secret_broker_v1::{image::{Image, Purpose}, ImageConfiguration};
use originals::{Origin, Original};
use serde::Deserialize;
use serde_json::Value;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use sha2::{Digest, Sha256};

pub(crate) const IMAGE_PATH: &str = "/opt/catchplate/native-shadow-verifier-runtime.squashfs";
pub(crate) const INTERPRETER_PATH: &str = "/usr/local/bin/python3.11";
pub(crate) const ENTRYPOINT_PATH: &str = "/opt/catchplate/scripts/verify_native_shadow_custody.py";
pub(crate) const TIME_IMAGE_PATH: &str = "/opt/catchplate/native-shadow-time-issuer-runtime.squashfs";
pub(crate) const TIME_ENTRYPOINT_PATH: &str = "/opt/catchplate/scripts/issue_native_shadow_guest_time.py";
pub(crate) const ORIGIN_IMAGE_PATH: &str = "/opt/catchplate/native-generation-origin-issuer-runtime.squashfs";
pub(crate) const ORIGIN_ENTRYPOINT_PATH: &str = "/opt/catchplate/scripts/issue_native_generation_origin.py";
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Profile { Verifier, TimeIssuer, OriginIssuer, Setup(setup_issuer::Role) }
impl Profile {
    fn configuration_path(self) -> &'static str {
        match self { Self::Verifier => "/etc/catchplate/native-shadow-nitro-verifier.json",
            Self::TimeIssuer => "/etc/catchplate/native-shadow-guest-time-issuer.json",
            Self::OriginIssuer => "/etc/catchplate/native-generation-origin-issuer.json",
            Self::Setup(role) => role.configuration_path() }
    }
    pub(crate) fn entrypoint(self) -> &'static str {
        match self { Self::Verifier => ENTRYPOINT_PATH, Self::TimeIssuer => TIME_ENTRYPOINT_PATH,
            Self::OriginIssuer => ORIGIN_ENTRYPOINT_PATH, Self::Setup(role) => role.entrypoint() }
    }
    fn image_purpose(self) -> Purpose {
        match self { Self::Verifier => Purpose::ExternalShadowVerifier, Self::TimeIssuer => Purpose::ExternalShadowTimeIssuer,
            Self::OriginIssuer => Purpose::ExternalGenerationOriginIssuer,
            Self::Setup(role) => role.image_purpose() }
    }
}
fn ensure(value: bool, message: &str) -> Result<(), String> { if value { Ok(()) } else { Err(message.to_owned()) } }
fn digest(value: &str) -> Result<(), String> {
    ensure(value.len() == 71 && value.starts_with("sha256:") && value[7..].bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) && value[7..] != "0".repeat(64), "verifier pin is not canonical nonzero SHA256")
}
fn hash(bytes: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(bytes))) }
fn now() -> Result<u64, String> {
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } == 0 && clock.tv_sec >= 0
        && (0..1_000_000_000).contains(&clock.tv_nsec), "verifier original BOOTTIME unavailable")?;
    (clock.tv_sec as u64).checked_mul(1_000_000_000).and_then(|value| value.checked_add(clock.tv_nsec as u64))
        .ok_or_else(|| "verifier BOOTTIME overflow".to_owned())
}
fn within(issued: u64, deadline: u64) -> Result<(), String> {
    let observed = now()?;
    ensure(issued <= observed && observed < deadline, "verifier original operation allowance is over")
}
fn decimal(value: &str) -> Result<u64, String> {
    ensure(!value.is_empty() && value.len() <= 20 && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit()),
        "verifier deadline is not original positive decimal")?;
    value.parse().map_err(|_| "verifier deadline overflow".to_owned())
}
fn document(raw: &[u8], maximum: usize) -> Result<Value, String> {
    let value = json::parse(raw, maximum)?;
    ensure(canonical_ascii_bytes(&value)? == raw, "verifier configuration is not original canonical ASCII")?;
    Ok(value)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeImage {
    profile: String, image_path: String, image_sha256: String,
    interpreter_sha256: String, entrypoint_sha256: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Launch { api_version: String, runtime_image: RuntimeImage, verifier_configuration_sha256: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    boot_id_base64url: String, time_namespace_device: u64, time_namespace_inode: u64,
    issued_at_boottime_ns: String, deadline_boottime_ns: String,
}
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) enum ResultPurpose { Production, KeyAdmission, BridgeAdmission }
struct Policy { uid: u32, gid: u32, issued: u64, deadline: u64, purpose:Option<ResultPurpose>, profile:Profile }
fn policy(value: &Value, origin: &Origin) -> Result<Policy, String> {
    let fields = value.as_object().ok_or("verifier policy is not an object")?;
    let (purpose,scope,expected):(_,_,&[&str])=match value["apiVersion"].as_str() {
        Some("catchplate.nativeShadowNitroVerifierConfiguration/v1")=>(ResultPurpose::Production,"expectedStatement",
            &["apiVersion","uid","gid","operation","authorization","expectedStatement","authorityKeys",
                "trustCheckpoint","nitro","collateralRevocation","expectedAttestation","maximumResultAgeNanos"]),
        Some("catchplate.nativeShadowNitroVerifierConfiguration/v2")=>(ResultPurpose::KeyAdmission,"expectedScope",
            &["apiVersion","uid","gid","operation","authorization","expectedScope","authorityKeys",
                "trustCheckpoint","nitro","collateralRevocation","expectedAttestation","maximumResultAgeNanos","admissionAuthorization"]),
        Some("catchplate.nativeShadowNitroVerifierConfiguration/v3")=>(ResultPurpose::BridgeAdmission,"expectedScope",
            &["apiVersion","uid","gid","operation","authorization","expectedScope","authorityKeys",
                "trustCheckpoint","nitro","collateralRevocation","expectedAttestation","maximumResultAgeNanos","admissionAuthorization"]),
        _=>return Err("verifier original policy purpose differs".into()),
    };
    ensure(fields.len()==expected.len() && expected.iter().all(|name|fields.contains_key(*name)),"verifier original policy shape differs")?;
    let uid = value["uid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("verifier UID invalid")?;
    let gid = value["gid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("verifier GID invalid")?;
    ensure([uid,gid].iter().all(|value| *value > 0 && *value < u32::MAX
        && ![64988,64989,64990,65534].contains(value))
        && value[scope]["guest"]["uid"].as_u64().is_some_and(|id| id != uid as u64)
        && value[scope]["guest"]["gid"].as_u64().is_some_and(|id| id != gid as u64),
        "verifier final identity aliases a claimant/reserved identity")?;
    let op: Operation = serde_json::from_value(value["operation"].clone()).map_err(|_| "verifier operation original is not closed")?;
    ensure(op.boot_id_base64url == origin.boot && origin.time_identity()? == (op.time_namespace_device, op.time_namespace_inode)
        && op.time_namespace_device > 0 && op.time_namespace_inode > 0, "verifier external boot/time namespace differs")?;
    let issued = decimal(&op.issued_at_boottime_ns)?; let deadline = decimal(&op.deadline_boottime_ns)?;
    ensure(deadline.checked_sub(issued).is_some_and(|window| window > 0 && window <= 30_000_000_000),
        "verifier original operation interval differs")?;
    Ok(Policy { uid, gid, issued, deadline, purpose:Some(purpose), profile:Profile::Verifier })
}

enum Phase { Prepared, Exported, Reaped }
pub(crate) struct PreparedRuntime {
    // Drop mounts before backing image or restoring the original namespace.
    mounts: mounts::Mounts, image: Image, launch: Original, configuration: Original,
    origin: Origin, policy: Policy, phase: Phase, namespace: mounts::Namespace,
}
/// Retain actual public launch originals before any image/mount work. The
/// one-shot supervisor arms its kernel watchdog from this SAME admission.
pub(crate) struct RuntimeAdmission {
    launch: Original, configuration: Original, origin: Origin, policy: Policy,
    image_config: ImageConfiguration,
}
impl RuntimeAdmission {
    pub(crate) fn open_setup(role: setup_issuer::Role) -> Result<Self, String> { setup_issuer::open(role) }
    pub(crate) fn open_time_issuer() -> Result<Self, String> { time_issuer::open() }
    pub(crate) fn open_origin_issuer() -> Result<Self, String> { origin_issuer::open() }
    pub(crate) fn open() -> Result<Self, String> {
        let origin = Origin::capture()?;
        let launch = Original::open("native-shadow-verifier-launch.json", 16384)?;
        let selected: Launch = serde_json::from_value(document(&launch.bytes, 16384)?).map_err(|_| "verifier launch is not closed")?;
        ensure(selected.api_version == "catchplate.nativeShadowVerifierLaunch/v1"
            && selected.runtime_image.profile == "sealed-memfd-squashfs-v1"
            && selected.runtime_image.image_path == IMAGE_PATH, "verifier image purpose selection differs")?;
        for pin in [&selected.verifier_configuration_sha256, &selected.runtime_image.image_sha256,
            &selected.runtime_image.interpreter_sha256, &selected.runtime_image.entrypoint_sha256] { digest(pin)?; }
        let configuration = Original::open("native-shadow-nitro-verifier.json", 512 * 1024)?;
        ensure(hash(&configuration.bytes) == selected.verifier_configuration_sha256,
            "verifier launch does not pin its actual protected policy")?;
        let policy = policy(&document(&configuration.bytes, 512 * 1024)?, &origin)?;
        within(policy.issued, policy.deadline)?;
        // Internal image custody adapter only; no old broker wire/profile is
        // accepted as an external verifier launch, and no NSM/KMS owner exists.
        let image_config = ImageConfiguration { profile: selected.runtime_image.profile,
            image_path: selected.runtime_image.image_path, image_sha256: selected.runtime_image.image_sha256,
            interpreter_sha256: selected.runtime_image.interpreter_sha256, helper_sha256: selected.runtime_image.entrypoint_sha256 };
        let owner = Self { launch, configuration, origin, policy, image_config };
        owner.check()?; Ok(owner)
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        self.origin.check()?; self.launch.check()?; self.configuration.check()?;
        within(self.policy.issued, self.policy.deadline)
    }
    pub(crate) fn uid(&self) -> u32 { self.policy.uid }
    pub(crate) fn gid(&self) -> u32 { self.policy.gid }
    pub(crate) fn issued_boottime_ns(&self) -> u64 { self.policy.issued }
    pub(crate) fn deadline_boottime_ns(&self) -> u64 { self.policy.deadline }
    pub(crate) fn profile(&self) -> Profile { self.policy.profile }
    pub(crate) fn time_transport(&self) -> Result<(String, u16, String), String> {
        self.check()?;
        ensure(self.policy.profile == Profile::TimeIssuer, "time transport requires its actual issuer admission")?;
        time_issuer::transport(&document(&self.configuration.bytes, 512 * 1024)?)
    }
    pub(crate) fn origin_transport(&self) -> Result<(String, u16, String), String> {
        self.check()?;
        ensure(self.policy.profile == Profile::OriginIssuer, "origin transport requires its actual issuer admission")?;
        // Only the closed IP tuple grammar is shared, never time authority.
        time_issuer::transport(&document(&self.configuration.bytes, 512 * 1024)?)
    }
    /// Public consistency pins from the SAME retained originals, not a new
    /// policy/deadline admission or a caller-selected transport authority.
    pub(crate) fn public_transport_pins(&self) -> Result<(String, String), String> {
        self.check()?;
        let pins = (hash(&self.launch.bytes), hash(&self.configuration.bytes));
        self.check()?;
        Ok(pins)
    }
    pub(crate) fn result_purpose(&self)->Result<ResultPurpose,String> {
        self.check()?;
        self.policy.purpose.ok_or_else(||"issuer admission has no verifier result purpose".into())
    }
    pub(crate) fn evidence_api(&self)->Result<&'static str,String> {
        Ok(match self.result_purpose()? {
            ResultPurpose::Production=>"catchplate.nativeShadowRoleKeyEvidence/v1",
            ResultPurpose::KeyAdmission=>"catchplate.nativeShadowKeyAdmissionEvidence/v1",
            ResultPurpose::BridgeAdmission=>"catchplate.nativeShadowBridgeAdmissionEvidence/v1",
        })
    }
    pub(crate) fn prepare(self) -> Result<PreparedRuntime, String> {
        self.check()?;
        let Self { launch, configuration, origin, policy, image_config } = self;
        let namespace = mounts::Namespace::enter()?;
        let image = Image::open_for(&image_config, policy.deadline, policy.profile.image_purpose())?;
        origin.check()?; within(policy.issued, policy.deadline)?;
        let mounts = mounts::Mounts::install(&image, &configuration, policy.issued, policy.deadline, policy.profile)?;
        let owner = PreparedRuntime { mounts, image, launch, configuration, origin, policy, phase: Phase::Prepared, namespace };
        owner.check()?; Ok(owner)
    }
}
impl PreparedRuntime {
    pub(crate) fn check(&self) -> Result<(), String> {
        self.origin.check()?; self.namespace.check()?; self.launch.check()?; self.configuration.check()?;
        within(self.policy.issued, self.policy.deadline)?;
        ensure(!matches!(self.phase, Phase::Reaped), "verifier operation was already reaped")?;
        self.image.check(self.policy.deadline)?; self.mounts.check(&self.image, &self.configuration)?;
        within(self.policy.issued, self.policy.deadline)
    }
    pub(crate) fn inheritance(&mut self) -> Result<RuntimeBorrow<'_>, String> {
        self.check()?;
        ensure(matches!(self.phase, Phase::Prepared), "verifier root inheritance is once-only")?;
        self.phase = Phase::Exported;
        // From here only actual kernel child reap may authorize detachment.
        self.mounts.automatic = false; self.namespace.automatic = false;
        Ok(RuntimeBorrow { runtime: self })
    }
    pub(crate) fn bind_child(mut self, child: OwnedFd, pid: libc::pid_t) -> Result<RunningRuntime, BindFailure> {
        // Even a failed constructor retains the supplied actual child owner;
        // failure can never become implicit permission to detach a live root.
        self.mounts.automatic = false; self.namespace.automatic = false;
        let mut owner = RunningRuntime { runtime: self, child, pid, joined: None, reaped: None };
        match owner.join().and_then(|_| owner.check()) {
            Ok(()) => Ok(owner), Err(error) => Err(BindFailure { owner, error }),
        }
    }
}
pub(crate) struct RuntimeBorrow<'a> { runtime: &'a PreparedRuntime }
impl RuntimeBorrow<'_> {
    pub(crate) fn profile(&self) -> Profile { self.runtime.policy.profile }
    pub(crate) fn root(&self) -> BorrowedFd<'_> { self.runtime.image.root.as_fd() }
    pub(crate) fn interpreter(&self) -> BorrowedFd<'_> { self.runtime.image.interpreter.as_fd() }
    pub(crate) fn configuration(&self) -> BorrowedFd<'_> { self.runtime.configuration.file.as_fd() }
    pub(crate) fn uid(&self) -> u32 { self.runtime.policy.uid }
    pub(crate) fn gid(&self) -> u32 { self.runtime.policy.gid }
    pub(crate) fn issued_boottime_ns(&self) -> u64 { self.runtime.policy.issued }
    pub(crate) fn deadline_boottime_ns(&self) -> u64 { self.runtime.policy.deadline }
}
struct ChildJoin { identity: originals::Identity, start: u64 }
pub(crate) struct RunningRuntime {
    runtime: PreparedRuntime, child: OwnedFd, pid: libc::pid_t, joined: Option<ChildJoin>, reaped: Option<Retired>,
}
pub(crate) struct BindFailure { owner: RunningRuntime, error: String }
impl BindFailure {
    pub(crate) fn error(&self) -> &str { &self.error }
    /// Retains custody only; no successful admission or executable handoff.
    pub(crate) fn into_cleanup(self) -> RunningRuntime { self.owner }
}
pub(crate) struct RetireFailure { owner: RunningRuntime, error: String }
impl RetireFailure {
    pub(crate) fn error(&self) -> &str { &self.error }
    pub(crate) fn into_cleanup(self) -> RunningRuntime { self.owner }
}
pub(crate) struct Retired { code: i32, status: i32 }
impl Retired {
    pub(crate) fn code(&self) -> i32 { self.code }
    pub(crate) fn status(&self) -> i32 { self.status }
}
impl RunningRuntime {
    fn wait(&self, peek: bool) -> Result<libc::siginfo_t, String> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        ensure(unsafe { libc::waitid(libc::P_PIDFD, self.child.as_raw_fd() as libc::id_t, &mut info,
            libc::WEXITED | libc::WNOHANG | if peek { libc::WNOWAIT } else { 0 }) } == 0,
            "verifier child ownership/exit wait failed")?;
        let pid = unsafe { info.si_pid() };
        ensure(pid == 0 || pid == self.pid && info.si_signo == libc::SIGCHLD
            && [libc::CLD_EXITED,libc::CLD_KILLED,libc::CLD_DUMPED].contains(&info.si_code),
            "verifier kernel child exit identity differs")?;
        Ok(info)
    }
    fn join(&mut self) -> Result<(), String> {
        self.runtime.origin.check()?; self.runtime.namespace.check()?;
        ensure(matches!(self.runtime.phase, Phase::Exported) && self.pid > 1 && self.pid != self.runtime.origin.pid,
            "verifier child did not inherit the actual preparation")?;
        originals::pidfd(self.child.as_raw_fd(), self.pid)?;
        ensure(unsafe { libc::fcntl(self.child.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC,
            "verifier child PIDFD is not retained close-on-exec")?;
        let before = originals::identity(self.child.as_raw_fd())?;
        let (parent, start) = originals::process(self.pid)?;
        ensure(parent == self.runtime.origin.pid && start > 0, "verifier clone's actual parent/start relation differs")?;
        self.wait(true)?;
        ensure(originals::identity(self.child.as_raw_fd())? == before && originals::process(self.pid)? == (parent,start),
            "verifier child changed during binding")?;
        if let Some(joined) = &self.joined {
            ensure(joined.identity == before && joined.start == start, "verifier original child binding changed")?;
        } else { self.joined = Some(ChildJoin { identity: before, start }); }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        self.runtime.check()?;
        let joined = self.joined.as_ref().ok_or("verifier child has no actual kernel join")?;
        ensure(self.reaped.is_none() && originals::identity(self.child.as_raw_fd())? == joined.identity
            && originals::process(self.pid)? == (self.runtime.origin.pid, joined.start), "verifier actual child identity changed")?;
        originals::pidfd(self.child.as_raw_fd(), self.pid)?;
        ensure(unsafe { self.wait(true)?.si_pid() } == 0, "verifier child has already exited")
    }
    /// Output eligibility only while the original interval is still live.
    /// Unlike retire, this verifies every runtime original after a real exit.
    pub(crate) fn check_after_exit(&self) -> Result<(), String> {
        self.runtime.check()?;
        let joined = self.joined.as_ref().ok_or("verifier child has no actual kernel join")?;
        ensure(self.reaped.is_none() && originals::identity(self.child.as_raw_fd())? == joined.identity
            && originals::process(self.pid)? == (self.runtime.origin.pid, joined.start),
            "verifier terminal child identity changed")?;
        originals::pidfd(self.child.as_raw_fd(), self.pid)?;
        ensure(unsafe { self.wait(true)?.si_pid() } == self.pid, "verifier child has no genuine terminal evidence")?;
        ensure(originals::identity(self.child.as_raw_fd())? == joined.identity
            && originals::process(self.pid)? == (self.runtime.origin.pid, joined.start),
            "verifier terminal PIDFD/start identity changed during checking")?;
        self.runtime.origin.check()?; self.runtime.namespace.check()?;
        within(self.runtime.policy.issued, self.runtime.policy.deadline)
    }
    /// Borrow the actual retained clone PIDFD for the future supervisor's
    /// bounded stop/poll operation. This does not assert admission or liveness.
    pub(crate) fn child_pidfd(&self) -> BorrowedFd<'_> { self.child.as_fd() }
    pub(crate) fn retire(mut self) -> Result<Retired, RetireFailure> {
        let result = (|| {
            self.runtime.origin.check()?; self.runtime.namespace.check()?;
            if self.reaped.is_none() {
                self.join()?;
                let terminal = self.wait(true)?;
                ensure(unsafe { terminal.si_pid() } == self.pid, "verifier child is not actually exited; no timeout substitute")?;
                let reaped = self.wait(false)?;
                ensure(unsafe { reaped.si_pid() } == self.pid && reaped.si_code == terminal.si_code
                    && unsafe { reaped.si_status() } == unsafe { terminal.si_status() }, "verifier exact PIDFD reap differs")?;
                self.reaped = Some(Retired { code: reaped.si_code, status: unsafe { reaped.si_status() } });
                self.runtime.phase = Phase::Reaped;
            }
            // Cleanup has no new service interval and performs no new key or
            // verification operation. Every retry still owns the same reap.
            self.runtime.mounts.retire()?; self.runtime.namespace.restore()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(self.reaped.take().unwrap()), Err(error) => Err(RetireFailure { owner: self, error }),
        }
    }
}
// Once descriptors are exported, Drop deliberately cannot infer child death.
// Mounts/namespace automatic cleanup was disabled at the actual handoff. The
// fixed supervisor must retain this owner through stop and explicit PIDFD reap.
