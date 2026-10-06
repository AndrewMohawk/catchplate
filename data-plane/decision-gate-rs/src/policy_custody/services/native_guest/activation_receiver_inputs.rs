//! One original-input completion for the held service-enclave connection.
//! The pipe/observation is acquisition only. Existing signed C9 and the
//! unchanged child service/key/NSM/journal admission confer all authority.
use super::*;
use crate::policy_shadow::policy_custody::services::guest;
use serverware_decision_gate::native_policy_activation_transport::ChannelVersion;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

const MAX_COMPLETION: usize = 1024;
const MAX_SERVICE: usize = 65536;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Completion { api_version: String, observation_sha256: Sha256Digest, launch_sha256: Sha256Digest }

// Exact existing service/v2 syntax, not a signature-verification result. The
// child still parses the same protected original and performs its full actual
// admission; this projection only prevents selecting another service/channel.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServicePayload {
    api_version: String, purpose: String, guest: GuestClosureBinding,
    assignment_payload_sha256: Sha256Digest, key_authorization_sha256: Sha256Digest,
    authority: Pin, initial_state_sha256: Sha256Digest, generation_id: Sha256Digest,
    generation_publication_envelope_sha256: Sha256Digest, trust_checkpoint_id: Sha256Digest,
    revocation_generation: u64, revocation_root_sha256: Sha256Digest,
    issued_at_unix_nanos: i64, expires_at_unix_nanos: i64,
    signing_key_id: Sha256Digest, signing_key_spki_sha256: Sha256Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceOriginal { payload: ServicePayload, signature: CanonicalEd25519Signature }

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }
fn identity(fd: BorrowedFd<'_>) -> Result<Identity, ShadowError> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstat(fd.as_raw_fd(), &mut s) } == 0)?;
    Ok(Identity { device: s.st_dev, inode: s.st_ino, mode: s.st_mode, uid: s.st_uid, gid: s.st_gid })
}

struct Input { fd: OwnedFd, identity: Identity, flags: i32 }
impl Input {
    fn open() -> Result<Self, ShadowError> {
        let fd = retrieval_peer::duplicate(unsafe { BorrowedFd::borrow_raw(0) })?;
        let original = identity(fd.as_fd())?;
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        require(original.mode & libc::S_IFMT == libc::S_IFIFO && flags >= 0
            && flags & (libc::O_PATH | libc::O_ACCMODE) == libc::O_RDONLY
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0)?;
        let value = Self { fd, identity: original, flags: flags | libc::O_NONBLOCK };
        value.check()?; Ok(value)
    }
    fn check(&self) -> Result<(), ShadowError> {
        require(identity(self.fd.as_fd())? == self.identity
            && identity(unsafe { BorrowedFd::borrow_raw(0) })? == self.identity
            && unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) } == self.flags
            && unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFD) } == libc::FD_CLOEXEC)
    }
    fn read(&self, cold: &super::activation_receiver::Cold, out: &mut [u8]) -> Result<usize, ShadowError> {
        loop {
            cold.check()?; self.check()?;
            let n = unsafe { libc::read(self.fd.as_raw_fd(), out.as_mut_ptr().cast(), out.len()) };
            let error = if n < 0 { std::io::Error::last_os_error().raw_os_error() } else { None };
            cold.check()?; self.check()?;
            if n >= 0 { return Ok(n as usize); }
            require(matches!(error, Some(libc::EAGAIN) | Some(libc::EINTR)))?;
            // Preauthority waiting is cancellable but has no invented startup
            // window. The signed C9 interval is enforced after its acquisition.
            let mut p = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let status = unsafe { libc::poll(&mut p, 1, 100) };
            require(status >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR))?;
            require(p.revents & (libc::POLLERR | libc::POLLNVAL) == 0)?;
        }
    }
    fn exact(&self, cold: &super::activation_receiver::Cold, out: &mut [u8]) -> Result<(), ShadowError> {
        let mut used = 0;
        while used < out.len() { let n = self.read(cold, &mut out[used..])?; require(n > 0)?; used += n; }
        Ok(())
    }
    fn completion(&self, cold: &super::activation_receiver::Cold) -> Result<Completion, ShadowError> {
        let mut header = [0u8; 4]; self.exact(cold, &mut header)?;
        let length = u32::from_be_bytes(header) as usize;
        require(length > 0 && length <= MAX_COMPLETION)?;
        let mut raw = vec![0u8; length]; self.exact(cold, &mut raw)?;
        require(self.read(cold, &mut [0u8; 1])? == 0)?;
        exact(&raw)
    }
}

pub(super) struct Completed {
    pub(super) launch: Original,
    pub(super) launch_bytes: Vec<u8>,
    pub(super) files: guest::FileAdmission,
    pub(super) activation: BTreeMap<String, OwnedFd>,
    pub(super) service_original: Original,
}
impl Completed {
    pub(super) fn receive(cold: &super::activation_receiver::Cold, observation_sha: &Sha256Digest,
        channel: OwnedFd, journal: OwnedFd) -> Result<Self, ShadowError> {
        cold.check()?;
        let completion = Input::open()?.completion(cold)?;
        require(completion.api_version == "serverware.nativeShadowActivationReceiverCompletion/v1"
            && completion.observation_sha256 == *observation_sha)?;
        let launch = Original::native_launch().map_err(fail)?;
        let launch_bytes = launch.read(32768).map_err(fail)?.to_vec();
        require(Sha256Digest::compute(&launch_bytes) == completion.launch_sha256)?;
        let (selected, service) = selection(&launch_bytes)?;
        let service_pin = match service { SelectedService::Activation(pin) => pin,
            _ => return Err(ShadowError::BindingDrift) };
        require(selected.delivery_configuration.path == cold.delivery_configuration().path
            && selected.delivery_configuration.sha256 == cold.delivery_configuration().sha256)?;
        let files = guest::admit_files(&selected.delivery_configuration.path, selected.delivery_configuration.sha256,
            &selected.delivery.path, selected.delivery.sha256).map_err(fail)?;
        cold.require_delivery(&files.payload)?;
        require(files.payload.service_role == guest::Role::ProductionBridge && files.payload.activation.len() == 2)?;
        let mut activation = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for (index, (name, descriptor, kind)) in [("activation-channel", channel, libc::S_IFSOCK),
            ("activation-journal", journal, libc::S_IFDIR)].into_iter().enumerate() {
            let actual = identity(descriptor.as_fd())?;
            let entry = &files.payload.activation[index];
            require(entry.name == name && entry.fd == 6 + index as i32 && actual.mode & libc::S_IFMT == kind
                && actual == Identity { device: entry.device, inode: entry.inode, mode: entry.mode, uid: entry.uid, gid: entry.gid }
                && identities.insert((actual.device, actual.inode)))?;
            if index == 0 { ChannelVersion::VsockV2.validate(descriptor.as_fd()).map_err(fail)?; }
            activation.insert(name.to_string(), descriptor);
        }
        files.check_preparation().map_err(fail)?;
        let service_original = service_pin.open(MAX_SERVICE)?;
        let service: ServiceOriginal = exact(&service_original.read(MAX_SERVICE).map_err(fail)?)?;
        let p = &files.payload;
        let binding = GuestClosureBinding { configuration_sha256: p.configuration_sha256.clone(),
            delivery_sha256: files.delivery_sha256.clone(), runtime_configuration_sha256: p.runtime_config.sha256.clone(),
            service_role: "production-bridge".into(), uid: p.uid, gid: p.gid,
            boot_id_base64url: p.boot_id_base64url.clone(), time_namespace_device: p.time_namespace_device,
            time_namespace_inode: p.time_namespace_inode, issued_at_boottime_ns: p.issued_at_boottime_ns.clone(),
            startup_deadline_boottime_ns: p.startup_deadline_boottime_ns.clone(),
            lifetime_deadline_boottime_ns: p.lifetime_deadline_boottime_ns.clone(), invocation_id: p.invocation_id.clone() };
        require(service.payload.api_version == "serverware.nativeShadowActivationServiceAssignment/v2"
            && service.payload.purpose == "native-policy-activation-publication" && service.payload.guest == binding)?;
        service.signature.decode()?;
        cold.require_delivery(&files.payload)?; files.check_preparation().map_err(fail)?;
        require(launch.read(32768).map_err(fail)?.as_slice() == launch_bytes.as_slice())?;
        service_original.check().map_err(fail)?;
        Ok(Self { launch, launch_bytes, files, activation, service_original })
    }
}
