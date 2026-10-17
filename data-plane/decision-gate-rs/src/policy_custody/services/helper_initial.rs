//! Explicit fresh-helper initialization. These records describe actual new
//! journal writes, never recovered effects, parent proofs or prior receipts.
use super::*;
use super::common::AuthenticatedInheritedSeqpacket;
use super::super::protocol::{ProtocolBoottimeDeadline, require_nonzero_digest};
use crate::policy_shadow::hash_domain_frames;

pub(super) const RUNTIME: &str = "catchplate.policyCustodyServiceRuntimeConfig/v9";
pub(super) const API: &str = "catchplate.policyCustodyCleanupHelperInitialBootstrap/v1";
const SEAL_API: &str = "catchplate.policyCustodyCleanupHelperInitialSeal/v1";
pub(super) const ROLES: [PolicyCustodyEndpointRole; 4] = [
    PolicyCustodyEndpointRole::SettlementStore, PolicyCustodyEndpointRole::FenceAuthority,
    PolicyCustodyEndpointRole::CgroupExecutor, PolicyCustodyEndpointRole::TerminationLedger,
];
pub(super) type Histories = BTreeMap<PolicyCustodyEndpointRole, String>;
pub(super) type HistoryPins = BTreeMap<PolicyCustodyEndpointRole, Sha256Digest>;

fn require(value: bool) -> Result<(), ServiceError> {
    if value { Ok(()) } else { Err(ServiceError::Invalid("initial helper bootstrap refused")) }
}
pub(super) fn history_pins(histories: &Histories) -> Result<HistoryPins, ServiceError> {
    require(histories.keys().copied().collect::<Vec<_>>() == ROLES)?;
    histories.iter().map(|(role, raw)| {
        require(!raw.is_empty() && raw.is_ascii() && raw.len() <= 1024 * 1024)?;
        Ok((*role, Sha256Digest::compute(raw.as_bytes())))
    }).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) api_version: String,
    pub(super) initialization: String,
    pub(super) operation_generation: u64,
    pub(super) shared_configuration_sha256: Sha256Digest,
    pub(super) service_configuration_sha256: Sha256Digest,
    pub(super) initial_endpoint_history_sha256: HistoryPins,
    pub(super) deadline: ProtocolBoottimeDeadline,
    pub(super) manifest_sha256: Sha256Digest,
}
impl Manifest {
    fn expected_digest(&self) -> Result<Sha256Digest, ServiceError> {
        let raw = encode_canonical_frame(&(&self.api_version, &self.initialization,
            self.operation_generation, &self.shared_configuration_sha256,
            &self.service_configuration_sha256, &self.initial_endpoint_history_sha256, &self.deadline))?;
        require(raw.len() <= 32768)?;
        Ok(hash_domain_frames(API.as_bytes(), &[&raw]))
    }
    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        require(self.api_version == API && self.initialization == "fresh-helper"
            && self.operation_generation > 0
            && self.initial_endpoint_history_sha256.keys().copied().collect::<Vec<_>>() == ROLES)?;
        for pin in self.initial_endpoint_history_sha256.values().chain([
            &self.shared_configuration_sha256, &self.service_configuration_sha256, &self.manifest_sha256]) {
            require_nonzero_digest("initialHelper.pin", pin)?;
        }
        self.deadline.to_runtime()?;
        require(self.manifest_sha256 == self.expected_digest()?)
    }
    pub(super) fn require_live(&self) -> Result<(), ServiceError> {
        self.validate()?;
        self.deadline.to_runtime()?.require_live().map_err(|_| ServiceError::Invalid("initial helper deadline expired"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Seal {
    api_version: String,
    manifest_sha256: Sha256Digest,
    authorized_endpoint_roles: Vec<PolicyCustodyEndpointRole>,
    journal_head_before_seal_sha256: Sha256Digest,
    seal_sha256: Sha256Digest,
}
impl Seal {
    fn digest(&self) -> Result<Sha256Digest, ServiceError> {
        let raw = encode_canonical_frame(&(&self.api_version, &self.manifest_sha256,
            &self.authorized_endpoint_roles, &self.journal_head_before_seal_sha256))?;
        Ok(hash_domain_frames(SEAL_API.as_bytes(), &[&raw]))
    }
    fn new(manifest: &Manifest, head: Sha256Digest) -> Result<Self, ServiceError> {
        let mut value = Self { api_version: SEAL_API.to_owned(), manifest_sha256: manifest.manifest_sha256.clone(),
            authorized_endpoint_roles: ROLES.to_vec(), journal_head_before_seal_sha256: head,
            seal_sha256: Sha256Digest::compute(&[]) };
        value.seal_sha256 = value.digest()?;
        value.validate(manifest)?;
        Ok(value)
    }
    fn validate(&self, manifest: &Manifest) -> Result<(), ServiceError> {
        manifest.require_live()?;
        require_nonzero_digest("initialHelper.journalHead", &self.journal_head_before_seal_sha256)?;
        require(self.api_version == SEAL_API && self.manifest_sha256 == manifest.manifest_sha256
            && self.authorized_endpoint_roles == ROLES && self.seal_sha256 == self.digest()?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="bootstrapOperation", content="body", rename_all="kebab-case", deny_unknown_fields)]
pub(super) enum Request {
    InstallInitial { manifest: Manifest },
    SealInitial { manifest_sha256: Sha256Digest },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="bootstrapOutcome", content="body", rename_all="kebab-case", deny_unknown_fields)]
pub(super) enum Reply {
    InitialInstalled { manifest_sha256: Sha256Digest },
    InitialSealed { seal: Seal },
}

pub(super) struct Receiver {
    operation: u64, shared: Sha256Digest, runtime: Sha256Digest, histories: HistoryPins,
    deadline: ProtocolBoottimeDeadline,
    manifest: Option<Manifest>, seal: Option<Seal>,
}
impl Receiver {
    pub(super) fn new(runtime: Sha256Digest, header: &RuntimeConfigHeaderV3, histories: &Histories,
        deadline: ProtocolBoottimeDeadline) -> Result<Self, ServiceError> {
        require(header.api_version == RUNTIME)?;
        Ok(Self { operation: header.operation_generation, shared: header.shared_configuration_sha256.clone(),
            runtime, histories: history_pins(histories)?, deadline, manifest: None, seal: None })
    }
    pub(super) fn prepare(&self, request: &Request, head: Option<Sha256Digest>) -> Result<Reply, ServiceError> {
        require(self.seal.is_none())?;
        match request {
            Request::InstallInitial { manifest } => {
                manifest.require_live()?;
                require(self.manifest.is_none() && head.is_none()
                    && manifest.operation_generation == self.operation && manifest.shared_configuration_sha256 == self.shared
                    && manifest.service_configuration_sha256 == self.runtime
                    && manifest.initial_endpoint_history_sha256 == self.histories
                    && manifest.deadline.domain() == self.deadline.domain()
                    && manifest.deadline.absolute_boottime_nanos() <= self.deadline.absolute_boottime_nanos())?;
                Ok(Reply::InitialInstalled { manifest_sha256: manifest.manifest_sha256.clone() })
            }
            Request::SealInitial { manifest_sha256 } => {
                let manifest = self.manifest.as_ref().ok_or(ServiceError::Invalid("initial helper manifest absent"))?;
                require(manifest_sha256 == &manifest.manifest_sha256)?;
                Ok(Reply::InitialSealed { seal: Seal::new(manifest,
                    head.ok_or(ServiceError::Invalid("initial helper durable installation head absent"))?)? })
            }
        }
    }
    // Called only after the exact request/reply has completed its durable append.
    pub(super) fn committed(&mut self, request: Request, reply: Reply) -> Result<(), ServiceError> {
        match (request, reply) {
            (Request::InstallInitial { manifest }, Reply::InitialInstalled { manifest_sha256 }) => {
                manifest.require_live()?;
                require(self.manifest.is_none() && self.seal.is_none() && manifest.manifest_sha256 == manifest_sha256)?;
                self.manifest = Some(manifest);
            }
            (Request::SealInitial { manifest_sha256 }, Reply::InitialSealed { seal }) => {
                let manifest = self.manifest.as_ref().ok_or(ServiceError::Invalid("initial helper manifest absent"))?;
                seal.validate(manifest)?;
                require(self.seal.is_none() && manifest_sha256 == manifest.manifest_sha256)?;
                self.seal = Some(seal);
            }
            _ => return Err(ServiceError::Invalid("initial helper completion crossed operation")),
        }
        Ok(())
    }
    pub(super) fn seal(&self) -> Result<&Seal, ServiceError> {
        self.seal.as_ref().ok_or(ServiceError::Invalid("initial helper is not durably sealed"))
    }
    pub(super) fn request_deadline(&self, request: &Request) -> Result<u64, ServiceError> {
        let manifest = match request {
            Request::InstallInitial { manifest } => manifest,
            Request::SealInitial { .. } => self.manifest.as_ref().ok_or(ServiceError::Invalid("initial helper manifest absent"))?,
        };
        manifest.require_live()?;
        Ok(manifest.deadline.absolute_boottime_nanos())
    }
    pub(super) fn deadline(&self) -> u64 {
        self.manifest.as_ref().map_or(self.deadline.absolute_boottime_nanos(), |manifest| manifest.deadline.absolute_boottime_nanos())
    }
}

fn wait(socket: &AuthenticatedInheritedSeqpacket, events: libc::c_short, manifest: &Manifest)
    -> Result<(), ServiceError> {
    manifest.require_live()?;
    let now = super::super::boottime::boottime_now_nanos()
        .map_err(|_| ServiceError::Invalid("initial helper clock unavailable"))?;
    let millis = manifest.deadline.absolute_boottime_nanos().saturating_sub(now).div_ceil(1_000_000).min(1000);
    require(millis > 0)?;
    let mut item = libc::pollfd { fd: socket.progress_fd().as_raw_fd(), events, revents: 0 };
    let count = unsafe { libc::poll(&mut item, 1, millis as i32) };
    if count < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(ServiceError::Invalid("initial helper poll failed"));
    }
    require(item.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0)?;
    socket.revalidate_peer()?;
    manifest.require_live()
}
fn exchange(socket: &AuthenticatedInheritedSeqpacket, manifest: &Manifest, request: &Request)
    -> Result<Reply, ServiceError> {
    let raw = encode_canonical_frame(request)?;
    loop {
        manifest.require_live()?; socket.revalidate_peer()?;
        if socket.try_send(&raw, &[], 0)? { break; }
        wait(socket, libc::POLLOUT, manifest)?;
    }
    loop {
        manifest.require_live()?; socket.revalidate_peer()?;
        if let Some(packet) = socket.try_receive(0)? {
            require(packet.rights.is_empty())?;
            let reply = decode_canonical_frame(&packet.frame)?;
            socket.revalidate_peer()?; manifest.require_live()?;
            return Ok(reply);
        }
        wait(socket, libc::POLLIN, manifest)?;
    }
}
pub(super) fn initialize(socket: &AuthenticatedInheritedSeqpacket, manifest: &Manifest) -> Result<Seal, ServiceError> {
    manifest.require_live()?;
    match exchange(socket, manifest, &Request::InstallInitial { manifest: manifest.clone() })? {
        Reply::InitialInstalled { manifest_sha256 } => require(manifest_sha256 == manifest.manifest_sha256)?,
        _ => return Err(ServiceError::Invalid("initial helper installation reply mismatched")),
    }
    match exchange(socket, manifest, &Request::SealInitial { manifest_sha256: manifest.manifest_sha256.clone() })? {
        Reply::InitialSealed { seal } => { seal.validate(manifest)?; Ok(seal) }
        _ => Err(ServiceError::Invalid("initial helper seal reply mismatched")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Synthetic public fixtures only: no clock, owner, socket, key or journal.
    fn fixture() -> Manifest {
        let pin = Sha256Digest::compute(b"SYNTHETIC initial helper pin");
        let histories: HistoryPins = ROLES.into_iter().map(|role| (role, pin.clone())).collect();
        serde_json::from_value(serde_json::json!({"apiVersion": API, "initialization":"fresh-helper",
            "operationGeneration":7, "sharedConfigurationSha256":pin, "serviceConfigurationSha256":pin,
            "initialEndpointHistorySha256":histories, "deadline":{"domain":{"authorityBootId":vec![1u8;16],
                "timeNamespaceDevice":9,"timeNamespaceInode":10},"absoluteBoottimeNanos":11},
            "manifestSha256":pin})).unwrap()
    }

    #[test]
    fn manifest_digest_binds_exact_seven_field_transcript() {
        let value = fixture();
        let raw = encode_canonical_frame(&serde_json::json!([API,"fresh-helper",7,
            value.shared_configuration_sha256,value.service_configuration_sha256,
            value.initial_endpoint_history_sha256,value.deadline])).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"catchplate.policyCustodyCleanupHelperInitialBootstrap/v1\0");
        hash.update((raw.len() as u64).to_be_bytes()); hash.update(&raw);
        assert_eq!(value.expected_digest().unwrap().as_str(), format!("sha256:{}",hex::encode(hash.finalize())));
        let mut changed = value.clone(); changed.operation_generation += 1;
        assert_ne!(changed.expected_digest().unwrap(),value.expected_digest().unwrap());
    }

    #[test]
    fn initial_history_roles_are_exact_not_a_subset_or_extra_role() {
        let mut values: Histories = ROLES.into_iter().map(|role| (role,"{\"synthetic\":true}".to_owned())).collect();
        assert!(history_pins(&values).is_ok());
        values.remove(&ROLES[0]); assert!(history_pins(&values).is_err());
        values.insert(PolicyCustodyEndpointRole::SignerHsm,"{}".to_owned());
        assert!(history_pins(&values).is_err());
    }

    #[test]
    fn initial_wire_does_not_accept_recovered_manifest_or_unknown_fields() {
        assert!(serde_json::from_value::<Request>(serde_json::json!({"bootstrapOperation":"install-manifest",
            "body":{"manifest":fixture()}})).is_err());
        let mut value = serde_json::to_value(fixture()).unwrap();
        value.as_object_mut().unwrap().insert("priorJournalHead".to_owned(),serde_json::Value::Null);
        assert!(serde_json::from_value::<Manifest>(value).is_err());
    }
}
