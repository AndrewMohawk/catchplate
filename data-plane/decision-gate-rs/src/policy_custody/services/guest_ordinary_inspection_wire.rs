//! Private, same-invocation inspection IPC. No transferable admission verdict.
use super::super::Sha256Digest;
use serde::{Deserialize, Serialize};

pub(super) const API: &str = "catchplate.custodyOrdinaryPeerInspectionExchange/v1";
pub(super) const MAX_IPC: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    pub(super) api_version: String,
    pub(super) sequence: u64,
    pub(super) socket_device: u64,
    pub(super) socket_inode: u64,
    pub(super) process_identity_sha256: Sha256Digest,
    pub(super) deadline_boottime_ns: String,
    pub(super) runtime_configuration_sha256: Sha256Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Reply {
    pub(super) api_version: String,
    pub(super) sequence: u64,
    pub(super) request_sha256: Sha256Digest,
    pub(super) process_identity_sha256: Sha256Digest,
}
