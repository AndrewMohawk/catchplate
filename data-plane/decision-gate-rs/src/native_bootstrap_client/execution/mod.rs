//! Filesystem/entry admission only. No public configuration or start operation.
//!
//! A future StartOwner must independently admit its signed authority, retain
//! this exact owner, and consume separate creation/start permissions. Neither
//! the manifest nor these observations authorize executing a workload.

mod elf;
mod manifest;
pub(super) mod filesystem;
mod start_authority;
mod start;
// Reuse actual host observation, never CA-install permission or its journal.
#[path = "../install/host.rs"]
mod host;
