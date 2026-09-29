//! Retained executable-parent admission and claimed cgroup preparation.
//!
//! No public configuration, executable child or independent guardian yet.
//! Actual owners and distinct durable claims precede cgroup creation; the old
//! diagnostic workload cannot be promoted by these observations.

mod elf;
mod manifest;
pub(super) mod filesystem;
pub(super) mod start_authority;
mod start;
mod parent;
mod start_reservation;
mod containment;
// Reuse actual host observation, never CA-install permission or its journal.
#[path = "../install/host.rs"]
mod host;
