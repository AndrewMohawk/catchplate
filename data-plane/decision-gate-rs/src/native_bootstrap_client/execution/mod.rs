//! Retained executable-parent admission and guarded pre-exec child ownership.
//!
//! No public start configuration or same-child network/release path yet.
//! Actual owners and durable claims precede cgroup/child creation; the new child
//! remains blocked. The old diagnostic workload cannot be promoted.

mod elf;
mod manifest;
pub(super) mod filesystem;
pub(super) mod start_authority;
mod start;
mod parent;
mod start_reservation;
mod containment;
mod child;
mod child_trampoline;
mod guardian;
mod guardian_process;
mod guarded;
#[path = "../egress/child_network_policy.rs"]
mod child_network_policy;
// Reuse actual host observation, never CA-install permission or its journal.
#[path = "../install/host.rs"]
mod host;
