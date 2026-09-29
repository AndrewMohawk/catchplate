//! Retained native execution admission, same-child networking and lifecycle.
//!
//! Explicit cold v5 reaches only genuine executable parents and durable claims.
//! The old diagnostic workload cannot be promoted or used to mint a permit.

mod elf;
mod manifest;
pub(super) mod filesystem;
pub(super) mod start_authority;
mod start;
mod parent;
mod start_reservation;
mod containment;
pub(super) mod child;
pub(super) mod child_network;
pub(super) mod network;
mod child_trampoline;
mod guardian;
mod guardian_process;
mod guarded;
mod lifecycle;
pub(super) use start::{Inputs, PreparedStart};
pub(super) use lifecycle::execute;
#[path = "../egress/child_network_policy.rs"]
mod child_network_policy;
// Reuse actual host observation, never CA-install permission or its journal.
#[path = "../install/host.rs"]
mod host;
