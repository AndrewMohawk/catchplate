//! Shared comparison of already-authenticated native operation bindings.
//! Callers still check exact command bytes, durable completion and ownership.
use super::super::production_dispatch::ProductionDispatchBindingV4;
use super::ServiceRunnerError;

#[path = "completed_operation_identity.rs"]
mod identity;

pub(super) fn relation(prior: &ProductionDispatchBindingV4, next: &ProductionDispatchBindingV4)
    -> Result<bool, ServiceRunnerError> {
    identity::relation(identity(prior), identity(next), prior == next)
        .map_err(ServiceRunnerError::invalid)
}

fn identity(binding: &ProductionDispatchBindingV4) -> identity::Identity<'_> {
    identity::Identity {
        operation: binding.operation_id_sha256.as_str(),
        replay: binding.replay_id_sha256.as_str(),
        fence: binding.termination_fence_sha256.as_str(),
    }
}
