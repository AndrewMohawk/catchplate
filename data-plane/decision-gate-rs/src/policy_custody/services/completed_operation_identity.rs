//! Collision comparison only, never authority or evidence of completion.
#[derive(Clone, Copy)]
pub(crate) struct Identity<'a> {
    pub operation: &'a str,
    pub replay: &'a str,
    pub fence: &'a str,
}

pub(crate) fn relation(prior: Identity<'_>, next: Identity<'_>, same_binding: bool)
    -> Result<bool, &'static str> {
    let operation = prior.operation == next.operation;
    let replay = prior.replay == next.replay;
    let fence = prior.fence == next.fence;
    if operation && replay && fence && same_binding {
        Ok(true)
    } else if !operation && !replay && !fence && !same_binding {
        Ok(false)
    } else {
        Err("completed operation identity overlaps a different exact binding")
    }
}

#[cfg(test)]
#[path = "completed_operation_identity_tests.rs"]
mod tests;
