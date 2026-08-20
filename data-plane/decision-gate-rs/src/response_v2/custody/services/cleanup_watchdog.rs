use super::common::ServiceRuntime;
use super::super::{
    CustodyServiceRole, RootOwnedResponseObservationV2Config,
    V2RuntimeError,
};

pub(crate) fn run(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    ServiceRuntime::prepare(
        config,
        CustodyServiceRole::CleanupWatchdog,
    )?
    .run()
}
