use super::common::ServiceRuntime;
use super::super::{
    CustodyServiceRole, RootOwnedResponseObservationV2Config,
    V2RuntimeError,
};

pub(crate) fn run(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    let _prevalidated_release_transparency_artifact =
        config.release_transparency_artifact();
    ServiceRuntime::prepare(
        config,
        CustodyServiceRole::ReleaseAttestorPublisher,
    )?
    .run()
}
