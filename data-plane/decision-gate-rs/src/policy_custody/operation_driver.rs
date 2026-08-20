//! Concrete composition for the five policy-custody recovery services.
//!
//! This driver proves recovery readiness only. It does not implement the
//! legacy mutation supervisor and cannot mint a TEE or HSM attestation.

use super::services::{
    RecoveryRuntimeMaterialV3, ServiceError,
    ServiceHandshakeReplyV3, ServiceHandshakeRequestV3,
    TrustedHostServiceRoleV3,
    TrustedHostNoTeeDurableRecoveryStoreClient,
};
use super::boottime::BoottimeDeadline as AbsoluteBoottimeDeadline;
use super::protocol::PolicyCustodyEndpointRole;
use super::super::Sha256Digest;
use super::watchdog_recovery::{
    drive_nonblocking_until, BoottimeWatchdogPoller,
    BoundedCleanupHelper,
    CleanupAuthorizationConsumer, CurrentSignatureAuthority,
    DurableRecoveryStore, HardUnreadyLatch, HeartbeatEvent,
    RecoveryError, RecoveryLimits, RecoveryRuntimeMaterialStore,
    RecoveryScanPage, RecoveryTargetProvider,
    TrustedHostRecoveryProtocol, WatchdogDescriptors,
    WatchdogLeaseIdentity, WatchdogRecovery,
};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd;

const MAX_DRIVER_SCAN_PASSES: usize = 64;

pub(super) struct ValidatedServiceHandshakeV3 {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) request: ServiceHandshakeRequestV3,
    pub(super) reply: ServiceHandshakeReplyV3,
}

pub(super) struct VerifiedFiveServiceReadinessV3 {
    driver_process_identity_sha256: Sha256Digest,
    driver_configuration_generation_sha256: Sha256Digest,
    operation_generation: u64,
    shared_configuration_sha256: Sha256Digest,
    deployment_generation_sha256: Sha256Digest,
    service_configuration_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    service_signing_credential_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    service_restart_epoch:
        BTreeMap<TrustedHostServiceRoleV3, u64>,
    service_invocation_id_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    service_readiness_epoch:
        BTreeMap<TrustedHostServiceRoleV3, u64>,
    service_authority_history_manifest_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    production_dispatch_protocol_set_sha256: Sha256Digest,
}

impl VerifiedFiveServiceReadinessV3 {
    pub(super) fn from_handshakes(
        handshakes: Vec<ValidatedServiceHandshakeV3>,
        retained_prior_readiness: Option<&Self>,
        expected_helper_endpoint_roles:
            BTreeSet<PolicyCustodyEndpointRole>,
        expected_driver_process_identity_sha256: Sha256Digest,
        expected_driver_configuration_generation_sha256:
            Sha256Digest,
        expected_operation_generation: u64,
        expected_shared_configuration_sha256: Sha256Digest,
        expected_service_configuration_sha256:
            BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
        expected_service_signing_credential_sha256:
            BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
        expected_service_restart_epoch:
            BTreeMap<TrustedHostServiceRoleV3, u64>,
        expected_service_readiness_epoch:
            BTreeMap<TrustedHostServiceRoleV3, u64>,
        expected_service_authority_history_manifest_sha256:
            BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
        expected_production_dispatch_protocol_set_sha256:
            Sha256Digest,
        expected_maximum_durability_worker_nanos: u64,
    ) -> Result<Self, ServiceError> {
        let expected_roles = BTreeSet::from([
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
            TrustedHostServiceRoleV3::CurrentSignatureAuthority,
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
        ]);
        if expected_helper_endpoint_roles.is_empty()
            || expected_helper_endpoint_roles.len() > 6
            || expected_operation_generation == 0
            || expected_driver_process_identity_sha256
                == Sha256Digest::compute(&[])
            || expected_driver_configuration_generation_sha256
                == Sha256Digest::compute(&[])
            || expected_shared_configuration_sha256
                == Sha256Digest::compute(&[])
            || expected_service_configuration_sha256
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_roles
            || expected_service_configuration_sha256
                .values()
                .any(|digest| {
                    digest == &Sha256Digest::compute(&[])
                })
            || expected_service_signing_credential_sha256
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_roles
            || expected_service_signing_credential_sha256
                .values()
                .any(|digest| {
                    digest == &Sha256Digest::compute(&[])
                })
            || expected_service_restart_epoch
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_roles
            || expected_service_restart_epoch
                .values()
                .any(|epoch| *epoch == 0)
            || expected_service_readiness_epoch
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_roles
            || expected_service_readiness_epoch.iter().any(
                |(role, epoch)| {
                    *epoch
                        < *expected_service_restart_epoch
                            .get(role)
                            .unwrap_or(&u64::MAX)
                },
            )
            || expected_service_authority_history_manifest_sha256
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_roles
            || expected_service_authority_history_manifest_sha256
                .values()
                .any(|digest| {
                    digest == &Sha256Digest::compute(&[])
                })
            || expected_production_dispatch_protocol_set_sha256
                == Sha256Digest::compute(&[])
            || expected_maximum_durability_worker_nanos == 0
            || expected_maximum_durability_worker_nanos
                > 1_000_000_000
        {
            return Err(ServiceError::Invalid(
                "policy-custody readiness expectations are incomplete or outside their fixed bounds",
            ));
        }
        let expected_handshake_count = 4_usize
            .checked_add(expected_helper_endpoint_roles.len())
            .ok_or(ServiceError::Invalid(
                "policy-custody readiness handshake count overflowed",
            ))?;
        if handshakes.len() != expected_handshake_count {
            return Err(ServiceError::Invalid(
                "policy-custody readiness does not contain the exact four singleton services and helper endpoint handshakes",
            ));
        }
        let mut deployment_generation_sha256 = None;
        let mut reports = BTreeMap::new();
        let mut helper_endpoint_roles = BTreeSet::new();
        let mut client_process_identity_sha256 = None;
        let mut service_process_roles = BTreeMap::new();
        let mut service_invocation_roles = BTreeMap::new();
        for handshake in handshakes {
            handshake.reply.validate_for_request(
                &handshake.request,
                handshake.endpoint_role,
            )?;
            if handshake
                    .request
                    .client_process_identity_sha256
                != expected_driver_process_identity_sha256
                || handshake
                    .request
                    .client_configuration_generation_sha256
                    != expected_driver_configuration_generation_sha256
            {
                return Err(ServiceError::Invalid(
                    "policy-custody handshake client claim differs from the retained kernel-measured driver identity or exact configuration generation",
                ));
            }
            if client_process_identity_sha256
                .as_ref()
                .is_some_and(|expected| {
                    expected
                        != &handshake
                            .request
                            .client_process_identity_sha256
                })
            {
                return Err(ServiceError::Invalid(
                    "policy-custody readiness handshakes came from different driver process identities",
                ));
            }
            client_process_identity_sha256.get_or_insert_with(|| {
                handshake
                    .request
                    .client_process_identity_sha256
                    .clone()
            });
            let expected_rights =
                expected_handshake_rights(
                    handshake.request.service_role,
                );
            if (
                handshake.request.request_rights_count,
                handshake.request.reply_rights_count,
            ) != expected_rights
            {
                return Err(ServiceError::Invalid(
                    "policy-custody handshake changed its operation-specific descriptor contract",
                ));
            }
            let report =
                &handshake.reply.trusted_host_report;
            if report.operation_generation
                    != expected_operation_generation
                || report.shared_configuration_sha256
                    != expected_shared_configuration_sha256
                || expected_service_configuration_sha256
                    .get(&report.service_role)
                    != Some(
                        &report
                            .deployment_configuration_sha256,
                    )
                || expected_service_signing_credential_sha256
                    .get(&report.service_role)
                    != report.signing_credential_sha256.as_ref()
                || expected_service_restart_epoch
                    .get(&report.service_role)
                    != Some(&report.service_restart_epoch)
                || expected_service_readiness_epoch
                    .get(&report.service_role)
                    != Some(&report.readiness_epoch)
                || expected_service_authority_history_manifest_sha256
                    .get(&report.service_role)
                    != Some(
                        &report
                            .authority_history_manifest_sha256,
                    )
                || report.production_dispatch_protocol_set_sha256
                    != expected_production_dispatch_protocol_set_sha256
                || usize::from(
                    report.durability_worker_queue_depth,
                ) != 8
                || report.maximum_durability_worker_nanos
                    != expected_maximum_durability_worker_nanos
            {
                return Err(ServiceError::Invalid(
                    "policy-custody service report differs from the exact expected generation, configuration, or signing-credential manifest",
                ));
            }
            let service_process_identity = report
                .service_process_identity_sha256
                .as_str()
                .to_owned();
            if service_process_roles
                .get(&service_process_identity)
                .is_some_and(|existing_role| {
                    existing_role != &report.service_role
                })
            {
                return Err(ServiceError::Invalid(
                    "policy-custody readiness aliases distinct service roles to one process identity",
                ));
            }
            service_process_roles
                .insert(service_process_identity, report.service_role);
            let service_invocation = report
                .service_invocation_id_sha256
                .as_str()
                .to_owned();
            if service_invocation_roles
                .get(&service_invocation)
                .is_some_and(|existing_role| {
                    existing_role != &report.service_role
                })
            {
                return Err(ServiceError::Invalid(
                    "policy-custody readiness aliases distinct service roles to one systemd invocation identity",
                ));
            }
            service_invocation_roles
                .insert(service_invocation, report.service_role);
            if deployment_generation_sha256.as_ref().is_some_and(
                |expected| {
                    expected
                        != &report.deployment_generation_sha256
                },
            ) {
                return Err(ServiceError::Invalid(
                    "policy-custody services report different deployment generations",
                ));
            }
            deployment_generation_sha256.get_or_insert_with(|| {
                report.deployment_generation_sha256.clone()
            });
            if let Some(existing) =
                reports.get(&report.service_role)
            {
                if report.service_role
                        != TrustedHostServiceRoleV3::
                            BoundedCleanupHelper
                    || existing != report
                    || !helper_endpoint_roles
                        .insert(handshake.endpoint_role)
                {
                    return Err(ServiceError::Invalid(
                        "policy-custody service role or helper endpoint handshake is duplicated",
                    ));
                }
            } else {
                if report.service_role
                        == TrustedHostServiceRoleV3::
                            BoundedCleanupHelper
                {
                    if !expected_helper_endpoint_roles
                        .contains(&handshake.endpoint_role)
                    {
                        return Err(ServiceError::Invalid(
                            "policy-custody helper readiness contains an unexpected endpoint role",
                        ));
                    }
                    helper_endpoint_roles
                        .insert(handshake.endpoint_role);
                }
                reports.insert(
                    report.service_role,
                    report.clone(),
                );
            }
        }
        if reports.keys().copied().collect::<BTreeSet<_>>()
            != expected_roles
            || helper_endpoint_roles
                != expected_helper_endpoint_roles
        {
            return Err(ServiceError::Invalid(
                "policy-custody readiness does not contain exactly the five services and helper endpoint-role set",
            ));
        }
        let service_configuration_sha256 = reports
            .iter()
            .map(|(role, report)| {
                (
                    *role,
                    report
                        .deployment_configuration_sha256
                        .clone(),
                )
            })
            .collect();
        let service_invocation_id_sha256 = reports
            .iter()
            .map(|(role, report)| {
                (
                    *role,
                    report.service_invocation_id_sha256.clone(),
                )
            })
            .collect();
        let readiness = Self {
            driver_process_identity_sha256:
                expected_driver_process_identity_sha256,
            driver_configuration_generation_sha256:
                expected_driver_configuration_generation_sha256,
            operation_generation:
                expected_operation_generation,
            shared_configuration_sha256:
                expected_shared_configuration_sha256,
            deployment_generation_sha256:
                deployment_generation_sha256.ok_or(
                    ServiceError::Invalid(
                        "policy-custody deployment generation is absent",
                    ),
                )?,
            service_configuration_sha256,
            service_signing_credential_sha256:
                expected_service_signing_credential_sha256,
            service_restart_epoch:
                expected_service_restart_epoch,
            service_invocation_id_sha256:
                service_invocation_id_sha256,
            service_readiness_epoch:
                expected_service_readiness_epoch,
            service_authority_history_manifest_sha256:
                expected_service_authority_history_manifest_sha256,
            production_dispatch_protocol_set_sha256:
                expected_production_dispatch_protocol_set_sha256,
        };
        if let Some(previous) = retained_prior_readiness {
            readiness.validate_successor_of(previous)?;
        }
        Ok(readiness)
    }

    pub(super) fn validate_successor_of(
        &self,
        previous: &Self,
    ) -> Result<(), ServiceError> {
        let roles = self
            .service_restart_epoch
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if roles
                != previous
                    .service_restart_epoch
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
            || roles
                != self
                    .service_invocation_id_sha256
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
            || roles
                != previous
                    .service_invocation_id_sha256
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
            || roles
                != self
                    .service_readiness_epoch
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
            || roles
                != previous
                    .service_readiness_epoch
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>()
        {
            return Err(ServiceError::Invalid(
                "policy-custody readiness successor changed its exact service role set",
            ));
        }
        for role in roles {
            let current_restart = self.service_restart_epoch[&role];
            let previous_restart =
                previous.service_restart_epoch[&role];
            let current_readiness =
                self.service_readiness_epoch[&role];
            let previous_readiness =
                previous.service_readiness_epoch[&role];
            let current_invocation =
                &self.service_invocation_id_sha256[&role];
            let previous_invocation =
                &previous.service_invocation_id_sha256[&role];
            if current_restart < previous_restart
                || current_readiness <= previous_readiness
                || (current_restart == previous_restart
                    && current_invocation != previous_invocation)
                || (current_restart > previous_restart
                    && (current_invocation == previous_invocation
                        || current_readiness
                            <= previous_readiness))
                || (current_invocation != previous_invocation
                    && (current_restart <= previous_restart
                        || current_readiness
                            <= previous_readiness))
            {
                return Err(ServiceError::Invalid(
                    "policy-custody readiness successor replays, rolls back, or inconsistently replaces a service invocation",
                ));
            }
        }
        Ok(())
    }
}

fn expected_handshake_rights(
    role: TrustedHostServiceRoleV3,
) -> (u8, u8) {
    match role {
        TrustedHostServiceRoleV3::DurableRecoveryStore
        | TrustedHostServiceRoleV3::
            CleanupAuthorizationConsumer
        | TrustedHostServiceRoleV3::
            CurrentSignatureAuthority => (0, 0),
        TrustedHostServiceRoleV3::RecoveryTargetProvider => {
            (6, 2)
        }
        TrustedHostServiceRoleV3::BoundedCleanupHelper => {
            (2, 0)
        }
    }
}

pub(super) struct PolicyCustodyRecoveryReadiness {
    reconciled_owner_count: usize,
    driver_process_identity_sha256: Sha256Digest,
    driver_configuration_generation_sha256: Sha256Digest,
    operation_generation: u64,
    shared_configuration_sha256: Sha256Digest,
    deployment_generation_sha256: Sha256Digest,
    service_configuration_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    service_signing_credential_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    service_restart_epoch:
        BTreeMap<TrustedHostServiceRoleV3, u64>,
    service_invocation_id_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    service_readiness_epoch:
        BTreeMap<TrustedHostServiceRoleV3, u64>,
    service_authority_history_manifest_sha256:
        BTreeMap<TrustedHostServiceRoleV3, Sha256Digest>,
    production_dispatch_protocol_set_sha256: Sha256Digest,
}

impl PolicyCustodyRecoveryReadiness {
    pub(super) fn reconciled_owner_count(&self) -> usize {
        self.reconciled_owner_count
    }

    pub(super) fn driver_process_identity_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.driver_process_identity_sha256
    }

    pub(super) fn operation_generation(&self) -> u64 {
        self.operation_generation
    }

    pub(super) fn shared_configuration_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.shared_configuration_sha256
    }

    pub(super) fn deployment_generation_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.deployment_generation_sha256
    }

    pub(super) fn service_configuration_sha256(
        &self,
    ) -> &BTreeMap<
        TrustedHostServiceRoleV3,
        Sha256Digest,
    > {
        &self.service_configuration_sha256
    }

    pub(super) fn service_signing_credential_sha256(
        &self,
    ) -> &BTreeMap<
        TrustedHostServiceRoleV3,
        Sha256Digest,
    > {
        &self.service_signing_credential_sha256
    }

    pub(super) fn service_restart_epoch(
        &self,
    ) -> &BTreeMap<TrustedHostServiceRoleV3, u64> {
        &self.service_restart_epoch
    }

    pub(super) fn service_readiness_epoch(
        &self,
    ) -> &BTreeMap<TrustedHostServiceRoleV3, u64> {
        &self.service_readiness_epoch
    }

    pub(super) fn service_invocation_id_sha256(
        &self,
    ) -> &BTreeMap<
        TrustedHostServiceRoleV3,
        Sha256Digest,
    > {
        &self.service_invocation_id_sha256
    }

    pub(super) fn service_authority_history_manifest_sha256(
        &self,
    ) -> &BTreeMap<
        TrustedHostServiceRoleV3,
        Sha256Digest,
    > {
        &self.service_authority_history_manifest_sha256
    }

    pub(super) fn production_dispatch_protocol_set_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.production_dispatch_protocol_set_sha256
    }
}

pub(super) struct PolicyCustodyOperationDriver<
    S,
    A,
    T,
    H,
    V,
    B,
    E,
> where
    S: RecoveryRuntimeMaterialStore,
    A: CleanupAuthorizationConsumer,
    T: RecoveryTargetProvider,
    H: BoundedCleanupHelper,
    V: CurrentSignatureAuthority,
    B: BoottimeWatchdogPoller,
    E: HeartbeatEvent,
{
    pub(super) service_readiness:
        VerifiedFiveServiceReadinessV3,
    pub(super) store: S,
    pub(super) cleanup_authority: A,
    pub(super) targets: T,
    pub(super) cleanup_helper: H,
    pub(super) signature_authority: V,
    pub(super) poller: B,
    pub(super) heartbeat: E,
    pub(super) descriptors: WatchdogDescriptors,
    pub(super) watchdog_lease: WatchdogLeaseIdentity,
    pub(super) hard_unready: HardUnreadyLatch,
    pub(super) limits: RecoveryLimits,
}

impl<S, A, T, H, V, B, E>
    PolicyCustodyOperationDriver<S, A, T, H, V, B, E>
where
    S: RecoveryRuntimeMaterialStore,
    A: CleanupAuthorizationConsumer,
    T: RecoveryTargetProvider,
    H: BoundedCleanupHelper,
    V: CurrentSignatureAuthority,
    B: BoottimeWatchdogPoller,
    E: HeartbeatEvent,
{
    pub(super) fn reconcile_startup(
        &mut self,
        startup_deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<PolicyCustodyRecoveryReadiness, RecoveryError> {
        self.limits.validate()?;
        startup_deadline
            .domain()
            .require_current()
            .map_err(|_| {
                RecoveryError::Deadline(
                    "policy-custody driver startup domain is not current",
                )
            })?;

        let owners = self.scan_all_incomplete(startup_deadline)?;
        let mut reconciled_owner_count = 0_usize;
        for owner in owners {
            let progress_fd =
                self.store.progress_fd().as_raw_fd();
            let material = drive_nonblocking_until(
                progress_fd,
                startup_deadline,
                || {
                    self.store
                        .try_recovery_runtime_material_nonblocking(
                            &owner.ownership_id_sha256,
                            startup_deadline,
                        )
                },
            )?
            .ok_or(RecoveryError::Durable(
                "incomplete owner has no lossless recovery material",
            ))?;
            if material.owner != owner {
                return Err(RecoveryError::Durable(
                    "recovery material changed the exact durable owner",
                ));
            }
            let protocol = TrustedHostRecoveryProtocol::new(
                material.settlement_chain,
                material.authorized_cleanup_steps,
                material.stored_cleanup_evidence,
            )?;
            let mut recovery = WatchdogRecovery {
                protocol: &protocol,
                store: &mut self.store,
                cleanup_authority: &mut self.cleanup_authority,
                targets: &mut self.targets,
                cleanup_helper: &mut self.cleanup_helper,
                signature_authority:
                    &mut self.signature_authority,
                poller: &mut self.poller,
                heartbeat: &mut self.heartbeat,
                descriptors: &self.descriptors,
                watchdog_lease:
                    self.watchdog_lease.clone(),
                hard_unready: &self.hard_unready,
                limits: self.limits,
            };
            recovery.reconcile_exact_owner_startup(
                &owner,
                startup_deadline,
            )?;
            reconciled_owner_count = reconciled_owner_count
                .checked_add(1)
                .ok_or(RecoveryError::Invalid(
                    "reconciled owner count overflowed",
                ))?;
        }

        if !self.scan_all_incomplete(startup_deadline)?.is_empty() {
            return Err(RecoveryError::Durable(
                "nonterminal ownership remains after startup reconciliation",
            ));
        }
        if self.hard_unready.is_latched() {
            return Err(RecoveryError::HardUnready(
                self.hard_unready.reason().unwrap_or(
                    super::watchdog_recovery::
                        HardUnreadyReason::
                        StartupReconciliationFailed,
                ),
            ));
        }
        Ok(PolicyCustodyRecoveryReadiness {
            reconciled_owner_count,
            driver_process_identity_sha256: self
                .service_readiness
                .driver_process_identity_sha256
                .clone(),
            driver_configuration_generation_sha256: self
                .service_readiness
                .driver_configuration_generation_sha256
                .clone(),
            operation_generation: self
                .service_readiness
                .operation_generation,
            shared_configuration_sha256: self
                .service_readiness
                .shared_configuration_sha256
                .clone(),
            deployment_generation_sha256: self
                .service_readiness
                .deployment_generation_sha256
                .clone(),
            service_configuration_sha256: self
                .service_readiness
                .service_configuration_sha256
                .clone(),
            service_signing_credential_sha256: self
                .service_readiness
                .service_signing_credential_sha256
                .clone(),
            service_restart_epoch: self
                .service_readiness
                .service_restart_epoch
                .clone(),
            service_invocation_id_sha256: self
                .service_readiness
                .service_invocation_id_sha256
                .clone(),
            service_readiness_epoch: self
                .service_readiness
                .service_readiness_epoch
                .clone(),
            service_authority_history_manifest_sha256: self
                .service_readiness
                .service_authority_history_manifest_sha256
                .clone(),
            production_dispatch_protocol_set_sha256: self
                .service_readiness
                .production_dispatch_protocol_set_sha256
                .clone(),
        })
    }

    fn scan_all_incomplete(
        &mut self,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Vec<super::watchdog_recovery::DurableOwnershipRecord>,
        RecoveryError,
    > {
        let mut continuation = None;
        let mut owners = Vec::new();
        let mut ownership_ids = BTreeSet::new();
        for _ in 0..MAX_DRIVER_SCAN_PASSES {
            let page_continuation = continuation;
            let maximum_records =
                self.limits.maximum_scan_records;
            let progress_fd =
                self.store.progress_fd().as_raw_fd();
            let page: RecoveryScanPage<_> =
                drive_nonblocking_until(
                    progress_fd,
                    deadline,
                    || {
                        self.store
                            .try_scan_incomplete_ownership_nonblocking(
                                page_continuation.clone(),
                                maximum_records,
                                deadline,
                            )
                    },
                )?;
            if page.records.len() > maximum_records {
                return Err(RecoveryError::Invalid(
                    "durable store exceeded the requested scan page bound",
                ));
            }
            for owner in page.records {
                if !ownership_ids
                    .insert(owner.ownership_id_sha256.clone())
                {
                    return Err(RecoveryError::Durable(
                        "durable store repeated an ownership record across scan pages",
                    ));
                }
                owners.push(owner);
            }
            continuation = page.continuation;
            if continuation.is_none() {
                return Ok(owners);
            }
        }
        Err(RecoveryError::Durable(
            "durable ownership scan did not converge within its bound",
        ))
    }
}

impl RecoveryRuntimeMaterialStore
    for TrustedHostNoTeeDurableRecoveryStoreClient
{
    fn try_recovery_runtime_material_nonblocking(
        &mut self,
        ownership_id_sha256:
            &super::watchdog_recovery::RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<Option<RecoveryRuntimeMaterialV3>>,
        RecoveryError,
    > {
        TrustedHostNoTeeDurableRecoveryStoreClient::
            try_recovery_runtime_material_nonblocking(
                self,
                ownership_id_sha256,
                deadline,
            )
    }
}
