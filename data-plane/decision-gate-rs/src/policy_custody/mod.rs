//! Policy-custody process, protocol, timing, and receipt-accounting boundary.
//!
//! Extracted modules are the sole policy-custody authorities. The historical
//! source path contains only a fail-closed compatibility facade.

pub(super) mod authority_history;
pub(super) mod boottime;
pub(super) mod endpoint_clients;
pub(super) mod launcher;
pub(super) mod operation_driver;
pub(super) mod production_dispatch;
pub(super) mod protocol;
pub(super) mod receipt_arena;
pub(super) mod services;
pub(super) mod terminal_settlement;
pub(super) mod watchdog_recovery;

use super::{
    EnvelopeKeyTrust, ProductionCustodyOperationDeadline,
    ProductionCustodyTerminationProof,
    ProductionPolicyShadowCustodyRpcSupervisor, Sha256Digest,
    ShadowError, TrustedTime, VerifiedAssignment,
};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

pub(crate) use receipt_arena::{
    InlineReceiptReference, InlineSha256Digest, ModeledReservationKind,
    ModeledReservationToken, ReceiptArenaError, ReceiptReferenceKind,
    ReceiptSlotHandle,
    MODELED_RECEIPT_REFERENCE_BUDGET_BYTES,
    MODELED_RECEIPT_REFERENCE_BUDGET_LABEL,
};

pub(crate) const POLICY_CORE_MODELED_RECEIPT_RESERVATION_SLOTS: usize =
    128;
pub(crate) type PolicyCoreModeledReceiptArena =
    receipt_arena::ModeledReceiptArena<
        POLICY_CORE_MODELED_RECEIPT_RESERVATION_SLOTS,
    >;

#[path = "../policy_shadow_custody_process.rs"]
mod facade;

pub(crate) use facade::{
    install_policy_shadow_custody_generation_from_retained_file,
    run_policy_shadow_custody_server_from_env,
    PolicyShadowCustodyProcessClient,
};

pub(crate) use services::{
    PreparedNativeCustodyLifecycle,NativeCustodyLifecycleOwner,
    run_bounded_cleanup_helper_from_env,
    run_cleanup_authorization_consumer_from_env,
    run_current_signature_authority_from_env,
    run_durable_recovery_store_from_env,
    run_recovery_target_provider_from_env,
};
pub(crate) use services::guest::{PreparedGuestServiceDelivery,GuestClosureAssociation,GuestClosureBinding};
pub(crate) use services::guest::native_keys::{NativeCustodyKeyConfiguration,PreparedNativeCustodyKeys,NativeCustodyKeys,
    NativeShadowEncryptedKeysConfiguration};

pub(crate) fn run_production_rpc_service_from_env(
) -> Result<(), services::ServiceRunnerError> {
    services::run_production_rpc_service_from_env()
}

pub(super) struct ExtractedPolicyCustodyAuthority;

impl ExtractedPolicyCustodyAuthority {
    pub(super) fn install_generation_from_retained_file(
        retained_config: std::fs::File,
        expected_config_sha256: Sha256Digest,
        assignment: VerifiedAssignment,
        key_trust: Arc<dyn EnvelopeKeyTrust + Send + Sync>,
        trusted_time: Arc<dyn TrustedTime + Send + Sync>,
    ) -> Result<
        Arc<ProductionPolicyShadowCustodyRpcSupervisor>,
        ShadowError,
    > {
        facade::install_retained_generation(
            retained_config,
            expected_config_sha256,
            assignment,
            key_trust,
            trusted_time,
        )
    }

}

pub(super) fn boottime_now_nanos() -> Result<u64, ShadowError> {
    boottime::boottime_now_nanos()
        .map_err(|_| ShadowError::CustodyUnavailable)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OpaqueOperationHandle {
    operation_id_sha256: Sha256Digest,
    operation_deadline: boottime::BoottimeDeadline,
    cleanup_deadline: boottime::BoottimeDeadline,
    termination_fence_sha256: Sha256Digest,
}

impl OpaqueOperationHandle {
    pub(super) fn from_production_deadline(
        operation_id_sha256: Sha256Digest,
        deadline: &ProductionCustodyOperationDeadline,
        termination_fence_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        let domain = boottime::BoottimeDomain::current()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let operation_deadline =
            boottime::BoottimeDeadline::from_absolute_in_expected_domain(
                domain,
                deadline.operation_deadline_boottime_nanos(),
            )
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let cleanup_deadline =
            boottime::BoottimeDeadline::from_absolute_in_expected_domain(
                domain,
                deadline.cleanup_deadline_boottime_nanos(),
            )
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if operation_deadline.absolute_nanos()
            >= cleanup_deadline.absolute_nanos()
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(Self {
            operation_id_sha256,
            operation_deadline,
            cleanup_deadline,
            termination_fence_sha256,
        })
    }

    pub(super) fn operation_id_sha256(&self) -> &Sha256Digest {
        &self.operation_id_sha256
    }

    pub(super) fn operation_deadline(
        &self,
    ) -> boottime::BoottimeDeadline {
        self.operation_deadline
    }

    pub(super) fn cleanup_deadline(
        &self,
    ) -> boottime::BoottimeDeadline {
        self.cleanup_deadline
    }

    pub(super) fn termination_fence_sha256(&self) -> &Sha256Digest {
        &self.termination_fence_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PolicyShadowCustodyResultDisposition {
    ResultCommitted,
    ResultAborted,
}

impl PolicyShadowCustodyResultDisposition {
    fn protocol_phase(self) -> protocol::DurableSettlementPhase {
        match self {
            Self::ResultCommitted => {
                protocol::DurableSettlementPhase::ResultCommitted
            }
            Self::ResultAborted => {
                protocol::DurableSettlementPhase::ResultAborted
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedTerminalCleanupEvidence {
    operation_id_sha256: Sha256Digest,
    termination_fence_sha256: Sha256Digest,
    result_disposition: PolicyShadowCustodyResultDisposition,
    terminal_phase: protocol::DurableSettlementPhase,
    completed_at_boottime_nanos: u64,
    evidence_sha256: Sha256Digest,
}

impl VerifiedTerminalCleanupEvidence {
    pub(super) fn from_verified_process_termination(
        proof: &ProductionCustodyTerminationProof,
        expected_worker_executable_sha256: &Sha256Digest,
        handle: &OpaqueOperationHandle,
        durable_request_sha256: &Sha256Digest,
        result_disposition: PolicyShadowCustodyResultDisposition,
        settlement: &terminal_settlement::
            VerifiedFiveServiceTerminalSettlementV4,
    ) -> Result<Self, ShadowError> {
        let operation = settlement.operation();
        let worker = settlement.worker();
        let deadlines = settlement.deadlines();
        let cleanup = settlement.cleanup();
        let expected_disposition = match result_disposition {
            PolicyShadowCustodyResultDisposition::ResultCommitted => {
                terminal_settlement::TerminalResultDispositionV4::
                    ResultCommitted
            }
            PolicyShadowCustodyResultDisposition::ResultAborted => {
                terminal_settlement::TerminalResultDispositionV4::
                    ResultAborted
            }
        };
        if operation.operation_id_sha256
                != *handle.operation_id_sha256()
            || operation.durable_request_sha256
                != *durable_request_sha256
            || operation.termination_fence_sha256
                != *handle.termination_fence_sha256()
            || operation.result_disposition != expected_disposition
            || worker.worker_executable_sha256
                != *expected_worker_executable_sha256
            || worker.worker_executable_sha256
                != proof.worker_executable_sha256
            || worker.kernel_driver_identity_sha256
                != proof.kernel_driver_identity_sha256
            || worker.kernel_retained_descriptor_set_sha256
                != proof.kernel_retained_descriptor_set_sha256
            || worker.driver_generation_receipt_sha256
                != proof.driver_generation_receipt_sha256
            || deadlines.opened_at_boottime_nanos
                >= handle.operation_deadline().absolute_nanos()
            || deadlines.operation_deadline_boottime_nanos
                != handle.operation_deadline().absolute_nanos()
            || deadlines.cleanup_deadline_boottime_nanos
                != handle.cleanup_deadline().absolute_nanos()
            || deadlines.worker_terminated_at_unix_nanos
                != proof.worker_terminated_at_unix_nanos
            || deadlines.worker_terminated_at_boottime_nanos
                != proof.worker_terminated_at_boottime_nanos
            || cleanup.late_mutation_fence_closed_sha256
                == Sha256Digest::compute(&[])
            || settlement
                .five_service_receipts_root_sha256()
                == &Sha256Digest::compute(&[])
            || settlement.final_committed_head_sha256()
                == &Sha256Digest::compute(&[])
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let _ = (
            proof.process_reaped,
            proof.late_mutation_fence_closed,
            worker.worker.pid,
            worker.worker.start_time_ticks,
            worker.worker.pidfd_inode,
            worker.authority_boot_id_sha256.as_str(),
        );
        Ok(Self {
            operation_id_sha256:
                handle.operation_id_sha256().clone(),
            termination_fence_sha256:
                handle.termination_fence_sha256().clone(),
            result_disposition,
            terminal_phase:
                protocol::DurableSettlementPhase::
                    TerminationCommitted,
            completed_at_boottime_nanos:
                deadlines.worker_terminated_at_boottime_nanos,
            evidence_sha256: settlement.evidence_sha256().clone(),
        })
    }

    pub(crate) fn result_disposition(
        &self,
    ) -> PolicyShadowCustodyResultDisposition {
        self.result_disposition
    }

    pub(crate) fn receipt_releasable(&self) -> bool {
        self.terminal_phase
            == protocol::DurableSettlementPhase::TerminationCommitted
            && self.result_disposition
                == PolicyShadowCustodyResultDisposition::ResultCommitted
    }

    pub(super) fn validates(
        &self,
        operation_id_sha256: &Sha256Digest,
        deadline: boottime::BoottimeDeadline,
    ) -> bool {
        self.operation_id_sha256 == *operation_id_sha256
            && self
                .termination_fence_sha256
                .as_str()
                .starts_with("sha256:")
            && self.terminal_phase
                == protocol::DurableSettlementPhase::TerminationCommitted
            && self.completed_at_boottime_nanos > 0
            && self.completed_at_boottime_nanos
                < deadline.absolute_nanos()
            && self.evidence_sha256.as_str().starts_with("sha256:")
    }

    pub(super) fn validates_production_deadline(
        &self,
        operation_id_sha256: &Sha256Digest,
        opened_at_boottime_nanos: u64,
        cleanup_deadline_boottime_nanos: u64,
    ) -> bool {
        self.operation_id_sha256 == *operation_id_sha256
            && opened_at_boottime_nanos > 0
            && self.completed_at_boottime_nanos
                >= opened_at_boottime_nanos
            && self.completed_at_boottime_nanos
                < cleanup_deadline_boottime_nanos
            && self.terminal_phase
                == protocol::DurableSettlementPhase::TerminationCommitted
            && self.evidence_sha256.as_str().starts_with("sha256:")
    }
}

pub(super) struct BoottimeCompletion<T> {
    deadline: boottime::BoottimeDeadline,
    event: OwnedFd,
    result: Mutex<Option<T>>,
}

impl<T> BoottimeCompletion<T> {
    pub(super) fn new(
        deadline: boottime::BoottimeDeadline,
    ) -> Result<Self, ShadowError> {
        deadline
            .require_live()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let raw = unsafe {
            libc::eventfd(
                0,
                libc::EFD_CLOEXEC | libc::EFD_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(Self {
            deadline,
            event: unsafe { OwnedFd::from_raw_fd(raw) },
            result: Mutex::new(None),
        })
    }

    pub(super) fn complete(&self, result: T) -> Result<(), ShadowError> {
        let mut slot = self
            .result
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if slot.is_some() {
            return Err(ShadowError::CustodyUnavailable);
        }
        *slot = Some(result);
        drop(slot);
        let signal = 1_u64.to_ne_bytes();
        loop {
            let written = unsafe {
                libc::write(
                    self.event.as_raw_fd(),
                    signal.as_ptr().cast(),
                    signal.len(),
                )
            };
            if written == signal.len() as isize {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(ShadowError::CustodyUnavailable);
            }
        }
    }

    pub(super) fn wait(&self) -> Result<T, ShadowError> {
        match boottime::poll_until(
            self.deadline,
            &[boottime::PollTarget::eventfd(self.event.as_fd())],
        )
        .map_err(|_| ShadowError::CustodyUnavailable)?
        {
            boottime::WaitOutcome::DeadlineExpired => {
                Err(ShadowError::CustodyUnavailable)
            }
            boottime::WaitOutcome::Progress(events)
                if events.len() == 1
                    && events[0].readable()
                    && !events[0].errored()
                    && !events[0].hung_up() =>
            {
                self.consume_signal()?;
                self.result
                    .lock()
                    .map_err(|_| ShadowError::CustodyUnavailable)?
                    .take()
                    .ok_or(ShadowError::CustodyUnavailable)
            }
            boottime::WaitOutcome::Progress(_) => {
                Err(ShadowError::CustodyUnavailable)
            }
        }
    }

    fn consume_signal(&self) -> Result<(), ShadowError> {
        let mut signal = [0_u8; std::mem::size_of::<u64>()];
        loop {
            let read = unsafe {
                libc::read(
                    self.event.as_raw_fd(),
                    signal.as_mut_ptr().cast(),
                    signal.len(),
                )
            };
            if read == signal.len() as isize {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(ShadowError::CustodyUnavailable);
            }
        }
    }
}
