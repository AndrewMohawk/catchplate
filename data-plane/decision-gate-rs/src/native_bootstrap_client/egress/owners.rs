//! Closed source-owner joins. No generic FD, callback or successful DTO owner.

use super::{attachment::PreattachmentGuard, attachment_authority, authority,
    native_execution::{ExecutableAttachmentGuard, PreparedNetwork}, workload, EgressGuard};
use std::fs::File;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct OwnerIdentity { family: u8, address: usize }

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase { Admission, Continuation }

#[derive(Clone, Copy)]
pub(super) enum Owner<'a> { Diagnostic(&'a EgressGuard), Executable(&'a PreparedNetwork<'a>) }
impl<'a> Owner<'a> {
    pub(super) fn identity(self) -> OwnerIdentity {
        match self {
            Self::Diagnostic(owner) => OwnerIdentity { family: 0, address: owner as *const _ as usize },
            Self::Executable(owner) => OwnerIdentity { family: 1, address: owner as *const _ as usize },
        }
    }
    pub(super) fn same(self, other: Owner<'_>) -> bool { self.identity() == other.identity() }
    pub(super) fn check(self) -> Result<(), String> { self.check_phase(Phase::Admission) }
    pub(super) fn check_phase(self, phase: Phase) -> Result<(), String> {
        match (self, phase) {
            (Self::Diagnostic(owner), Phase::Admission) => owner.check(),
            (Self::Executable(owner), Phase::Admission) => owner.check(),
            (Self::Executable(owner), Phase::Continuation) => owner.check_running(),
            _ => Err("diagnostic egress has no execution continuation permission".to_owned()),
        }
    }
    pub(super) fn deadline(self, phase: Phase) -> Result<Instant, String> {
        self.check_phase(phase)?;
        match self { Self::Diagnostic(owner) => owner.deadline(), Self::Executable(owner) => owner.deadline(phase) }
    }
    pub(super) fn authority(self) -> &'a authority::Authorization {
        match self { Self::Diagnostic(owner) => &owner.precreation.authorization,
            Self::Executable(owner) => owner.authority() }
    }
    pub(super) fn association(self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        match self { Self::Diagnostic(owner) => (owner.reservation_id, owner.association_sha256, owner.token_sha256),
            Self::Executable(owner) => owner.association() }
    }
    pub(super) fn duplicate_backend(self) -> Result<File, String> {
        self.check()?;
        match self { Self::Diagnostic(owner) => owner.duplicate_backend(), Self::Executable(owner) => owner.filter() }
    }
    pub(super) fn backend_identity(self) -> Result<(u64, u64, u32, u64, u64), String> {
        match self {
            Self::Diagnostic(owner) => {
                let held = owner.workload.try_borrow().map_err(|_| "diagnostic workload is already borrowed")?;
                let value = held.identity();
                Ok((value.namespace_device, value.namespace_inode, value.backend_port_id,
                    value.backend_socket_device, value.backend_socket_inode))
            }
            Self::Executable(owner) => owner.backend_identity(),
        }
    }
    pub(super) fn duplicate_attachment(self) -> Result<workload::AttachmentDescriptors, String> {
        self.check()?;
        match self { Self::Diagnostic(owner) => owner.duplicate_attachment(),
            Self::Executable(owner) => owner.duplicate_attachment() }
    }
}

/// The executable Arc owns the real installed firewall but owns no attachment
/// backend/journal referring back to it. Diagnostic guards stay borrowed.
#[derive(Clone)]
pub(super) enum AttachmentOwner<'guard, 'egress> {
    Diagnostic(&'guard PreattachmentGuard<'egress>),
    Executable(Arc<ExecutableAttachmentGuard<'egress>>),
}
impl<'egress> AttachmentOwner<'_, 'egress> {
    pub(super) fn same(&self, other: &AttachmentOwner<'_, '_>) -> bool {
        match (self, other) {
            (Self::Diagnostic(left), AttachmentOwner::Diagnostic(right)) => *left as *const _ as usize == *right as *const _ as usize,
            (Self::Executable(left), AttachmentOwner::Executable(right)) => Arc::as_ptr(left) as usize == Arc::as_ptr(right) as usize,
            _ => false,
        }
    }
    pub(super) fn egress(&self) -> Owner<'egress> {
        match self { Self::Diagnostic(owner) => Owner::Diagnostic(owner.egress()),
            Self::Executable(owner) => owner.egress() }
    }
    pub(super) fn authority(&self) -> &attachment_authority::Authorization {
        match self { Self::Diagnostic(owner) => owner.authority(), Self::Executable(owner) => owner.authority() }
    }
    pub(super) fn check(&self) -> Result<(), String> { self.check_phase(Phase::Admission) }
    pub(super) fn check_phase(&self, phase: Phase) -> Result<(), String> {
        match (self, phase) {
            (Self::Diagnostic(owner), Phase::Admission) => owner.check(),
            (Self::Executable(owner), Phase::Admission) => owner.check(),
            (Self::Executable(owner), Phase::Continuation) => owner.check_running(),
            _ => Err("diagnostic attachment has no execution continuation permission".to_owned()),
        }
    }
    pub(super) fn deadline(&self, phase: Phase) -> Result<Instant, String> {
        self.check_phase(phase)?;
        self.egress().deadline(phase)
    }
}
