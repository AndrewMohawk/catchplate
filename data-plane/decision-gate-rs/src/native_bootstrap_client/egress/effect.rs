//! Actual single kernel transaction, retained original readback and completion.
//!
//! Only the genuine EgressGuard reaches this private path. The returned owner
//! borrows that guard and retains the backend plus both cooperative locks; it is
//! not a serializable permission to start a workload or enter another session.

use super::{backend::{Backend, ReplyOriginals}, kernel_reservation::{self, KernelClaimState},
    readback, reservation::Spec, wire::DumpKind, EgressGuard};
use std::path::PathBuf;

struct Snapshot {
    before: ReplyOriginals,
    dumps: [ReplyOriginals; 6],
    after: ReplyOriginals,
}

impl Snapshot {
    fn acquire(backend: &mut Backend<'_>, table: &str) -> Result<Self, String> {
        let before = backend.generation()?;
        let dumps = [backend.dump(DumpKind::Table, table)?, backend.dump(DumpKind::Chain, table)?,
            backend.dump(DumpKind::Rules, table)?, backend.dump(DumpKind::Set, table)?,
            backend.dump(DumpKind::Object, table)?, backend.dump(DumpKind::FlowTable, table)?];
        let after = backend.generation()?;
        Ok(Self { before, dumps, after })
    }

    fn references(&self) -> [&ReplyOriginals; 6] {
        [&self.dumps[0], &self.dumps[1], &self.dumps[2], &self.dumps[3], &self.dumps[4], &self.dumps[5]]
    }
}

/// Retains original guard, namespace/socket and both locks. Getters below are
/// historical local data; check() performs a fresh bounded read-only comparison
/// under the SAME original allowance. Nothing grants workload start authority.
pub(in super::super) struct Installed<'a> {
    guard: &'a EgressGuard,
    backend: Backend<'a>,
    semantic_sha256: [u8; 32],
    evidence_sha256: [u8; 32],
    created: bool,
    stopped: bool,
}

impl Installed<'_> {
    pub(in super::super) fn check(&mut self) -> Result<(), String> {
        super::ensure(!std::mem::replace(&mut self.stopped, true), "native installed egress owner stopped")?;
        self.guard.check()?;
        let snapshot = Snapshot::acquire(&mut self.backend, &self.guard.authorization.ruleset.table_name)?;
        let current = readback::verify(&self.guard.authorization.ruleset,
            &snapshot.before, snapshot.references(), &snapshot.after)?;
        super::ensure(current.semantic_sha256() == self.semantic_sha256,
            "native installed egress semantic state changed")?;
        self.guard.check()?;
        self.stopped = false;
        Ok(())
    }

    pub(in super::super) fn semantic_sha256(&self) -> [u8; 32] { self.semantic_sha256 }
    pub(in super::super) fn evidence_sha256(&self) -> [u8; 32] { self.evidence_sha256 }
    pub(in super::super) fn created(&self) -> bool { self.created }
}

pub(super) fn install(guard: &EgressGuard) -> Result<Installed<'_>, String> {
    guard.check()?;
    let grant = &guard.authorization;
    // The journal lock precedes the independent protected backend lock. Intent
    // is initially absent, not a caller-supplied success or transaction digest.
    let mut journal = kernel_reservation::open_kernel(Spec {
        journal_path: PathBuf::from(&grant.journal.path), journal_device: grant.journal.device,
        journal_inode: grant.journal.inode, reservation_id: guard.reservation_id,
        association_sha256: guard.association_sha256, token_sha256: guard.token_sha256,
        intended_transaction_sha256: [0; 32],
    }, guard)?;
    let mut backend = Backend::open(guard, &journal)?;

    if let Some(retained) = journal.retained_transaction().map(|raw| raw.to_vec()) {
        // A completed read-only check must not encode a new transaction using a
        // changed generation or sequence, and must never publish another claim.
        journal.reserve_transaction(&retained)?;
        let (semantic_sha256, evidence_sha256) = match journal.replay_completed()? {
            KernelClaimState::AlreadyComplete { semantic_sha256, evidence_sha256 } =>
                (semantic_sha256, evidence_sha256),
            KernelClaimState::Fresh => return Err("native completed replay cannot authorize an effect".to_owned()),
        };
        let snapshot = Snapshot::acquire(&mut backend, &grant.ruleset.table_name)?;
        let current = readback::verify(&grant.ruleset, &snapshot.before, snapshot.references(), &snapshot.after)?;
        super::ensure(current.semantic_sha256() == semantic_sha256,
            "native completed egress differs from actual current kernel state")?;
        journal.check()?;
        guard.check()?;
        return Ok(Installed { guard, backend, semantic_sha256, evidence_sha256,
            created: false, stopped: false });
    }

    let mut claimed = false;
    let mut observation_retained = false;
    let outcome = (|| -> Result<([u8; 32], [u8; 32]), String> {
        let before = Snapshot::acquire(&mut backend, &grant.ruleset.table_name)?;
        let generation = readback::verify_empty_namespace(&grant.ruleset,
            &before.before, before.references(), &before.after)?;
        let transaction = backend.transaction(&grant.ruleset, generation)?;
        journal.reserve_transaction(transaction.bytes())?;
        match journal.claim()? {
            KernelClaimState::Fresh => claimed = true,
            KernelClaimState::AlreadyComplete { .. } =>
                return Err("native fresh installation unexpectedly became completed".to_owned()),
        }
        // This method independently requires the actual journal Claimed owner
        // and exact original intent immediately before its one allowed send.
        let acknowledgment = backend.submit_once(&transaction, &journal)?;
        super::ensure(acknowledgment.request() == transaction.bytes(),
            "native kernel ACK owner has a different intended transaction")?;
        let after = Snapshot::acquire(&mut backend, &grant.ruleset.table_name)?;
        // Retain actual precheck/send-attempt/ACK/readback originals before
        // interpreting success. This raw record itself is not a kernel verdict.
        let evidence_sha256 = journal.observe(&backend.transcript_bytes()?)?;
        observation_retained = true;
        let current = readback::verify(&grant.ruleset, &after.before, after.references(), &after.after)?;
        journal.check()?;
        guard.check()?;
        Ok((current.semantic_sha256(), evidence_sha256))
    })();

    let (semantic_sha256, evidence_sha256) = match outcome {
        Ok(result) => result,
        Err(error) => {
            // Best-effort forensic custody only while the original guard still
            // allows it. No renewed authority, overwrite or repair follows a
            // hard kill, expired guard, partial write or incomplete observation.
            if claimed && !observation_retained {
                if let Ok(originals) = backend.transcript_bytes() { let _ = journal.observe(&originals); }
            }
            return Err(error);
        }
    };
    journal.complete(semantic_sha256)?;
    guard.check()?;
    // BackendLock owns duplicated protected directory handles, keeping both
    // cooperative locks live even after the completed journal owner is consumed.
    Ok(Installed { guard, backend, semantic_sha256, evidence_sha256, created: true, stopped: false })
}
