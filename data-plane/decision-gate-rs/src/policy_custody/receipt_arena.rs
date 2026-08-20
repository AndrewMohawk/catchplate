//! Fixed receipt-reference storage with explicit modeled-budget accounting.
//!
//! The property modeled here is exactly:
//! "32 MiB modeled receipt-reference and reconciliation reservation budget".
//! It is not a claim about allocator overhead, transient serialization,
//! application heap usage, process RSS, kernel memory, or cgroup enforcement.

use std::fmt;
use std::mem::size_of;

pub(crate) const MODELED_RECEIPT_REFERENCE_BUDGET_LABEL: &str =
    "32 MiB modeled receipt-reference and reconciliation reservation budget";
pub(crate) const MODELED_RECEIPT_REFERENCE_BUDGET_BYTES: usize =
    32 * 1024 * 1024;
const INLINE_RECEIPT_REFERENCE_KNOWN_FLAGS: u8 = 0;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct InlineSha256Digest([u8; 32]);

impl InlineSha256Digest {
    pub(crate) const ZERO: Self = Self([0; 32]);

    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn is_zero(self) -> bool {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, aa, ab, ac, ad, ae, af] =
            self.0;
        (a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p
            | q | r | s | t | u | v | w | x | y | z | aa | ab | ac | ad
            | ae | af)
            == 0
    }
}

impl fmt::Debug for InlineSha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InlineSha256Digest([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ReceiptReferenceKind {
    Spill = 1,
    Unavailable = 2,
    Reconciliation = 3,
    Cleanup = 4,
    EndpointConsumption = 5,
}

/// All variable-sized receipt bytes stay in immutable external storage. The
/// arena retains only fixed-width identities and retrieval bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct InlineReceiptReference {
    pub(crate) kind: ReceiptReferenceKind,
    pub(crate) flags: u8,
    pub(crate) reserved: [u8; 6],
    pub(crate) generation: u64,
    pub(crate) ordinal: u64,
    pub(crate) canonical_length: u64,
    pub(crate) operation_id_sha256: InlineSha256Digest,
    pub(crate) request_sha256: InlineSha256Digest,
    pub(crate) predecessor_sha256: InlineSha256Digest,
    pub(crate) receipt_sha256: InlineSha256Digest,
    pub(crate) retrieval_id_sha256: InlineSha256Digest,
    pub(crate) retrieval_proof_sha256: InlineSha256Digest,
}

impl InlineReceiptReference {
    pub(crate) fn validate(&self) -> Result<(), ReceiptArenaError> {
        if self.flags & !INLINE_RECEIPT_REFERENCE_KNOWN_FLAGS != 0
            || self.reserved != [0; 6]
            || self.generation == 0
            || self.ordinal == 0
            || self.canonical_length == 0
            || self.operation_id_sha256.is_zero()
            || self.request_sha256.is_zero()
            || self.predecessor_sha256.is_zero()
            || self.receipt_sha256.is_zero()
            || self.retrieval_id_sha256.is_zero()
            || self.retrieval_proof_sha256.is_zero()
        {
            return Err(ReceiptArenaError::InvalidReference);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceiptSlotHandle {
    index: u32,
    generation: u32,
}

impl ReceiptSlotHandle {
    pub(crate) const fn index(self) -> u32 {
        self.index
    }

    pub(crate) const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy)]
struct ReceiptSlot {
    generation: u32,
    occupied: bool,
    reference: InlineReceiptReference,
}

impl ReceiptSlot {
    const EMPTY_REFERENCE: InlineReceiptReference =
        InlineReceiptReference {
            kind: ReceiptReferenceKind::Spill,
            flags: 0,
            reserved: [0; 6],
            generation: 0,
            ordinal: 0,
            canonical_length: 0,
            operation_id_sha256: InlineSha256Digest::ZERO,
            request_sha256: InlineSha256Digest::ZERO,
            predecessor_sha256: InlineSha256Digest::ZERO,
            receipt_sha256: InlineSha256Digest::ZERO,
            retrieval_id_sha256: InlineSha256Digest::ZERO,
            retrieval_proof_sha256: InlineSha256Digest::ZERO,
        };

    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        reference: Self::EMPTY_REFERENCE,
    };
}

/// A fixed-capacity slab. It allocates once at construction and never grows.
/// This controls reference cardinality, not allocator or process memory.
pub(super) struct FixedReceiptReferenceSlab {
    slots: Box<[ReceiptSlot]>,
    free_stack: Box<[u32]>,
    free_length: usize,
    occupied: usize,
}

impl FixedReceiptReferenceSlab {
    fn try_new(capacity: usize) -> Result<Self, ReceiptArenaError> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return Err(ReceiptArenaError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| ReceiptArenaError::AllocationFailed)?;
        slots.resize(capacity, ReceiptSlot::EMPTY);
        if slots.capacity() != capacity {
            return Err(ReceiptArenaError::NonExactAllocation);
        }

        let mut free_stack = Vec::new();
        free_stack
            .try_reserve_exact(capacity)
            .map_err(|_| ReceiptArenaError::AllocationFailed)?;
        for index in (0..capacity).rev() {
            free_stack.push(
                u32::try_from(index)
                    .map_err(|_| ReceiptArenaError::InvalidCapacity)?,
            );
        }
        if free_stack.capacity() != capacity {
            return Err(ReceiptArenaError::NonExactAllocation);
        }

        Ok(Self {
            slots: slots.into_boxed_slice(),
            free_stack: free_stack.into_boxed_slice(),
            free_length: capacity,
            occupied: 0,
        })
    }

    fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn len(&self) -> usize {
        self.occupied
    }

    fn is_empty(&self) -> bool {
        self.occupied == 0
    }

    fn modeled_dynamic_allocation_bytes(
        &self,
    ) -> Result<usize, ReceiptArenaError> {
        self.slots
            .len()
            .checked_mul(size_of::<ReceiptSlot>())
            .and_then(|slot_bytes| {
                self.free_stack
                    .len()
                    .checked_mul(size_of::<u32>())
                    .and_then(|stack_bytes| {
                        slot_bytes.checked_add(stack_bytes)
                    })
            })
            .ok_or(ReceiptArenaError::AccountingOverflow)
    }

    fn insert(
        &mut self,
        reference: InlineReceiptReference,
    ) -> Result<ReceiptSlotHandle, ReceiptArenaError> {
        reference.validate()?;
        if self.free_length == 0 {
            return Err(ReceiptArenaError::SlabFull);
        }
        let next_free_length = self
            .free_length
            .checked_sub(1)
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        let raw_index = *self
            .free_stack
            .get(next_free_length)
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        let index = usize::try_from(raw_index)
            .map_err(|_| ReceiptArenaError::CorruptSlab)?;
        let slot = self
            .slots
            .get(index)
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        if slot.occupied {
            return Err(ReceiptArenaError::CorruptSlab);
        }
        let next_occupied = self
            .occupied
            .checked_add(1)
            .ok_or(ReceiptArenaError::AccountingOverflow)?;
        let handle = ReceiptSlotHandle {
            index: u32::try_from(index)
                .map_err(|_| ReceiptArenaError::CorruptSlab)?,
            generation: slot.generation,
        };

        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        slot.occupied = true;
        slot.reference = reference;
        self.free_length = next_free_length;
        self.occupied = next_occupied;
        Ok(handle)
    }

    fn get(
        &self,
        handle: ReceiptSlotHandle,
    ) -> Result<&InlineReceiptReference, ReceiptArenaError> {
        let slot = self
            .slots
            .get(handle.index as usize)
            .ok_or(ReceiptArenaError::StaleHandle)?;
        if !slot.occupied || slot.generation != handle.generation {
            return Err(ReceiptArenaError::StaleHandle);
        }
        Ok(&slot.reference)
    }

    fn remove(
        &mut self,
        handle: ReceiptSlotHandle,
    ) -> Result<InlineReceiptReference, ReceiptArenaError> {
        let slot = self
            .slots
            .get_mut(handle.index as usize)
            .ok_or(ReceiptArenaError::StaleHandle)?;
        if !slot.occupied || slot.generation != handle.generation {
            return Err(ReceiptArenaError::StaleHandle);
        }
        let next_generation = slot
            .generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ReceiptArenaError::GenerationExhausted)?;
        let next_occupied = self
            .occupied
            .checked_sub(1)
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        let next_free_length = self
            .free_length
            .checked_add(1)
            .filter(|length| *length <= self.free_stack.len())
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        self.free_stack
            .get(self.free_length)
            .ok_or(ReceiptArenaError::CorruptSlab)?;
        let free = &mut self.free_stack[self.free_length];
        let removed = slot.reference;
        slot.reference = ReceiptSlot::EMPTY_REFERENCE;
        slot.occupied = false;
        slot.generation = next_generation;
        *free = handle.index;
        self.free_length = next_free_length;
        self.occupied = next_occupied;
        Ok(removed)
    }

    fn iter(
        &self,
    ) -> impl Iterator<Item = (ReceiptSlotHandle, &InlineReceiptReference)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.occupied.then_some((
                    ReceiptSlotHandle {
                        index: index as u32,
                        generation: slot.generation,
                    },
                    &slot.reference,
                ))
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeledReservationKind {
    ReceiptReference,
    Reconciliation,
    EndpointEvidence,
    Compaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModeledReservationToken {
    slot: u16,
    generation: u32,
    bytes: usize,
    kind: ModeledReservationKind,
}

#[derive(Debug, Clone, Copy)]
struct ReservationSlot {
    generation: u32,
    occupied: bool,
    bytes: usize,
    kind: ModeledReservationKind,
}

impl ReservationSlot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        bytes: 0,
        kind: ModeledReservationKind::ReceiptReference,
    };
}

/// Accounting for the declared model only. A reservation says that the model
/// has budget for an operation; it does not reserve allocator pages or enforce
/// RSS.
pub(super) struct ModeledReceiptReservationBudget<const RESERVATIONS: usize> {
    modeled_fixed_bytes: usize,
    modeled_reserved_bytes: usize,
    reservations: [ReservationSlot; RESERVATIONS],
}

impl<const RESERVATIONS: usize>
    ModeledReceiptReservationBudget<RESERVATIONS>
{
    fn try_new(
        modeled_fixed_bytes: usize,
    ) -> Result<Self, ReceiptArenaError> {
        if RESERVATIONS == 0
            || RESERVATIONS > u16::MAX as usize
            || modeled_fixed_bytes
                > MODELED_RECEIPT_REFERENCE_BUDGET_BYTES
        {
            return Err(ReceiptArenaError::InvalidCapacity);
        }
        Ok(Self {
            modeled_fixed_bytes,
            modeled_reserved_bytes: 0,
            reservations: [ReservationSlot::EMPTY; RESERVATIONS],
        })
    }

    fn label(&self) -> &'static str {
        MODELED_RECEIPT_REFERENCE_BUDGET_LABEL
    }

    fn modeled_fixed_bytes(&self) -> usize {
        self.modeled_fixed_bytes
    }

    fn modeled_reserved_bytes(&self) -> usize {
        self.modeled_reserved_bytes
    }

    fn modeled_remaining_bytes(&self) -> usize {
        MODELED_RECEIPT_REFERENCE_BUDGET_BYTES
            .saturating_sub(self.modeled_fixed_bytes)
            .saturating_sub(self.modeled_reserved_bytes)
    }

    fn reserve(
        &mut self,
        kind: ModeledReservationKind,
        bytes: usize,
    ) -> Result<ModeledReservationToken, ReceiptArenaError> {
        if bytes == 0 || bytes > self.modeled_remaining_bytes() {
            return Err(ReceiptArenaError::ModeledBudgetExceeded);
        }
        let slot_index = self
            .reservations
            .iter()
            .enumerate()
            .find(|(_, slot)| !slot.occupied)
            .map(|(index, _)| index)
            .ok_or(ReceiptArenaError::ReservationTableFull)?;
        let token_slot = u16::try_from(slot_index)
            .map_err(|_| ReceiptArenaError::ReservationTableFull)?;
        let next_reserved_bytes = self
            .modeled_reserved_bytes
            .checked_add(bytes)
            .ok_or(ReceiptArenaError::AccountingOverflow)?;
        let slot = self
            .reservations
            .get_mut(slot_index)
            .ok_or(ReceiptArenaError::ReservationTableFull)?;
        let token = ModeledReservationToken {
            slot: token_slot,
            generation: slot.generation,
            bytes,
            kind,
        };
        slot.occupied = true;
        slot.bytes = bytes;
        slot.kind = kind;
        self.modeled_reserved_bytes = next_reserved_bytes;
        Ok(token)
    }

    fn release(
        &mut self,
        token: ModeledReservationToken,
    ) -> Result<(), ReceiptArenaError> {
        let slot = self
            .reservations
            .get_mut(token.slot as usize)
            .ok_or(ReceiptArenaError::StaleReservation)?;
        if !slot.occupied
            || slot.generation != token.generation
            || slot.bytes != token.bytes
            || slot.kind != token.kind
        {
            return Err(ReceiptArenaError::StaleReservation);
        }
        let next_reserved_bytes = self
            .modeled_reserved_bytes
            .checked_sub(slot.bytes)
            .ok_or(ReceiptArenaError::AccountingOverflow)?;
        let next_generation = slot
            .generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(ReceiptArenaError::GenerationExhausted)?;
        self.modeled_reserved_bytes = next_reserved_bytes;
        slot.occupied = false;
        slot.bytes = 0;
        slot.generation = next_generation;
        Ok(())
    }
}

/// The sole modeled-accounting constructor joins the fixed slab and
/// reconciliation reservation table. Callers cannot supply or understate the
/// baseline byte count.
pub(crate) struct ModeledReceiptArena<const RESERVATIONS: usize> {
    slab: FixedReceiptReferenceSlab,
    budget: ModeledReceiptReservationBudget<RESERVATIONS>,
    available: bool,
}

impl<const RESERVATIONS: usize> ModeledReceiptArena<RESERVATIONS> {
    pub(crate) fn try_new(
        reference_capacity: usize,
    ) -> Result<Self, ReceiptArenaError> {
        let modeled_fixed_bytes =
            Self::complete_modeled_fixed_bytes(reference_capacity)?;
        if modeled_fixed_bytes
            > MODELED_RECEIPT_REFERENCE_BUDGET_BYTES
        {
            return Err(ReceiptArenaError::ModeledBudgetExceeded);
        }
        let slab =
            FixedReceiptReferenceSlab::try_new(reference_capacity)?;
        let observed_modeled_fixed_bytes = slab
            .modeled_dynamic_allocation_bytes()?
            .checked_add(size_of::<Self>())
            .ok_or(ReceiptArenaError::AccountingOverflow)?;
        if observed_modeled_fixed_bytes != modeled_fixed_bytes {
            return Err(ReceiptArenaError::AccountingDrift);
        }
        let budget =
            ModeledReceiptReservationBudget::try_new(
                modeled_fixed_bytes,
            )?;
        Ok(Self {
            slab,
            budget,
            available: true,
        })
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            slab: FixedReceiptReferenceSlab {
                slots: Vec::new().into_boxed_slice(),
                free_stack: Vec::new().into_boxed_slice(),
                free_length: 0,
                occupied: 0,
            },
            budget: ModeledReceiptReservationBudget {
                modeled_fixed_bytes: 0,
                modeled_reserved_bytes: 0,
                reservations: [ReservationSlot::EMPTY; RESERVATIONS],
            },
            available: false,
        }
    }

    fn complete_modeled_fixed_bytes(
        reference_capacity: usize,
    ) -> Result<usize, ReceiptArenaError> {
        if reference_capacity == 0
            || reference_capacity > u32::MAX as usize
            || RESERVATIONS == 0
            || RESERVATIONS > u16::MAX as usize
        {
            return Err(ReceiptArenaError::InvalidCapacity);
        }
        let reservation_table_bytes = RESERVATIONS
            .checked_mul(size_of::<ReservationSlot>())
            .ok_or(ReceiptArenaError::AccountingOverflow)?;
        let arena_fixed_overhead_bytes = size_of::<Self>()
            .checked_sub(reservation_table_bytes)
            .ok_or(ReceiptArenaError::AccountingOverflow)?;
        reference_capacity
            .checked_mul(size_of::<ReceiptSlot>())
            .and_then(|slot_bytes| {
                reference_capacity
                    .checked_mul(size_of::<u32>())
                    .and_then(|free_stack_bytes| {
                        slot_bytes.checked_add(free_stack_bytes)
                    })
            })
            .and_then(|dynamic_bytes| {
                dynamic_bytes.checked_add(reservation_table_bytes)
            })
            .and_then(|modeled_bytes| {
                modeled_bytes.checked_add(arena_fixed_overhead_bytes)
            })
            .ok_or(ReceiptArenaError::AccountingOverflow)
    }

    pub(crate) fn label(&self) -> &'static str {
        self.budget.label()
    }

    pub(crate) fn is_available(&self) -> bool {
        self.available
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slab.capacity()
    }

    pub(crate) fn len(&self) -> usize {
        self.slab.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.slab.is_empty()
    }

    pub(crate) fn modeled_fixed_bytes(&self) -> usize {
        self.budget.modeled_fixed_bytes()
    }

    pub(crate) fn modeled_reserved_bytes(&self) -> usize {
        self.budget.modeled_reserved_bytes()
    }

    pub(crate) fn modeled_remaining_bytes(&self) -> usize {
        self.budget.modeled_remaining_bytes()
    }

    pub(crate) fn insert(
        &mut self,
        reference: InlineReceiptReference,
    ) -> Result<ReceiptSlotHandle, ReceiptArenaError> {
        if !self.available {
            return Err(ReceiptArenaError::Unavailable);
        }
        self.slab.insert(reference)
    }

    pub(crate) fn get(
        &self,
        handle: ReceiptSlotHandle,
    ) -> Result<&InlineReceiptReference, ReceiptArenaError> {
        if !self.available {
            return Err(ReceiptArenaError::Unavailable);
        }
        self.slab.get(handle)
    }

    pub(crate) fn remove(
        &mut self,
        handle: ReceiptSlotHandle,
    ) -> Result<InlineReceiptReference, ReceiptArenaError> {
        if !self.available {
            return Err(ReceiptArenaError::Unavailable);
        }
        self.slab.remove(handle)
    }

    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (ReceiptSlotHandle, &InlineReceiptReference)> {
        self.slab.iter()
    }

    pub(crate) fn reserve(
        &mut self,
        kind: ModeledReservationKind,
        bytes: usize,
    ) -> Result<ModeledReservationToken, ReceiptArenaError> {
        if !self.available {
            return Err(ReceiptArenaError::Unavailable);
        }
        self.budget.reserve(kind, bytes)
    }

    pub(crate) fn release(
        &mut self,
        token: ModeledReservationToken,
    ) -> Result<(), ReceiptArenaError> {
        if !self.available {
            return Err(ReceiptArenaError::Unavailable);
        }
        self.budget.release(token)
    }
}

/// Declarative requirements for a future cache process that can make a real
/// memory-limit claim. Constructing this value does not provision or verify
/// the process, cgroup, kernel, launcher, or allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DedicatedCacheProcessContract {
    pub(super) memory_max_bytes: u64,
    pub(super) memory_swap_max_bytes: u64,
    pub(super) memory_oom_group: bool,
    pub(super) no_fallback_fixed_arena: bool,
    pub(super) separate_process: bool,
    pub(super) cgroup_v2_required: bool,
    pub(super) process_measurement_sha256: InlineSha256Digest,
    pub(super) allocator_configuration_sha256: InlineSha256Digest,
    pub(super) cgroup_configuration_sha256: InlineSha256Digest,
}

impl DedicatedCacheProcessContract {
    pub(super) fn validate_declaration(
        &self,
    ) -> Result<(), ReceiptArenaError> {
        if self.memory_max_bytes
                != MODELED_RECEIPT_REFERENCE_BUDGET_BYTES as u64
            || self.memory_swap_max_bytes != 0
            || !self.memory_oom_group
            || !self.no_fallback_fixed_arena
            || !self.separate_process
            || !self.cgroup_v2_required
            || self.process_measurement_sha256.is_zero()
            || self.allocator_configuration_sha256.is_zero()
            || self.cgroup_configuration_sha256.is_zero()
        {
            return Err(ReceiptArenaError::InvalidEnforcementContract);
        }
        Ok(())
    }

    pub(super) const fn enforcement_is_implemented_here(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptArenaError {
    Unavailable,
    InvalidCapacity,
    AllocationFailed,
    NonExactAllocation,
    InvalidReference,
    SlabFull,
    CorruptSlab,
    StaleHandle,
    GenerationExhausted,
    AccountingOverflow,
    AccountingDrift,
    ModeledBudgetExceeded,
    ReservationTableFull,
    StaleReservation,
    InvalidEnforcementContract,
}

impl fmt::Display for ReceiptArenaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "receipt arena is unavailable",
            Self::InvalidCapacity => "receipt arena capacity is invalid",
            Self::AllocationFailed => "receipt arena allocation failed",
            Self::NonExactAllocation => {
                "receipt arena allocation was not exact"
            }
            Self::InvalidReference => {
                "receipt reference is invalid or incomplete"
            }
            Self::SlabFull => "receipt reference slab is full",
            Self::CorruptSlab => "receipt reference slab is inconsistent",
            Self::StaleHandle => "receipt reference handle is stale",
            Self::GenerationExhausted => {
                "receipt slot generation is exhausted"
            }
            Self::AccountingOverflow => {
                "receipt reservation accounting overflowed"
            }
            Self::AccountingDrift => {
                "receipt arena modeled accounting drifted"
            }
            Self::ModeledBudgetExceeded => {
                "modeled receipt reservation budget exceeded"
            }
            Self::ReservationTableFull => {
                "receipt reservation table is full"
            }
            Self::StaleReservation => {
                "receipt reservation token is stale"
            }
            Self::InvalidEnforcementContract => {
                "dedicated cache-process contract is incomplete"
            }
        })
    }
}

impl std::error::Error for ReceiptArenaError {}
