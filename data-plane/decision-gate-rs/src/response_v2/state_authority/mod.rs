//! Durable response-v2 state authority.
//!
//! This module is intentionally independent from the current response-v2
//! custody facade. It defines the closed contracts, PostgreSQL schema, and
//! mutation engine that the seven-process TrustedHostNoTee deployment can
//! dispatch to later.

pub mod canonical;
pub mod contract;
pub mod lifecycle;
pub mod postgres;
pub mod reconciliation;
pub mod rpc;
pub mod services;
pub mod topology;
#[path = "../transparency_contract.rs"]
pub mod transparency_contract;

pub use contract::{
    AuthorityError, AuthorityResult, BootClock, BootDeadline, BootInstant,
    CgroupObservation, CgroupObserver, CgroupOwner, Digest, Identifier,
    StateAuthorityConfiguration,
};
pub use lifecycle::{
    AttemptState, FenceState, OperationKind, OperationStatus,
    ReconciliationState, TargetEffectState,
};
pub use postgres::{
    ExactSignedResultBytes, ImmutableObjectStore, PgRow, PgValue,
    PostgresBackend, PostgresTransaction, StateAuthority,
};
pub use reconciliation::{
    ReadinessBlocker, ReadinessReport, ReconciliationDomain,
};
pub use rpc::{
    AuthorityArtifactBody, AuthorityResultSigner, AuthoritySignerIdentity,
    CanonicalFinalEnvelope, GenerationMutationPayload,
    GenerationRpcRequestFrame, MutationPayload, RpcRequestFrame,
    SignedAuthorityArtifact,
    SignedGenerationOperationResult, SignedOperationResult,
};
pub use services::{
    service_contract, service_contracts, ThinServiceContract,
};
pub use topology::{
    ProviderGeneration, QuorumProfile, RoleIdentity, ServiceRole,
    TrustedHostTopology,
};
