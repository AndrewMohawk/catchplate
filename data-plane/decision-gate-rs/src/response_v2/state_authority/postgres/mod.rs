//! PostgreSQL authority boundary.
//!
//! `schema` and `statements` are closed SQL inputs. `store` implements the
//! lifecycle over a minimal adapter so this source does not choose a concrete
//! driver or expand the crate dependency surface.

pub mod schema;
pub mod statements;
pub mod store;
pub mod sequence_originals;
pub mod native_staging_profile;

pub use store::{
    ExactSignedResultBytes, ImmutableObjectStore, PgRow, PgValue,
    PostgresBackend, PostgresTransaction, StateAuthority,
};
