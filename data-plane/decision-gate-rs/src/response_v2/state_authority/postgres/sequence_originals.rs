//! Explicit fresh-database profile. Never reinterpret or backfill old fences.
use super::super::{canonical::sha256_digest, contract::{AuthorityError, AuthorityResult, Digest}};
use super::store::{PgValue, PostgresTransaction};

pub const PROFILE: &str = "sequence-request-originals/v2";
// Three frame/result pairs plus their witness and service envelopes fit the
// existing 256 KiB custody transport. Do not widen that transport implicitly.
pub const MAX_ORIGINAL_BYTES: usize = 24 * 1024;
pub const REQUIRED_CUSTODY_FRAME_BYTES: usize = 256 * 1024;
pub const EXTENSION_SQL: &str = r#"
-- Fresh-only extension to the byte-identical v1 bootstrap DDL.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM response_v2_state_authority.provider_generations)
       OR EXISTS (SELECT 1 FROM response_v2_state_authority.attempts)
       OR EXISTS (SELECT 1 FROM response_v2_state_authority.operations)
       OR EXISTS (SELECT 1 FROM response_v2_state_authority.schema_metadata)
       OR (SELECT is_called FROM response_v2_state_authority.fence_allocation_sequence) THEN
        RAISE EXCEPTION 'sequence-originals requires a fresh empty database; no migration/backfill';
    END IF;
END $$;
ALTER TABLE response_v2_state_authority.schema_metadata
    DROP CONSTRAINT schema_metadata_schema_version_check;
ALTER TABLE response_v2_state_authority.schema_metadata
    ADD CONSTRAINT schema_metadata_schema_version_check CHECK (schema_version = 2);
ALTER TABLE response_v2_state_authority.attempts
    ADD CONSTRAINT attempt_sequence_fence CHECK (fence_token ~ '^[1-9][0-9]*$');
ALTER TABLE response_v2_state_authority.fences
    ADD CONSTRAINT exact_sequence_fence CHECK (allocation_sequence > 0 AND fence_token = allocation_sequence::text);
CREATE TABLE response_v2_state_authority.attempt_request_originals (
    generation_id text NOT NULL,
    attempt_id text NOT NULL,
    original_kind text NOT NULL CHECK (original_kind IN ('RESERVE', 'STAGE', 'DISPATCH_BEGIN')),
    operation_id text NOT NULL,
    exact_request_sha256 text NOT NULL CHECK (exact_request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    canonical_request_frame bytea NOT NULL CHECK (octet_length(canonical_request_frame) BETWEEN 1 AND 24576),
    PRIMARY KEY (generation_id, attempt_id, original_kind),
    UNIQUE (generation_id, operation_id),
    FOREIGN KEY (generation_id, attempt_id) REFERENCES response_v2_state_authority.attempts(generation_id, attempt_id),
    FOREIGN KEY (generation_id, operation_id) REFERENCES response_v2_state_authority.operations(generation_id, operation_id)
);
CREATE FUNCTION response_v2_state_authority.reject_request_original_change()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN RAISE EXCEPTION 'authenticated attempt request originals are immutable'; END;
$$;
CREATE TRIGGER request_originals_immutable BEFORE UPDATE OR DELETE
ON response_v2_state_authority.attempt_request_originals
FOR EACH ROW EXECUTE FUNCTION response_v2_state_authority.reject_request_original_change();
REVOKE ALL ON response_v2_state_authority.attempt_request_originals FROM PUBLIC;
REVOKE ALL ON FUNCTION response_v2_state_authority.reject_request_original_change() FROM PUBLIC;
"#;

pub fn bootstrap_sql() -> String { format!("{}{}", super::schema::BOOTSTRAP_SQL, EXTENSION_SQL) }
pub fn migration_sha256() -> Digest { sha256_digest(bootstrap_sql().as_bytes()) }

/// Provisioning-only metadata parameters, after the exact fresh DDL succeeds.
/// The runtime owner only reads this row; it never migrates or creates it.
pub fn schema_metadata_parameters() -> [PgValue; 2] {
    [PgValue::U64(2), PgValue::Text(migration_sha256().0)]
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Profile { LegacyV1, SequenceOriginalsV2, NativeStagingV3 }
impl Profile {
    pub fn retains_originals(self)->bool { matches!(self,Self::SequenceOriginalsV2|Self::NativeStagingV3) }
}
pub fn profile(pin: &Digest) -> AuthorityResult<Profile> {
    if pin == &sha256_digest(super::schema::BOOTSTRAP_SQL.as_bytes()) { Ok(Profile::LegacyV1) }
    else if pin == &migration_sha256() { Ok(Profile::SequenceOriginalsV2) }
    else if pin == &super::native_staging_profile::migration_sha256() { Ok(Profile::NativeStagingV3) }
    else { Err(AuthorityError::InvalidContract { field:"generation.migrationSha256",
        reason:"unknown explicitly pinned state database profile".into() }) }
}

pub fn require_database(transaction:&mut dyn PostgresTransaction, pin:&Digest) -> AuthorityResult<Profile> {
    let selected=profile(pin)?;
    if selected.retains_originals() {
        let row=transaction.query_optional(super::statements::LOCK_SCHEMA_METADATA_SQL,&[])?
            .ok_or_else(|| refused("explicit v2 schema metadata is absent"))?;
        let version=if selected==Profile::NativeStagingV3 {3} else {2};
        if row.require_u64("schema_version")?!=version || row.require_text("migration_sha256")?!=pin.0 {
            return Err(refused("actual database is not the independently selected originals profile"));
        }
    }
    Ok(selected)
}

pub fn canonical_fence(text:&str, allocation:u64) -> AuthorityResult<u64> {
    if allocation==0 || allocation>super::super::contract::MAX_SAFE_INTEGER || text!=allocation.to_string() {
        return Err(refused("fence is not its exact authoritative positive sequence; legacy hash fences cannot migrate"));
    }
    Ok(allocation)
}
pub(super) fn refused(message:&str)->AuthorityError { AuthorityError::InvalidContract {
    field:"sequenceRequestOriginals",reason:message.to_owned() } }

pub const INSERT_ORIGINAL_SQL:&str=r#"
INSERT INTO response_v2_state_authority.attempt_request_originals
(generation_id,attempt_id,original_kind,operation_id,exact_request_sha256,canonical_request_frame)
VALUES ($1,$2,$3,$4,$5,$6)
"#;
pub const SELECT_ORIGINAL_SQL:&str=r#"
SELECT original.canonical_request_frame, original.exact_request_sha256,
       operation.status, operation.canonical_signed_result, operation.canonical_signed_result_sha256,
       replay.canonical_signed_result AS replay_result, replay.canonical_signed_result_sha256 AS replay_result_sha256,
       replay.exact_request_sha256 AS replay_request_sha256
FROM response_v2_state_authority.attempt_request_originals AS original
JOIN response_v2_state_authority.operations AS operation
  ON operation.generation_id=original.generation_id AND operation.operation_id=original.operation_id
 AND operation.attempt_id=original.attempt_id AND operation.exact_request_sha256=original.exact_request_sha256
JOIN response_v2_state_authority.replay_ledger AS replay
  ON replay.generation_id=operation.generation_id AND replay.operation_id=operation.operation_id
 AND replay.replay_id=operation.request_id
WHERE original.generation_id=$1 AND original.attempt_id=$2 AND original.original_kind=$3
FOR SHARE OF original, operation, replay
"#;

pub(super) fn parameters(generation:&str,attempt:&str,kind:&str)->[PgValue;3] {
    [PgValue::Text(generation.into()),PgValue::Text(attempt.into()),PgValue::Text(kind.into())]
}
