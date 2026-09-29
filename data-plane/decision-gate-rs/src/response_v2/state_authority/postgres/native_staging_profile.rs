//! Explicit new, empty-database profile; no old row/fence reinterpretation.
use super::store::PgValue;
use super::super::{canonical::sha256_digest, contract::Digest};
pub const PROFILE:&str="native-staging-originals/v3";
pub const EXTENSION_SQL:&str=r#"
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM response_v2_state_authority.provider_generations)
       OR EXISTS (SELECT 1 FROM response_v2_state_authority.attempts)
       OR EXISTS (SELECT 1 FROM response_v2_state_authority.schema_metadata)
       OR EXISTS (SELECT 1 FROM response_v2_state_authority.attempt_request_originals) THEN
        RAISE EXCEPTION 'native staging requires a fresh database; no migration/backfill';
    END IF;
END $$;
ALTER TABLE response_v2_state_authority.schema_metadata
    DROP CONSTRAINT schema_metadata_schema_version_check;
ALTER TABLE response_v2_state_authority.schema_metadata
    ADD CONSTRAINT schema_metadata_schema_version_check CHECK (schema_version = 3);
CREATE TABLE response_v2_state_authority.native_staging_claims (
    generation_id text NOT NULL REFERENCES response_v2_state_authority.provider_generations(generation_id),
    attempt_id text NOT NULL,
    phase text NOT NULL CHECK (phase IN ('RESERVE','AUTHORIZE','STAGE')),
    original_sha256 text NOT NULL CHECK (original_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    session_sha256 text NOT NULL CHECK (session_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    canonical_request bytea NOT NULL CHECK (octet_length(canonical_request) BETWEEN 1 AND 196608),
    canonical_inputs bytea NOT NULL CHECK (octet_length(canonical_inputs) BETWEEN 1 AND 262144),
    PRIMARY KEY(generation_id,attempt_id,phase),
    UNIQUE(generation_id,original_sha256)
);
CREATE TABLE response_v2_state_authority.native_staging_results (
    generation_id text NOT NULL,
    attempt_id text NOT NULL,
    phase text NOT NULL,
    original_sha256 text NOT NULL,
    result_sha256 text NOT NULL CHECK (result_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    canonical_result bytea NOT NULL CHECK (octet_length(canonical_result) BETWEEN 1 AND 196608),
    PRIMARY KEY(generation_id,attempt_id,phase),
    UNIQUE(generation_id,result_sha256),
    FOREIGN KEY(generation_id,attempt_id,phase)
        REFERENCES response_v2_state_authority.native_staging_claims(generation_id,attempt_id,phase),
    FOREIGN KEY(generation_id,original_sha256)
        REFERENCES response_v2_state_authority.native_staging_claims(generation_id,original_sha256)
);
CREATE TRIGGER native_staging_claims_immutable BEFORE UPDATE OR DELETE
ON response_v2_state_authority.native_staging_claims FOR EACH ROW
EXECUTE FUNCTION response_v2_state_authority.reject_request_original_change();
CREATE TRIGGER native_staging_results_immutable BEFORE UPDATE OR DELETE
ON response_v2_state_authority.native_staging_results FOR EACH ROW
EXECUTE FUNCTION response_v2_state_authority.reject_request_original_change();
REVOKE ALL ON response_v2_state_authority.native_staging_claims FROM PUBLIC;
REVOKE ALL ON response_v2_state_authority.native_staging_results FROM PUBLIC;
"#;
pub fn bootstrap_sql()->String { format!("{}{}",super::sequence_originals::bootstrap_sql(),EXTENSION_SQL) }
pub fn migration_sha256()->Digest { sha256_digest(bootstrap_sql().as_bytes()) }
pub fn schema_metadata_parameters()->[PgValue;2] {
    [PgValue::U64(3),PgValue::Text(migration_sha256().0)]
}
