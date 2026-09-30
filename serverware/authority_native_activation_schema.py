"""Additive protected sidecars. No legacy Fleet row or envelope is synthesized."""
TABLES = ("policy_native_canary_ready", "policy_native_canary_heads", "policy_native_activation_preparations", "policy_native_activation_finalizations", "policy_native_activation_holds")


def source():
    return """
CREATE TABLE IF NOT EXISTS policy_native_activation_holds (
 scope TEXT PRIMARY KEY CHECK (scope = 'native-policy-publication'),
 phase TEXT NOT NULL CHECK (phase IN ('held','published')),
 canary_id TEXT NOT NULL,
 activation_id TEXT NOT NULL,
 prepared_sha256 TEXT NOT NULL,
 prepare_request_digest TEXT NOT NULL,
 configuration_digest TEXT NOT NULL,
 guard_sha256 TEXT NOT NULL,
 issued_at_epoch_ns BIGINT NOT NULL,
 expires_at_epoch_ns BIGINT NOT NULL,
 publication_sha256 TEXT,
 finalization_digest TEXT,
 CHECK (issued_at_epoch_ns > 0 AND expires_at_epoch_ns > issued_at_epoch_ns
    AND expires_at_epoch_ns - issued_at_epoch_ns <= 300000000000),
 CHECK (length(canary_id) BETWEEN 1 AND 256 AND length(activation_id) = 36),
 CHECK (length(prepared_sha256) = 71 AND length(prepare_request_digest) = 71
    AND length(configuration_digest) = 71 AND length(guard_sha256) = 71),
 CHECK ((phase = 'held' AND publication_sha256 IS NULL AND finalization_digest IS NULL)
    OR (phase = 'published' AND publication_sha256 IS NOT NULL AND finalization_digest IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS policy_native_canary_ready (
 canary_id TEXT PRIMARY KEY REFERENCES policy_canaries(canary_id),
 ready_revision BIGINT NOT NULL CHECK (ready_revision > 0 AND ready_revision < 9223372036854775807),
 ready_state_digest TEXT NOT NULL UNIQUE,
 readiness_request_id TEXT NOT NULL UNIQUE,
 readiness_record_sha256 TEXT NOT NULL,
 readiness_result_original TEXT NOT NULL,
 ready_original TEXT NOT NULL,
 configuration_digest TEXT NOT NULL,
 activation_policy_sha256 TEXT NOT NULL,
 transition_digest TEXT NOT NULL,
 created_at_epoch_ns BIGINT NOT NULL,
 expires_at_epoch_ns BIGINT NOT NULL,
 CHECK (created_at_epoch_ns > 0 AND expires_at_epoch_ns > created_at_epoch_ns),
 CHECK (length(readiness_result_original) BETWEEN 2 AND 262144),
 CHECK (length(ready_original) BETWEEN 2 AND 16384)
);
CREATE TABLE IF NOT EXISTS policy_native_activation_preparations (
 canary_id TEXT PRIMARY KEY REFERENCES policy_native_canary_ready(canary_id),
 activation_id TEXT NOT NULL UNIQUE,
 replay_id TEXT NOT NULL UNIQUE,
 approval_id TEXT NOT NULL UNIQUE REFERENCES control_plane_approvals(id),
 requester_id TEXT NOT NULL,
 prepared_original TEXT NOT NULL,
 prepared_sha256 TEXT NOT NULL UNIQUE,
 request_digest TEXT NOT NULL UNIQUE,
 audit_outbox_id TEXT NOT NULL UNIQUE,
 audit_event_digest TEXT NOT NULL,
 publication_original TEXT,
 publication_sha256 TEXT,
 publication_request_sha256 TEXT,
 publication_audit_id TEXT,
 publication_audit_digest TEXT,
 CHECK (activation_id <> replay_id AND length(prepared_original) BETWEEN 2 AND 1048576),
 CHECK (publication_original IS NULL OR length(publication_original) BETWEEN 2 AND 32768),
 CHECK ((publication_original IS NULL AND publication_sha256 IS NULL AND publication_request_sha256 IS NULL
   AND publication_audit_id IS NULL AND publication_audit_digest IS NULL)
  OR (publication_original IS NOT NULL AND publication_sha256 IS NOT NULL AND publication_request_sha256 IS NOT NULL
   AND publication_audit_id IS NOT NULL AND publication_audit_digest IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS policy_native_canary_heads (
 canary_id TEXT PRIMARY KEY REFERENCES policy_native_canary_ready(canary_id) DEFERRABLE INITIALLY DEFERRED,
 source_profile TEXT NOT NULL CHECK (source_profile = 'native-policy-activation/v1'),
 predecessor_revision BIGINT NOT NULL,
 predecessor_state_digest TEXT NOT NULL,
 head_revision BIGINT NOT NULL,
 head_state_digest TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('ready','active')),
 ready_state_digest TEXT NOT NULL,
 updated_at_epoch_ns BIGINT NOT NULL,
 CHECK (predecessor_revision > 0 AND head_revision > predecessor_revision AND updated_at_epoch_ns > 0)
);
CREATE TABLE IF NOT EXISTS policy_native_activation_finalizations (
 canary_id TEXT PRIMARY KEY REFERENCES policy_native_activation_preparations(canary_id),
 activation_id TEXT NOT NULL UNIQUE,
 prepared_sha256 TEXT NOT NULL UNIQUE,
 publication_sha256 TEXT NOT NULL UNIQUE,
 policy_id TEXT NOT NULL,
 policy_hash TEXT NOT NULL,
 policy_sequence BIGINT NOT NULL,
 rollback_epoch BIGINT NOT NULL,
 artifact_envelope_digest TEXT NOT NULL,
 activation_policy_original TEXT NOT NULL,
 audit_originals_json TEXT NOT NULL,
 finalization_original TEXT NOT NULL,
 finalization_digest TEXT NOT NULL UNIQUE,
 request_digest TEXT NOT NULL UNIQUE,
 audit_outbox_id TEXT NOT NULL UNIQUE,
 audit_event_digest TEXT NOT NULL,
 finalized_at_epoch_ns BIGINT NOT NULL,
 CHECK (policy_sequence > 0 AND rollback_epoch >= 0 AND finalized_at_epoch_ns > 0),
 CHECK (length(activation_policy_original) BETWEEN 2 AND 16384),
 CHECK (length(audit_originals_json) BETWEEN 2 AND 1048576 AND length(finalization_original) BETWEEN 2 AND 1048576)
);
"""
