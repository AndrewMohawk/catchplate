"""Dedicated PostgreSQL storage for local, unanchored initialization records.

These declarations neither enroll a database nor admit initialization evidence.
An offline owner must provision the exact enrollment separately. The recorder
must validate canonical bytes and their domain-separated commitments, lock the
enrollment, and atomically join its head to the immutable candidate. SQL shape
checks are not signature verification, external anchoring or rollback proof.

The grant renderer is for these two source-owned tables. It removes direct
PUBLIC/runtime grants before granting the narrow reader/writer privileges; it
does not establish ownership, effective inherited privileges, database/schema
admission, independent administration or physical store separation.
"""
from __future__ import annotations

import re


ENROLLMENTS = "initialization_enrollments"
CANDIDATES = "initialization_candidates"
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_ENROLLMENT_BYTES = 16_384

_ENROLLMENT_COLUMNS = (
    "database_identity_digest", "enrollment_digest", "enrollment_bytes",
    "head_sequence", "head_digest",
)
_CANDIDATE_COLUMNS = (
    "database_identity_digest", "enrollment_digest", "request_digest",
    "candidate_digest", "candidate_bytes",
)


def _identifier(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise ValueError("initialization store identifier must be exact lowercase ASCII")
    return '"' + value + '"'


def _digest_check(column: str) -> str:
    # Column names are a fixed source inventory, not caller expressions.
    return (
        f"pg_catalog.octet_length({column}) = 71 AND "
        f"{column} COLLATE \"C\" ~ '^sha256:[0-9a-f]{{64}}$'"
    )


def audit_initialization_store_ddl(namespace: str) -> tuple[str, str]:
    """Render fresh tables only; never silently accept or repair an old schema.

    The stable database identity is the one-use key. Generation and the fixed
    global counter identity belong to canonical enrollment bytes, not a caller
    selected secondary key. No defaults manufacture an enrollment or head.
    Cross-table head/candidate correspondence remains the recorder's atomic
    transaction invariant; these declarations do not mark any record anchored.
    """
    schema = _identifier(namespace)
    enrollments = f'{schema}."{ENROLLMENTS}"'
    candidates = f'{schema}."{CANDIDATES}"'
    return (
        f"""CREATE TABLE {enrollments} (
            database_identity_digest pg_catalog.text PRIMARY KEY,
            enrollment_digest pg_catalog.text NOT NULL,
            enrollment_bytes pg_catalog.bytea NOT NULL,
            head_sequence pg_catalog.int8 NOT NULL,
            head_digest pg_catalog.text NOT NULL,
            UNIQUE (database_identity_digest, enrollment_digest),
            CHECK ({_digest_check('database_identity_digest')}),
            CHECK ({_digest_check('enrollment_digest')}),
            CHECK ({_digest_check('head_digest')}),
            CHECK (pg_catalog.octet_length(enrollment_bytes) BETWEEN 1 AND {MAX_ENROLLMENT_BYTES}),
            CHECK (head_sequence = 0 OR head_sequence = 1),
            CHECK (head_sequence <> 0 OR head_digest = enrollment_digest)
        );""",
        f"""CREATE TABLE {candidates} (
            database_identity_digest pg_catalog.text PRIMARY KEY,
            enrollment_digest pg_catalog.text NOT NULL,
            request_digest pg_catalog.text NOT NULL,
            candidate_digest pg_catalog.text NOT NULL,
            candidate_bytes pg_catalog.bytea NOT NULL,
            FOREIGN KEY (database_identity_digest, enrollment_digest)
                REFERENCES {enrollments} (database_identity_digest, enrollment_digest),
            CHECK ({_digest_check('database_identity_digest')}),
            CHECK ({_digest_check('enrollment_digest')}),
            CHECK ({_digest_check('request_digest')}),
            CHECK ({_digest_check('candidate_digest')}),
            CHECK (pg_catalog.octet_length(candidate_bytes) BETWEEN 1 AND {MAX_RECORD_BYTES})
        );""",
    )


def audit_initialization_store_grants(namespace: str, runtime_role: str) -> tuple[str, ...]:
    """Grant no enrollment INSERT, candidate UPDATE, DELETE, DDL or grant option.

    The enrollment's identity/bytes cannot be changed through these direct
    grants. Retained candidate bytes are append-only for this runtime role;
    owner/superuser power and rollback of the store remain outside this claim.
    No role or namespace is created, and unrelated schemas are untouched.
    """
    schema, role = _identifier(namespace), _identifier(runtime_role)
    enrollments = f'{schema}."{ENROLLMENTS}"'
    candidates = f'{schema}."{CANDIDATES}"'
    enrollment_columns = ", ".join(_ENROLLMENT_COLUMNS)
    candidate_columns = ", ".join(_CANDIDATE_COLUMNS)
    return (
        f"REVOKE ALL PRIVILEGES ON SCHEMA {schema} FROM PUBLIC, {role};",
        f"REVOKE ALL PRIVILEGES ON TABLE {enrollments}, {candidates} FROM PUBLIC, {role};",
        # Table-level REVOKE alone must not leave a pre-existing column grant.
        f"REVOKE ALL PRIVILEGES ({enrollment_columns}) ON TABLE {enrollments} FROM PUBLIC, {role};",
        f"REVOKE ALL PRIVILEGES ({candidate_columns}) ON TABLE {candidates} FROM PUBLIC, {role};",
        f"GRANT USAGE ON SCHEMA {schema} TO {role};",
        f"GRANT SELECT ON TABLE {enrollments}, {candidates} TO {role};",
        f"GRANT UPDATE (head_sequence, head_digest) ON TABLE {enrollments} TO {role};",
        f"GRANT INSERT ON TABLE {candidates} TO {role};",
    )
