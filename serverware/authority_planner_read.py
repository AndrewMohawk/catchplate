"""Source-owned native read primitives without planner registration.

These are the existing planner's sole identity, catalog and trace bodies,
not alternate operation admission. They can describe and authenticate bounded
reads only under the caller's original transaction, configuration and work.
A trace, loaded source manifest or valid database credential is not permission
to plan, sign, execute or dispatch an operation.

The public planner directly reexports these exact objects and retains its
complete registry, configured-program and request-admission gates. Native
component callers still need independently admitted roots/currentness,
request authority and deadlines; this module opens no connection or ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from serverware import authority_complete_query
from serverware import authority_contract
from serverware import authority_index_heads
from serverware import authority_index_reader
from serverware import authority_index_trace
from serverware import authority_primary_contract
from serverware import authority_revocation_roots as roots
from serverware import authority_transition_webauthn_completion
from serverware.authority_audit_trace import (
    AuditTraceBudget, AuditTraceError, MAX_PLAN_TRACE_ENTRIES,
)
from serverware.authority_request_commitment import AuthorityPlannerError


# The source-admission reservation retains its original module references.
authority = authority_contract


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AuthorityPlannerError(f"{label} is not a canonical digest")
    return value


@dataclass(frozen=True, slots=True)
class PlannerIdentity:
    database_role: str
    tls_client_dn: str
    tls_client_serial: str
    tls_issuer_dn: str
    session_identity_digest: str
    measurement_digest: str
    attestation_receipt_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PlannerIdentity":
        required = {
            "databaseRole",
            "tlsClientDn",
            "tlsClientSerial",
            "tlsIssuerDn",
            "sessionIdentityDigest",
            "measurementDigest",
            "attestationReceiptDigest",
        }
        if (
            set(value) != required
            or any(
                not isinstance(value[field], str) or not value[field]
                for field in (
                    "databaseRole",
                    "tlsClientDn",
                    "tlsClientSerial",
                    "tlsIssuerDn",
                )
            )
        ):
            raise AuthorityPlannerError("planner identity is not closed")
        for field in (
            "sessionIdentityDigest",
            "measurementDigest",
            "attestationReceiptDigest",
        ):
            _require_digest(value[field], f"planner {field}")
        return cls(
            database_role=value["databaseRole"],
            tls_client_dn=value["tlsClientDn"],
            tls_client_serial=value["tlsClientSerial"],
            tls_issuer_dn=value["tlsIssuerDn"],
            session_identity_digest=value["sessionIdentityDigest"],
            measurement_digest=value["measurementDigest"],
            attestation_receipt_digest=value["attestationReceiptDigest"],
        )


class PlannerTrace:
    def __init__(self, *, operation: str, _complete_queries: bool = False,
                 _counted_writes: bool = False, _challenge_successor: bool = False,
                 _recovery_successor: bool = False, _jit_successor: bool = False) -> None:
        if (type(_complete_queries) is not bool
                or _complete_queries and operation not in (authority_complete_query.OPERATION,
                    authority_complete_query.REGISTRATION_OPERATION, authority_complete_query.STAGE_OPERATION,
                    authority_complete_query.ACTIVATION_OPERATION, authority_complete_query.DELIVERY_OPERATION)
                or type(_counted_writes) is not bool
                or _counted_writes and (operation != authority_transition_webauthn_completion.OPERATION
                                       or _complete_queries)
                or type(_challenge_successor) is not bool
                or _challenge_successor and (operation not in authority_index_heads.CHALLENGE_OPERATIONS
                                             or _complete_queries or _counted_writes)
                or type(_recovery_successor) is not bool
                or _recovery_successor and (operation not in (*authority_index_heads.RECOVERY_HISTORY_OPERATIONS,
                    "webauthn.recovery.invalidate")
                    or _complete_queries or _counted_writes or _challenge_successor)
                or type(_jit_successor) is not bool
                or _jit_successor and (operation != authority_index_heads.JIT_RECEIPT_OPERATION
                    or _complete_queries or _counted_writes or _challenge_successor or _recovery_successor)):
            raise AuthorityPlannerError("complete trace scope is not source admitted")
        spec = authority_contract.operation_spec(operation)
        self.operation = operation
        self._complete_queries = _complete_queries
        self._counted_writes = _counted_writes
        # Only the separate source-fixed challenge owner requests this scope.
        # The public v3 planner still constructs the default-deny trace.
        self._challenge_successor = _challenge_successor
        self._recovery_successor = _recovery_successor
        self._jit_successor = _jit_successor
        self.business_reads = frozenset(
            set(spec["businessReads"]) | set(spec["businessWrites"])
        )
        self.selection_reads = frozenset(
            set(self.business_reads) | set(spec["authorizationReads"])
        )
        self.business_writes = frozenset(spec["businessWrites"])
        self.allowed_reads = frozenset(
            set(self.business_reads)
            | set(spec["authorizationReads"])
            | set(spec["frameworkPreconditions"])
            | set(spec["frameworkWrites"])
            | ({authority_index_heads.HEAD_TABLE, authority_index_reader.LEAF_TABLE,
                authority_index_reader.NODE_TABLE}
               if _complete_queries or _counted_writes or _challenge_successor or _recovery_successor
                   or _jit_successor else set())
        )
        self.allowed_writes = frozenset(
            set(spec["businessWrites"]) | set(spec["frameworkWrites"])
        )
        self._entries: list[dict[str, Any]] = []
        self._budget = AuditTraceBudget(operation)

    def read(self, table: str, key: Mapping[str, Any] | None) -> None:
        if table not in self.allowed_reads:
            raise AuthorityPlannerError(
                "planner read escaped the generated operation manifest"
            )
        if (isinstance(key, Mapping)
                and key.get("profile") == "serverware.policyAuthorityJitPrimaryChunkRead/v1"):
            if self._jit_successor is not True:
                raise AuthorityPlannerError("JIT chunk trace has no private source admission")
            from serverware import authority_jit_primary_chunk_reader
            try:
                authority_jit_primary_chunk_reader.validate_chunk_read_trace(self.operation, table, key)
            except (authority_index_reader.IndexReadError, UnicodeError) as exc:
                raise AuthorityPlannerError("JIT chunk trace differs from its fixed source query") from exc
        elif (table in {authority_index_heads.HEAD_TABLE, authority_index_reader.LEAF_TABLE,
                      authority_index_reader.NODE_TABLE}
                or isinstance(key, Mapping) and key.get("profile") in {
                    authority_index_trace.PRIMARY_READ_PROFILE,
                    "serverware.policyAuthorityChallengePrimaryRead/v1",
                    authority_index_trace.RECOVERY_HISTORY_PRIMARY_READ_PROFILE}):
            if not any((self._complete_queries, self._counted_writes,
                        self._challenge_successor, self._recovery_successor, self._jit_successor)):
                raise AuthorityPlannerError("complete trace profile has no current planner admission")
            try:
                if (type(key) is dict
                        and key.get("profile") == authority_index_trace.MUTATION_READ_PROFILE):
                    authority_index_trace.validate_mutation_read_trace(self.operation, table, key)
                elif self._challenge_successor:
                    if table == authority_index_heads.HEAD_TABLE:
                        authority_index_heads.validate_head_trace_key(
                            self.operation, key, include_write_heads=True)
                    elif type(key) is dict and key.get("profile") == authority_index_trace.COUNT_READ_PROFILE:
                        authority_index_trace.validate_count_read_trace(self.operation, table, key)
                    else:
                        authority_index_trace.validate_challenge_read_trace(self.operation, table, key)
                elif self._recovery_successor:
                    if table == authority_index_heads.HEAD_TABLE:
                        authority_index_heads.validate_head_trace_key(
                            self.operation, key, include_write_heads=True)
                    else:
                        authority_index_trace.validate_recovery_history_read_trace(self.operation, table, key)
                elif self._counted_writes or self._jit_successor:
                    if table != authority_index_heads.HEAD_TABLE:
                        raise AuthorityPlannerError("completion trace cannot admit complete-range reads")
                    authority_index_heads.validate_head_trace_key(
                        self.operation, key, include_write_heads=True)
                else:
                    authority_index_trace.validate_complete_read_trace(self.operation, table, key)
            except (authority_index_trace.IndexTraceError, authority_index_heads.IndexHeadReadError) as exc:
                raise AuthorityPlannerError("complete trace read is not source closed") from exc
        self._append("read", table, key)

    def write(self, table: str, key: Mapping[str, Any]) -> None:
        if table not in self.allowed_writes:
            raise AuthorityPlannerError(
                "planner write escaped the generated operation manifest"
            )
        self._append("write", table, key)

    def _append(
        self,
        access: str,
        table: str,
        key: Mapping[str, Any] | None,
    ) -> None:
        if len(self._entries) >= MAX_PLAN_TRACE_ENTRIES:
            raise AuthorityPlannerError("planner trace bound was exceeded")
        entry = {
            "ordinal": len(self._entries),
            "access": access,
            "table": table,
            "key": None if key is None else dict(key),
        }
        try:
            self._budget.append(entry)
        except AuditTraceError as exc:
            raise AuthorityPlannerError(str(exc)) from exc
        self._entries.append(entry)

    def close(
        self,
        *,
        selected_rows: tuple[dict[str, Any], ...],
        mutation_plan: tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        for selected in selected_rows:
            table = str(selected["table"])
            if table not in self.selection_reads:
                raise AuthorityPlannerError(
                    "selected row escaped the generated selection manifest"
                )
            if not isinstance(selected.get("key"), Mapping):
                raise AuthorityPlannerError(
                    "selected row key is not exact"
                )
        for mutation in mutation_plan:
            table = str(mutation["table"])
            if table not in self.business_writes:
                raise AuthorityPlannerError(
                    "planned mutation escaped the generated business writes"
                )
            if not isinstance(mutation.get("key"), Mapping):
                raise AuthorityPlannerError(
                    "planned mutation key is not exact"
                )
        try:
            self._budget.close(mutation_plan)
        except AuditTraceError as exc:
            raise AuthorityPlannerError(str(exc)) from exc
        return tuple(dict(entry) for entry in self._entries)


def _validate_database_identity(
    cursor: Any,
    identity: PlannerIdentity,
) -> None:
    row = cursor.execute(
        "SELECT current_user AS role, ssl.ssl, ssl.client_dn, "
        "ssl.client_serial::text AS client_serial, ssl.issuer_dn, "
        "role_record.rolsuper, role_record.rolcreaterole, "
        "role_record.rolcreatedb, role_record.rolreplication, "
        "role_record.rolbypassrls, "
        "pg_catalog.has_schema_privilege("
        "current_user, 'serverware_metadata', 'CREATE') AS schema_create, "
        "pg_catalog.has_database_privilege("
        "current_user, pg_catalog.current_database(), 'CREATE') "
        "AS database_create, "
        "pg_catalog.has_database_privilege("
        "current_user, pg_catalog.current_database(), 'TEMPORARY') "
        "AS database_temporary "
        "FROM pg_catalog.pg_stat_ssl AS ssl "
        "JOIN pg_catalog.pg_roles AS role_record "
        "ON role_record.oid = current_user::pg_catalog.regrole::oid "
        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
    ).fetchone()
    if (
        row is None
        or row["role"] != identity.database_role
        or not bool(row["ssl"])
        or row["client_dn"] != identity.tls_client_dn
        or row["client_serial"] != identity.tls_client_serial
        or row["issuer_dn"] != identity.tls_issuer_dn
        or any(
            bool(row[field])
            for field in (
                "rolsuper",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
                "schema_create",
                "database_create",
                "database_temporary",
            )
        )
    ):
        raise AuthorityPlannerError(
            "planner PostgreSQL identity is not exact"
        )
    mutation = cursor.execute(
        "SELECT 1 FROM pg_catalog.pg_class AS relation "
        "JOIN pg_catalog.pg_namespace AS namespace "
        "ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'serverware_metadata' "
        "AND relation.relkind IN ('r', 'p', 'S') "
        "AND ((relation.relkind IN ('r', 'p') AND "
        "pg_catalog.has_table_privilege(current_user, relation.oid, "
        "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) "
        "OR (relation.relkind = 'S' AND "
        "pg_catalog.has_sequence_privilege("
        "current_user, relation.oid, 'USAGE,UPDATE'))) LIMIT 1"
    ).fetchone()
    if mutation is not None:
        raise AuthorityPlannerError(
            "read-only planner credential has mutation authority"
        )


def _load_manifest(
    cursor: Any,
    *,
    operation: str,
    trace: PlannerTrace,
) -> tuple[tuple[dict[str, Any], ...], str]:
    trace.read(
        "policy_authority_query_dependency_manifests",
        {"operation": operation},
    )
    spec = authority_contract.operation_spec(operation)
    expected_count = len(set(spec["businessReads"]) | set(spec["businessWrites"]))
    rows = cursor.execute(
        "SELECT ordinal, predicate_id, table_name, handler_digest, "
        "key_columns_json, write_access, selector_paths_json, proof_kind, "
        "maximum_rows, entry_digest, manifest_digest, index_contract, "
        "predicate_kind, selector_source, exact_absence, source_revision "
        "FROM serverware_metadata."
        "policy_authority_query_dependency_manifests "
        "WHERE operation = %s ORDER BY ordinal LIMIT %s",
        (operation, expected_count + 1),
    ).fetchall()
    try:
        manifest = authority_primary_contract.validate_planner_manifest_rows(
            operation, rows, authorization=False,
        )
    except ValueError as exc:
        raise AuthorityPlannerError("planner query manifest differs from measured source") from exc
    return manifest, authority_primary_contract.source_query_manifest_digest()


def _load_authorization_manifest(
    cursor: Any,
    *,
    operation: str,
    trace: PlannerTrace,
) -> tuple[dict[str, Any], ...]:
    trace.read(
        "policy_authority_authorization_dependency_manifests",
        {"operation": operation},
    )
    expected_count = len(authority_contract.operation_spec(operation)["authorizationReads"])
    rows = cursor.execute(
        "SELECT ordinal, table_name, key_columns_json, predicate_kind, "
        "exact_absence, entry_digest, manifest_digest, source_revision "
        "FROM serverware_metadata."
        "policy_authority_authorization_dependency_manifests "
        "WHERE operation = %s ORDER BY ordinal LIMIT %s",
        (operation, expected_count + 1),
    ).fetchall()
    try:
        return authority_primary_contract.validate_planner_manifest_rows(
            operation, rows, authorization=True,
        )
    except ValueError as exc:
        raise AuthorityPlannerError("authorization dependency differs from measured source") from exc


def _source_admission_work(operation, work):
    """Conservative reservations for genuine fixed catalog source rebuilds.

    These descriptors come only from measured source, never database/request
    values. Their bounded reconstruction is not a generic CPU/allocation claim.
    Reserve repeated full source documents, hashes, row copies and comparisons
    before the original planner admission functions reconstruct/compare them.
    """
    primary = roots.primary
    operations = roots._callback(work, authority.operation_manifest)
    query = roots._callback(work, primary.source_query_manifest)
    authorization = roots._callback(work, primary.source_authorization_manifest)
    for _ in range(4):
        work.prepare_encoding(operations)
        work.prepare_copy(operations)
        work.charge(hashes=len(operations))
    for document, repeats in ((query, 3), (authorization, 2)):
        for _ in range(repeats):
            work.prepare_encoding(document)
            work.prepare_copy(document)
            work.prepare_scan(document)
            work.charge(hashes=1 + sum(entry["operation"] == operation for entry in document),
                input_bytes=16 + 128)
