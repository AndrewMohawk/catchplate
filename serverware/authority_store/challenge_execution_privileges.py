"""Closed maintenance issuer/executor catalog privilege query, without I/O.

Both distinct roles have zero effective relation/column/sequence privileges.
Only the issuer's exact step/seal signatures or executor's exact execute
signature may be executable. Even an ungranted overload of a required name is
refused. PUBLIC, membership, database/schema and grant-option guards remain
the real shared query's complete inventory, not a positive-only ACL listing.

This does not grant access or admit function bodies, return contracts, installed
triggers or a live process. The protected owner separately compares the actual
complete catalog to its independently admitted source pin before and after its
call in the same transaction. Existing aggregate successor roles are unchanged.
"""
from __future__ import annotations

import hashlib

from serverware import authority_challenge_execution_contract as contract
from serverware.authority_store import successor_execution_privileges as shared
from serverware.authority_store import verifier_read_sql as generic


_REQUESTED = shared._REQUESTED + """,
           %s::pg_catalog.text[] AS expected_function_names,
           %s::pg_catalog.text[] AS expected_function_arguments"""
_FUNCTIONS = """    SELECT function_record.oid, function_record.proowner,
           function_record.proacl, function_record.prokind,
           function_record.prosecdef, function_record.proisstrict,
           function_record.provolatile, function_record.proconfig,
           function_record.proname::pg_catalog.text AS function_name,
           pg_catalog.oidvectortypes(function_record.proargtypes) AS argument_signature,
           language.lanname, authority.role_oid, authority.nspowner, authority.namespace_name,
           (function_record.proname::pg_catalog.text COLLATE "C" = ANY(authority.expected_function_names)) AS expected_name,
           EXISTS (
               SELECT 1
               FROM pg_catalog.generate_subscripts(authority.expected_function_names, 1) AS wanted(position)
               WHERE function_record.proname::pg_catalog.text COLLATE "C"
                         = authority.expected_function_names[wanted.position] COLLATE "C"
                 AND pg_catalog.oidvectortypes(function_record.proargtypes) COLLATE "C"
                         = authority.expected_function_arguments[wanted.position] COLLATE "C"
           ) AS expected
    FROM authority
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.pronamespace = authority.namespace_oid
    LEFT JOIN pg_catalog.pg_language AS language ON language.oid = function_record.prolang"""
_FUNCTION_PRIVILEGE = """    SELECT 'function-privilege'
    FROM metadata_functions
    WHERE pg_catalog.has_function_privilege(role_oid, oid, 'EXECUTE') IS DISTINCT FROM expected
       OR pg_catalog.has_function_privilege(role_oid, oid, 'EXECUTE WITH GRANT OPTION') IS NOT FALSE
    UNION ALL
    SELECT 'required-function'
    FROM authority
    CROSS JOIN LATERAL pg_catalog.generate_subscripts(authority.expected_function_names, 1) AS wanted(position)
    WHERE (SELECT pg_catalog.count(*) FROM metadata_functions AS candidate
           WHERE candidate.function_name COLLATE "C"
                     = authority.expected_function_names[wanted.position] COLLATE "C"
             AND candidate.argument_signature COLLATE "C"
                     = authority.expected_function_arguments[wanted.position] COLLATE "C") <> 1
    UNION ALL
    SELECT 'function-overload'
    FROM metadata_functions
    WHERE expected_name AND NOT expected
    UNION ALL
    SELECT 'function-metadata'
    FROM metadata_functions
    WHERE expected AND (prokind IS DISTINCT FROM 'f' OR proowner IS DISTINCT FROM nspowner
       OR prosecdef IS NOT TRUE OR proisstrict IS NOT FALSE
       OR provolatile::pg_catalog.text IS DISTINCT FROM 'v'
       OR lanname::pg_catalog.text IS DISTINCT FROM 'plpgsql'
       OR proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, '
           || pg_catalog.quote_ident(namespace_name) || ', pg_temp']::pg_catalog.text[])"""


CHALLENGE_EXECUTION_PRIVILEGE_SQL = shared._replace_once(
    generic.VERIFIER_READ_PRIVILEGE_SQL, shared._REQUESTED, _REQUESTED)
CHALLENGE_EXECUTION_PRIVILEGE_SQL = shared._replace_once(
    CHALLENGE_EXECUTION_PRIVILEGE_SQL, shared._FUNCTIONS, _FUNCTIONS)
CHALLENGE_EXECUTION_PRIVILEGE_SQL = shared._replace_once(
    CHALLENGE_EXECUTION_PRIVILEGE_SQL, shared._FUNCTION_PRIVILEGE, _FUNCTION_PRIVILEGE)
CHALLENGE_EXECUTION_PRIVILEGE_SQL_DIGEST = (
    "sha256:" + hashlib.sha256(CHALLENGE_EXECUTION_PRIVILEGE_SQL.encode("utf-8")).hexdigest()
)


def challenge_execution_privilege_check(*, role, namespace):
    """Only source-selected functions; all identifiers are bound parameters."""
    if type(role) is not str or role not in (contract.ISSUER_ROLE, contract.EXECUTOR_ROLE):
        raise ValueError("challenge execution role is not source fixed")
    # Repeat the real exact scalar/UTF-8 validation, discard its read inventory.
    generic.verifier_read_privilege_check(role=role, namespace=namespace)
    names = contract.ROLE_FUNCTIONS[role]
    expected = ((contract.STEP_FUNCTION, contract.SEAL_FUNCTION) if role == contract.ISSUER_ROLE
        else (contract.EXECUTE_FUNCTION,))
    signatures = ((('text', 'integer', 'text', 'text', 'bigint'), ('text', 'text', 'text'))
        if role == contract.ISSUER_ROLE else (('text', 'text'),))
    if (type(names) is not tuple or names != expected
            or tuple(contract.FUNCTION_SIGNATURES[name] for name in names) != signatures):
        raise ValueError("challenge execution function roster changed")
    return CHALLENGE_EXECUTION_PRIVILEGE_SQL, (
        role, namespace, [], list(names), [", ".join(signature) for signature in signatures])
