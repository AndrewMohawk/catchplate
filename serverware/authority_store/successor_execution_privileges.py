"""Exact purpose-specific successor role privileges, without database IO.

All three roles have zero relation/sequence privileges and exactly one protected
function. The genuine generic verifier query supplies the complete effective
schema/database/membership/column/PUBLIC checks. Closed source replacements
change only the required function contract, never accept a caller inventory.
This checks ACL and function metadata, not function/trigger source bodies.
The fixed owner must separately compare the actual complete structure manifest
to an independently admitted source-generated pin on the same transaction.
"""
from __future__ import annotations

import hashlib

from serverware import authority_contract as authority
from serverware.authority_store import verifier_read_sql as generic


def _replace_once(source, original, replacement):
    if source.count(original) != 1:
        raise ValueError("successor privilege generic source closure changed")
    return source.replace(original, replacement)


_REQUESTED = "           %s::pg_catalog.text[] AS required_tables"
_FUNCTIONS = """    SELECT function_record.oid, function_record.proowner,
           function_record.proacl, authority.role_oid
    FROM authority
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.pronamespace = authority.namespace_oid"""
_FUNCTION_PRIVILEGE = """    SELECT 'function-privilege'
    FROM metadata_functions
    WHERE pg_catalog.has_function_privilege(
        role_oid, oid, 'EXECUTE') IS NOT FALSE"""

SUCCESSOR_EXECUTION_PRIVILEGE_SQL = _replace_once(
    generic.VERIFIER_READ_PRIVILEGE_SQL, _REQUESTED,
    _REQUESTED + ",\n           %s::pg_catalog.text AS expected_function")
SUCCESSOR_EXECUTION_PRIVILEGE_SQL = _replace_once(
    SUCCESSOR_EXECUTION_PRIVILEGE_SQL, _FUNCTIONS, """    SELECT function_record.oid,
           function_record.proowner, function_record.proacl, function_record.prokind,
           function_record.prosecdef, function_record.proisstrict,
           function_record.provolatile, function_record.proconfig,
           language.lanname, authority.role_oid, authority.nspowner, authority.namespace_name,
           (function_record.proname::pg_catalog.text = authority.expected_function
            AND pg_catalog.oidvectortypes(function_record.proargtypes) = 'text, text') AS expected
    FROM authority
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.pronamespace = authority.namespace_oid
    LEFT JOIN pg_catalog.pg_language AS language ON language.oid = function_record.prolang""")
SUCCESSOR_EXECUTION_PRIVILEGE_SQL = _replace_once(
    SUCCESSOR_EXECUTION_PRIVILEGE_SQL, _FUNCTION_PRIVILEGE, """    SELECT 'function-privilege'
    FROM metadata_functions
    WHERE pg_catalog.has_function_privilege(role_oid, oid, 'EXECUTE') IS DISTINCT FROM expected
       OR pg_catalog.has_function_privilege(role_oid, oid, 'EXECUTE WITH GRANT OPTION') IS NOT FALSE
    UNION ALL
    SELECT 'required-function'
    WHERE (SELECT pg_catalog.count(*) FROM metadata_functions WHERE expected) <> 1
    UNION ALL
    SELECT 'function-metadata'
    FROM metadata_functions
    WHERE expected AND (prokind IS DISTINCT FROM 'f' OR proowner IS DISTINCT FROM nspowner
       OR prosecdef IS NOT TRUE OR proisstrict IS NOT FALSE
       OR provolatile::pg_catalog.text IS DISTINCT FROM 'v'
       OR lanname::pg_catalog.text IS DISTINCT FROM 'plpgsql'
       OR proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, '
           || pg_catalog.quote_ident(namespace_name) || ', pg_temp']::pg_catalog.text[])""")
SUCCESSOR_EXECUTION_PRIVILEGE_SQL_DIGEST = (
    "sha256:" + hashlib.sha256(SUCCESSOR_EXECUTION_PRIVILEGE_SQL.encode("utf-8")).hexdigest()
)


def successor_execution_privilege_check(*, role, namespace):
    if type(role) is not str or role not in (authority.SUCCESSOR_ISSUER_ROLE,
            authority.SUCCESSOR_EXECUTOR_ROLE, authority.SUCCESSOR_RECOVERY_ROLE):
        raise ValueError("successor execution role is not source fixed")
    # Use the actual generic scalar admission, but never its read inventory.
    generic.verifier_read_privilege_check(role=role, namespace=namespace)
    function = (authority.SUCCESSOR_ISSUE_FUNCTION if role == authority.SUCCESSOR_ISSUER_ROLE
        else authority.SUCCESSOR_EXECUTE_FUNCTION if role == authority.SUCCESSOR_EXECUTOR_ROLE
        else authority.SUCCESSOR_READ_FUNCTION)
    return SUCCESSOR_EXECUTION_PRIVILEGE_SQL, (role, namespace, [], function)
