#!/usr/bin/env python3
"""Source and optional native PostgreSQL component controls, not an executor.

Only stdlib is imported. --emit-postgres-sql prints a rollback-only fixture for
an externally owned disposable PostgreSQL 16 database; this file never opens a
connection or starts a container. Actual production evidence DDL, wire/digest
functions and the complete extracted optional-evidence guard are exercised.
Synthetic records stand in for previously admitted capability/trust inputs;
they make no signature, TLS, root-currentness or full-pilot admission claim.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "serverware_optional_evidence_component"
NAMESPACE = '"' + SCHEMA + '"'
TABLE = "policy_authority_webauthn_assertion_evidence"
DOMAIN = "serverware.policyAuthorityWebAuthnAssertionEvidence/v1"
# Whitespace-normalized ORIGINAL committed executor excerpts, before the fix.
# Optional term: lines1598..1679; complete monolithic IF:1456..1689.
OLD_TERM_SHA256 = "f6406fbbbd11223df9d46ac093990a3a32877aa10b0008153bd0007d178fab1d"
OLD_GUARD_SHA256 = "e08074d407fb9c1d96698656b8c15dc48967c5a6d6dc2e3c560f197beaad2108"
DENIAL = "authority v9 closed preconditions changed"


def _read(relative):
    path = ROOT / relative
    if not 1 <= path.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError("component source size changed")
    return ast.parse(path.read_text(encoding="utf-8"))


def _one(values):
    if len(values) != 1:
        raise ValueError("component source boundary is not unique")
    return values[0]


def _template(node, substitutions=None):
    if type(node) is not ast.JoinedStr:
        raise ValueError("component SQL is not a source f-string")
    pieces = []
    for item in node.values:
        if type(item) is ast.Constant and type(item.value) is str:
            pieces.append(item.value)
        elif (type(item) is ast.FormattedValue and item.conversion == -1
                and item.format_spec is None):
            name = ast.unparse(item.value)
            if substitutions is None:
                pieces.append("{" + name + "}")
            elif name in substitutions:
                pieces.append(str(substitutions[name]))
            else:
                raise ValueError("component SQL acquired an unknown interpolation")
        else:
            raise ValueError("component SQL interpolation shape changed")
    return "".join(pieces)


def _normalized_sha(value):
    return hashlib.sha256((" ".join(value.split()) + "\n").encode("utf-8")).hexdigest()


def _guard_parts():
    tree = _read("serverware/authority_store/executor_v9.py")
    function = _one([node for node in tree.body if type(node) is ast.FunctionDef
        and node.name == "install_authority_v9_executor"])
    template = _one([_template(node) for node in ast.walk(function)
        if type(node) is ast.JoinedStr and any(type(part) is ast.Constant
            and type(part.value) is str and "IF fence_head.fence <> capability.fence" in part.value
            for part in node.values)])
    main = _one(re.findall(r"IF fence_head\.fence <> capability\.fence.*?END IF;", template, re.S))
    guard = _one(re.findall(
        r"IF authorization_projection\.assertion_evidence_digest\s+IS NOT NULL\s+THEN\s+"
        r"IF NOT EXISTS \(.*?END IF;\s+END IF;", template, re.S))
    predicate = _one(re.findall(r"IF NOT EXISTS \((.*?)\)\s+THEN\s+RAISE EXCEPTION\s+"
        r"'authority v9 closed preconditions changed';\s+END IF;", guard, re.S))
    old_term = ("OR ( authorization_projection.assertion_evidence_digest IS NOT NULL "
        "AND NOT EXISTS (" + predicate + ") )")
    seam = "OR operation_handlers->>capability.operation"
    if main.count(seam) != 1 or _normalized_sha(old_term) != OLD_TERM_SHA256:
        raise ValueError("original complete optional-evidence predicate changed")
    old_main = main.replace(seam, old_term + "\n" + seam)
    if _normalized_sha(old_main) != OLD_GUARD_SHA256:
        raise ValueError("monolithic guard changed beyond the optional-statement move")
    if guard.count("{namespace}") != 3 or "{" in guard.replace("{namespace}", ""):
        raise ValueError("optional guard gained an unbound source dependency")
    return guard.replace("{namespace}", NAMESPACE), old_term.replace("{namespace}", NAMESPACE)


def _integer(node):
    if type(node) is ast.Constant and type(node.value) is int:
        return node.value
    if type(node) is ast.BinOp and type(node.op) is ast.Mult:
        return _integer(node.left) * _integer(node.right)
    raise ValueError("source byte bound is not a literal integer product")


def _actual_helpers():
    tree = _read("serverware/authority_store/wire_json_sql.py")
    substitutions = {"namespace": NAMESPACE}
    for node in tree.body:
        if type(node) is ast.Assign and len(node.targets) == 1 and type(node.targets[0]) is ast.Name:
            name = node.targets[0].id
            if name in ("WIRE_JSON_MAX_DEPTH", "WIRE_JSON_MAX_NODES", "WIRE_JSON_MAX_BYTES"):
                substitutions[name] = _integer(node.value)
    wire = _one([node for node in ast.walk(tree) if type(node) is ast.JoinedStr])
    wire_sql = _template(wire, substitutions)
    tree = _read("serverware/db.py")
    maximum = _one([_integer(node.value) for node in tree.body if type(node) is ast.Assign
        and len(node.targets) == 1 and type(node.targets[0]) is ast.Name
        and node.targets[0].id == "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES"])
    digest = _one([node for node in ast.walk(tree) if type(node) is ast.JoinedStr
        and any(type(part) is ast.Constant and type(part.value) is str
            and "serverware_policy_authority_domain_digest(\n                    digest_domain text" in part.value
            for part in node.values)])
    digest_sql = _template(digest, {"guard_namespace": NAMESPACE,
        "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES": maximum})
    return wire_sql, digest_sql


def _actual_table():
    tree = _read("serverware/authority_store/v9_schema_source.py")
    function = _one([node for node in tree.body if type(node) is ast.FunctionDef
        and node.name == "authority_v9_schema_source"])
    # The enclosing source applies two numeric placeholder replacements to
    # other tables. This declaration is wholly literal and has neither slot.
    source = _one([node.value for node in ast.walk(function) if type(node) is ast.Constant
        and type(node.value) is str and re.search(
            r"CREATE TABLE IF NOT EXISTS\s+" + TABLE + r" \(", node.value)])
    declaration = _one(re.findall(r"CREATE TABLE IF NOT EXISTS\s+" + TABLE + r" \(.*?\n            \);", source, re.S))
    if "__MAX_" in declaration:
        raise ValueError("evidence declaration acquired a dynamic source bound")
    return declaration


def _quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value):
    raw = value.encode("ascii")
    return "sha256:" + hashlib.sha256(DOMAIN.encode("ascii") + b"\0"
        + len(raw).to_bytes(8, "big") + raw).hexdigest()


def postgres_sql():
    guard, old_term = _guard_parts()
    wire_sql, digest_sql = _actual_helpers()
    ddl = _actual_table()
    columns = re.findall(r"^\s+([a-z_][a-z0-9_]*) (TEXT|BIGINT) ", ddl, re.M)
    revision = _one(re.findall(r"source_revision =\s*'([^']+)'", ddl))
    values = {name: "synthetic-" + name if kind == "TEXT" else 1 for name, kind in columns}
    evidence_json = _canonical({"component": "synthetic", "purpose": "optional-evidence-guard"})
    values.update(operation="webauthn.counter.cas", evidence_json=evidence_json,
        assertion_evidence_digest=_digest(evidence_json), flags=5, prior_counter=1,
        counter=2, metadata_publication_sequence=7, verified_at_epoch_ns=0,
        expires_at_epoch_ns=20, source_revision=revision)
    receipt_fields = {
        "challengeId": "challenge_id", "challengeDigest": "challenge_digest",
        "credentialRecordId": "credential_record_id", "credentialId": "credential_id",
        "credentialPolicyDigest": "credential_policy_digest", "clientDataJSONDigest": "client_data_json_digest",
        "authenticatorDataDigest": "authenticator_data_digest", "signatureDigest": "signature_digest",
        "flags": "flags", "priorCounter": "prior_counter", "counter": "counter",
    }
    receipt = _canonical({key: values[column] for key, column in receipt_fields.items()})
    capability_fields = {name: values[name] for name in ("operation", "operation_id", "request_digest", "capability_id")}
    capability_fields.update(webauthn_receipt_digest=values["verified_assertion_receipt_digest"],
        webauthn_trust_high_water_digest=values["trust_high_water_digest"], webauthn_receipt_json=receipt)
    capability_select = ",\n".join(_quote(value) + "::text AS " + name for name, value in capability_fields.items())
    insert = (f"INSERT INTO {NAMESPACE}.{TABLE} (" + ",".join(name for name, _ in columns)
        + ") VALUES (" + ",".join(_quote(values[name]) for name, _ in columns) + ");")
    # Restore the EXACT old optional boolean expression, not a toy false AND.
    # The frozen hashes above bind all its predicates and the full old IF.
    old_guard = "IF " + old_term.removeprefix("OR ") + " THEN RAISE EXCEPTION " + _quote(DENIAL) + "; END IF;"
    function = f"""
CREATE FUNCTION {NAMESPACE}.exercise_guard(supplied_digest text, initialize_trust boolean, use_old boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $component_guard$
DECLARE
    authorization_projection record;
    capability record;
    trust_publication record;
    computed_trust_high_water_digest text := {_quote(values['trust_high_water_digest'])};
    now_epoch_ns bigint := 10;
BEGIN
    SELECT supplied_digest AS assertion_evidence_digest INTO authorization_projection;
    SELECT {capability_select} INTO capability;
    IF initialize_trust THEN
        SELECT 7::bigint AS sequence INTO trust_publication;
    END IF;
    IF use_old THEN
        {old_guard}
    ELSE
        {guard}
    END IF;
END;
$component_guard$;
"""
    actual_digest = _quote(values["assertion_evidence_digest"])
    call = f"PERFORM {NAMESPACE}.exercise_guard({actual_digest}, TRUE, FALSE);"
    negative_cases = (
        ("missing-row", f"DELETE FROM {NAMESPACE}.{TABLE};"),
        ("trust-sequence", f"UPDATE {NAMESPACE}.{TABLE} SET metadata_publication_sequence = 8;"),
        ("receipt-join", f"UPDATE {NAMESPACE}.{TABLE} SET challenge_id = 'different-challenge';"),
        ("evidence-bytes", f"UPDATE {NAMESPACE}.{TABLE} SET evidence_json = '{{}}';"),
        ("expired", f"UPDATE {NAMESPACE}.{TABLE} SET expires_at_epoch_ns = 9;"),
    )
    refusals = []
    for label, mutation in negative_cases:
        refusals.append(f"""
    caught := FALSE;
    BEGIN
        {mutation}
        {call}
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
        IF SQLERRM <> {_quote(DENIAL)} THEN RAISE; END IF;
        caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION 'optional-evidence {label} was accepted'; END IF;
    {call}
""")
    checks = f"""
DO $component_checks$
DECLARE caught boolean;
BEGIN
    IF pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR pg_catalog.getdatabaseencoding() <> 'UTF8' OR pg_catalog.inet_server_addr() IS NOT NULL
    THEN RAISE EXCEPTION 'component requires PostgreSQL16 UTF8 over a Unix socket'; END IF;
    IF {NAMESPACE}.serverware_policy_authority_domain_digest({_quote(DOMAIN)}, {_quote(evidence_json)})
            <> {actual_digest}
        OR {NAMESPACE}.serverware_policy_authority_wire_json({_quote(evidence_json)}::jsonb)
            <> {_quote(evidence_json)}
    THEN RAISE EXCEPTION 'actual helper does not match independent fixture bytes'; END IF;
    PERFORM {NAMESPACE}.exercise_guard(NULL, FALSE, FALSE);
    caught := FALSE;
    BEGIN
        PERFORM {NAMESPACE}.exercise_guard(NULL, FALSE, TRUE);
    EXCEPTION WHEN SQLSTATE '55000' THEN caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION 'original unassigned-record control did not fail55000'; END IF;
    {call}
    PERFORM {NAMESPACE}.exercise_guard({actual_digest}, TRUE, TRUE);
    {''.join(refusals)}
END;
$component_checks$;
"""
    return ("\\set ON_ERROR_STOP on\nBEGIN;\nSET LOCAL statement_timeout = '20s';\n"
        "SET LOCAL lock_timeout = '2s';\n" + f"CREATE SCHEMA {NAMESPACE};\n"
        f"SET LOCAL search_path = {NAMESPACE}, pg_catalog;\n" + ddl + "\n" + wire_sql + "\n"
        + digest_sql + ";\n" + insert + "\n" + function + checks
        + "ROLLBACK;\nSELECT 'optional-evidence component: absent/old55000/present/five refusals OK' AS result;\n")


class OptionalEvidenceSourceControls(unittest.TestCase):
    def test_complete_original_predicates_only_move_to_outer_statement(self):
        guard, old_term = _guard_parts()
        self.assertRegex(guard, r"^IF authorization_projection\.assertion_evidence_digest\s+IS NOT NULL\s+THEN\s+IF NOT EXISTS")
        self.assertIn("AND NOT EXISTS", old_term)
        self.assertIn("trust_publication.sequence", guard)
        self.assertEqual(guard.count("END IF;"), 2)

    def test_actual_table_and_helpers_are_extracted_without_production_imports(self):
        ddl, (wire, digest) = _actual_table(), _actual_helpers()
        self.assertIn("challenge_id TEXT NOT NULL UNIQUE", ddl)
        self.assertIn("CHECK (counter > prior_counter)", ddl)
        self.assertEqual(wire.count("CREATE OR REPLACE FUNCTION"), 3)
        self.assertIn("pg_catalog.sha256(digest_material)", digest)
        self.assertNotIn("serverware.authority_transition_registry", sys.modules)

    def test_native_program_retains_rollback_and_all_control_paths(self):
        program = postgres_sql()
        self.assertIn(_guard_parts()[0], program)
        self.assertIn("WHEN SQLSTATE '55000'", program)
        self.assertEqual(program.count("WHEN SQLSTATE 'P0001'"), 5)
        self.assertIn("exercise_guard(NULL, FALSE, FALSE)", program)
        self.assertIn("ROLLBACK;", program)
        self.assertNotIn("COMMIT;", program)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-postgres-sql", action="store_true")
    arguments = parser.parse_args()
    if arguments.emit_postgres_sql:
        sys.stdout.write(postgres_sql())
    else:
        unittest.main(argv=[sys.argv[0]])
