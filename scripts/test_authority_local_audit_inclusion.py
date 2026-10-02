#!/usr/bin/env python3
"""Signed synthetic row controls, no database/runtime-owner success simulation."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    from scripts.test_authority_genesis_successor import fixture as genesis_fixture
    from serverware import authority_local_audit_inclusion as local
    f = genesis_fixture()
    db, g = f["db"], f["g"]
    changes = {item["table"]: item["row"] for item in f["prepared"].mutations}
    preparation = changes["policy_authority_genesis_preparations"]
    stage = g.stage(f["record"], f["now"])
    outbox = dict(stage["outbox"], status="audited", audited_at="2026-10-01T00:00:00+00:00")
    audit = {key:outbox[key] for key in ("id", "event_type", "actor_type", "actor_id", "event_json")}
    audit.update(sequence=1, encrypted_canonical_event_json=None, storage_format_version=2,
        prev_event_hash=None, created_at="2026-10-01T00:00:00+00:00")
    audit["event_hash"] = db._audit_hash(**{key:audit[key] for key in
        ("event_type", "actor_type", "actor_id", "event_json", "prev_event_hash", "created_at")}, event_id=audit["id"])
    outbox["audit_event_hash"] = audit["event_hash"]
    keys = [item["row"] for item in f["final_context"].selected_rows
        if item["table"] == "policy_authority_trusted_keys" and item["present"]]
    heads = []
    for context in (f["prepare_context"], f["final_context"]):
        heads.extend(item["row"] for item in context.selected_rows if item["table"] == "policy_authority_trusted_key_heads" and item["present"])
    pin = db._candidate_authority_sha256(b"synthetic-sealed-dsn-original")
    selected = dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE,
        metadata=dict(sha256=pin, database="synthetic_metadata", role=local.reader.ROLE, host="/run/postgresql", port=5432, transport="unix"),
        audit=dict(sha256=pin, database="synthetic_audit", role="audit_runtime", host="/run/postgresql", port=5432, transport="unix"),
        genesisPreparationDigest=preparation["genesis_preparation_digest"], policyHash=preparation["policy_hash"],
        auditStoreIdentityDigest=f["policy"]["auditStoreIdentityDigest"],
        auditSignerPublicKeyDigest=f["policy"]["auditSignerPublicKeyDigest"],
        rootKeySpkiDigest=f["prepare_context"].genesis_root_digest, bootIdDigest=pin,
        issuedAtBoottimeNs=100, deadlineBoottimeNs=200, issuedAtUnixNanos=f["ns"]-500_000_000,
        expiresAtUnixNanos=f["ns"]+500_000_000)
    observed = dict(preparation=preparation, verification=changes["policy_authority_evidence_verifications"],
        transition=stage["transition"], outbox=outbox, keys=keys, heads=heads,
        revocations=[], runtime_keys=[], audit_rows=[audit], now_unix_ns=f["ns"])
    return local, f, selected, observed


def scenario(name):
    import ast
    import copy
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    local, f, selected, observed = fixture()
    def refuses(call):
        try: call()
        except Exception: return
        raise AssertionError("expected source refusal")
    if name == "approval":
        assert local.MAX_WINDOW_NS == 30_000_000_000
        raw = f["db"].dumps(selected).encode("ascii")
        assert local.approval(raw) == selected
        for field, value in (("purpose", "continue-audit"), ("deadlineBoottimeNs", 100 + local.MAX_WINDOW_NS + 1),
                             ("rootKeySpkiDigest", selected["auditSignerPublicKeyDigest"]), ("renew", True)):
            wrong = dict(selected, **{field:value})
            refuses(lambda: local.approval(f["db"].dumps(wrong).encode("ascii")))
    elif name == "signed-original":
        row, key, head, sequence = local.original_binding(selected, **observed)
        local.admit_signing_key(key, issued=selected["issuedAtUnixNanos"], expires=selected["expiresAtUnixNanos"], now=f["ns"])
        raw = local.signed_original(row, key, head, sequence, Ed25519PrivateKey.from_private_bytes(b"a"*32),
            issued=selected["issuedAtUnixNanos"], expires=selected["expiresAtUnixNanos"], now=f["ns"])
        value = f["db"].loads(raw.decode("ascii"), None)
        assert set(value) == set(f["db"]._POLICY_AUTHORITY_AUDIT_INCLUSION_FIELDS)
        assert value["audit_event_hash"] == observed["audit_rows"][-1]["event_hash"]
        assert value["audit_sequence"] == 1 and value["previous_audit_event_hash"] is None
        from dataclasses import replace
        from serverware import authority_radix_proof as radix
        context = f["final_context"]
        rows = list({**entry,"row":observed["outbox"]} if entry["table"] == "metadata_audit_outbox" else entry
            for entry in context.selected_rows)
        arguments = f["args"](f["g"].FINALIZE, value)
        for query in f["g"].queries(f["g"].FINALIZE, arguments=arguments, database_now=f["now"], request_digest=context.request_digest):
            if query.absent_key is None: continue
            key = dict(query.absent_key)
            if any(isinstance(item, f["core"].SelectedRowFieldReference) for item in key.values()):
                key = {"policy_hash":f["record"]["policy_hash"]}
            if not any(entry["table"] == query.table and entry["key"] == key for entry in rows):
                rows.append(dict(table=query.table,key=key,keyDigest=radix.authenticated_key_digest(query.table,key),present=False,row=None))
        result = f["g"].transition(replace(context, arguments=arguments, selected_rows=tuple(rows)))
        assert result.result["ok"] and result.result["inclusion_receipt_envelope_digest"] == value["inclusion_receipt_envelope_digest"]
    elif name == "event-originals":
        for target, field, value in (("outbox", "status", "pending"), ("transition", "state_digest", selected["bootIdDigest"]),
                ("outbox", "audit_event_hash", selected["bootIdDigest"]), ("preparation", "policy_hash", selected["bootIdDigest"])):
            wrong = copy.deepcopy(observed); wrong[target][field] = value
            refuses(lambda: local.original_binding(selected, **wrong))
        for field in ("event_json", "event_hash", "prev_event_hash"):
            wrong = copy.deepcopy(observed); wrong["audit_rows"][0][field] = "changed"
            refuses(lambda: local.original_binding(selected, **wrong))
    elif name == "key-authority":
        for change in ("revoked", "other-purpose", "runtime-custody", "head", "key-expiry"):
            wrong = copy.deepcopy(observed)
            signer = selected["auditSignerPublicKeyDigest"]
            if change == "revoked": wrong["revocations"].append(dict(evidence_kind="audit_inclusion_receipt", signing_key_id=signer, revocation_sequence=1, revoked_at_epoch_ns=f["ns"]))
            elif change == "other-purpose": wrong["keys"].append(dict(wrong["keys"][1], evidence_kind="candidate_artifact"))
            elif change == "runtime-custody": wrong["runtime_keys"].append(dict(public_key_digest=signer, role="custody"))
            elif change == "head": wrong["heads"][1]["head_key_revision"] = 2
            else:
                key = next(row for row in wrong["keys"] if row["evidence_kind"] == "audit_inclusion_receipt")
                key["not_after_epoch_ns"] = f["ns"]
            def check():
                _, key, _, _ = local.original_binding(selected, **wrong)
                local.admit_signing_key(key, issued=selected["issuedAtUnixNanos"], expires=selected["expiresAtUnixNanos"], now=f["ns"])
            refuses(check)
    elif name == "bounds":
        wrong = dict(observed, now_unix_ns=selected["expiresAtUnixNanos"])
        refuses(lambda: local.original_binding(selected, **wrong))
        wrong = dict(observed, audit_rows=observed["audit_rows"]*(local.MAX_AUDIT_ROWS+1))
        refuses(lambda: local.original_binding(selected, **wrong))
        wrong = copy.deepcopy(observed); wrong["audit_rows"][0]["encrypted_canonical_event_json"] = "not-an-admitted-preimage"
        refuses(lambda: local.original_binding(selected, **wrong))
    elif name == "runtime-source":
        tree = ast.parse(Path(local.__file__).read_text())
        owner = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "LocalAuditInclusionIssuer")
        functions = {item.name:item for item in owner.body if isinstance(item, ast.FunctionDef)}
        issue = functions["issue"]
        calls = [(item.lineno, item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id if isinstance(item.func, ast.Name) else "")
            for item in ast.walk(issue) if isinstance(item, ast.Call)]
        key_line = min(line for line, name in calls if name == "signing_key")
        assert max(line for line, name in calls if name in {"original_binding", "admit_signing_key"}) < key_line
        text = Path(local.__file__).read_text()
        assert "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" in text
        assert "retain_connection=self.connections.append" in text
        assert all(table in local.TABLES for table in ("policy_authority_audit_inclusion_heads", "policy_authority_audit_inclusion_receipts", "policy_publications"))
        sql = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        assert not any(value.lstrip().startswith(("INSERT ", "UPDATE ", "DELETE ", "CREATE ")) for value in sql)
    elif name == "cli":
        from scripts.authority import local_audit_inclusion as cli
        args = ["--approval-fd","3","--approval-sha256",selected["bootIdDigest"],"--metadata-dsn-fd","4","--audit-dsn-fd","5","--signing-key-fd","6"]
        assert cli.arguments(args)["signing_key_fd"] == 6
        for wrong in (args+["--dsn","credential"], [args[0],"03",*args[2:]], []): refuses(lambda: cli.arguments(wrong))
    elif name == "reader":
        from serverware.authority_store import verifier_read_sql
        from serverware import authority_contract
        from scripts.authority import provision_local_audit_reader as cli
        query, params = local.reader.privilege_check()
        assert query == verifier_read_sql.VERIFIER_READ_PRIVILEGE_SQL
        assert params == (local.reader.ROLE, "serverware_metadata", sorted(local.reader.TABLES))
        assert local.reader.TABLES != authority_contract.VERIFIER_READ_TABLES
        assert set(local.TABLES) <= local.reader.TABLES
        assert cli.arguments(["--plan"]) is None
        assert cli.arguments(["--apply","--database","metadata","--admin-dsn-fd","3"]) == {"database":"metadata","fd":3}
        refuses(lambda: cli.arguments(["--apply","--role","arbitrary","--admin-dsn-fd","3"]))
        tree = ast.parse(Path(local.reader.__file__).read_text())
        constants = [node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and isinstance(node.value,str)]
        assert any("already exists; no adoption or overwrite" in text for text in constants)
        assert not any(text.startswith(("ALTER ROLE", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE")) for text in constants)
    else: raise AssertionError(name)


class LocalAuditInclusionTests(unittest.TestCase):
    def check(self, name):
        environment = {key:value for key,value in os.environ.items() if not key.startswith("SERVERWARE_")}
        with tempfile.TemporaryDirectory(prefix="serverware-first-inclusion-") as directory:
            environment.update(SERVERWARE_DATA_DIR=directory, SERVERWARE_RELEASE_CHANNEL="dev", SERVERWARE_PROCESS_MODE="serverware-control-plane")
            command = "import sys; sys.path.insert(0,sys.argv[1]); from scripts.test_authority_local_audit_inclusion import scenario; scenario(sys.argv[2])"
            result = subprocess.run([sys.executable,"-I","-B","-c",command,str(ROOT),name], cwd=ROOT,
                env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_closed_independent_approval(self): self.check("approval")
    def test_existing_inclusion_signature_and_genesis_finalize_acceptance(self): self.check("signed-original")
    def test_exact_terminal_event_and_preparation_originals(self): self.check("event-originals")
    def test_current_key_revocation_purpose_and_expiry(self): self.check("key-authority")
    def test_original_bounds_and_full_bounded_prefix(self): self.check("bounds")
    def test_actual_reader_order_and_no_dml_source(self): self.check("runtime-source")
    def test_fixed_descriptor_only_cli(self): self.check("cli")
    def test_separate_fixed_reader_and_absent_role_provisioner(self): self.check("reader")


if __name__ == "__main__": unittest.main()
