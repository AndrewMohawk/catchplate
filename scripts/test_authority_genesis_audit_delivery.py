#!/usr/bin/env python3
"""Synthetic signed-row/kernel controls; no PG append or live owner is simulated."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    import copy
    from dataclasses import replace
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from scripts.test_authority_local_audit_inclusion import fixture as prior
    local, f, selected, observed = prior()
    g, db = f["g"], f["db"]
    selected = dict(selected, schema=local.DELIVERY_APPROVAL_SCHEMA, purpose=local.DELIVERY_PURPOSE,
        audit={**selected["audit"], "role":db._AUDIT_STORE_RUNTIME_ROLE})
    observed = copy.deepcopy(observed)
    observed["outbox"] = g.stage(f["record"], f["now"])["outbox"]
    binding, key, head, sequence = local.original_binding(selected, **observed)
    raw = local.signed_original(binding, key, head, sequence, Ed25519PrivateKey.from_private_bytes(b"a"*32),
        issued=selected["issuedAtUnixNanos"], expires=selected["expiresAtUnixNanos"], now=f["ns"])
    receipt = db.loads(raw.decode("ascii"), None)
    arguments = f["args"](g.FINALIZE, receipt)
    arguments["schema"] = g.FINALIZE_DELIVERY_SCHEMA
    arguments.pop("businessIntent")
    arguments["businessIntent"] = f["contract"].synthesize_business_intent(g.FINALIZE, arguments)
    context = f["final_context"]
    rows = [dict(entry, row=observed["outbox"]) if entry["table"] == "metadata_audit_outbox" else entry
        for entry in context.selected_rows]
    # The newly signed receipt has different exact query identities from the
    # older fixture. Use the actual source declarations for their absent rows.
    from serverware import authority_radix_proof as radix
    for query in g.queries(g.FINALIZE, arguments=arguments, database_now=f["now"], request_digest=context.request_digest):
        if query.absent_key is None:
            continue
        key = dict(query.absent_key)
        if any(isinstance(item, f["core"].SelectedRowFieldReference) for item in key.values()):
            key = {"policy_hash":f["record"]["policy_hash"]}
        if not any(entry["table"] == query.table and entry["key"] == key for entry in rows):
            rows.append(dict(table=query.table, key=key, keyDigest=radix.authenticated_key_digest(query.table,key), present=False,row=None))
    return local, f, selected, observed, replace(context, arguments=arguments, selected_rows=tuple(rows)), receipt


def scenario(name):
    import ast
    import copy
    from dataclasses import replace
    local, f, selected, observed, context, receipt = fixture()
    g, db = f["g"], f["db"]
    def refuses(call):
        try:
            call()
        except (ValueError, RuntimeError):
            return
        raise AssertionError("expected exact source refusal")

    if name == "versions":
        assert db._AUDIT_STORE_RUNTIME_ROLE == "synthetic_audit_runtime"
        assert local.approval(db.dumps(selected).encode("ascii")) == selected
        for schema,purpose in ((local.APPROVAL_SCHEMA,local.DELIVERY_PURPOSE),
                (local.DELIVERY_APPROVAL_SCHEMA,local.PURPOSE)):
            refuses(lambda: local.approval(db.dumps(dict(selected,schema=schema,purpose=purpose)).encode("ascii")))
        wrong=copy.deepcopy(selected); wrong["audit"]["role"]="unselected_audit_writer"
        refuses(lambda: local.approval(db.dumps(wrong).encode("ascii")))
        assert g.selected(g.FINALIZE,context.arguments)
        assert g.selected(g.FINALIZE,f["final_arguments"])
        assert not g.selected(g.FINALIZE,{"schema":"serverware.policyAuthorityGenesisFinalize/v4"})
    elif name == "atomic":
        result=g.transition(context)
        changes={entry["table"]:entry for entry in result.mutations}
        outbox=changes["metadata_audit_outbox"]
        assert outbox["operation"] == "UPDATE" and outbox["expectedRow"] == observed["outbox"]
        assert outbox["row"] == dict(observed["outbox"],status="audited",audited_at=f["now"].isoformat(),
            audit_event_hash=observed["audit_rows"][-1]["event_hash"])
        assert changes["policy_authority_genesis_finalizations"]["row"]["inclusion_receipt_envelope_digest"] == receipt["inclusion_receipt_envelope_digest"]
        assert {"policy_high_water","policy_publications","policy_authority_audit_inclusion_heads",
            "policy_authority_evidence_verifications"} <= changes.keys()
        assert result.result["ok"] is True and result.result["idempotent"] is False
    elif name == "old":
        old=g.transition(f["final_context"])
        assert all(item["table"] != "metadata_audit_outbox" for item in old.mutations)
        arguments={**context.arguments,"schema":g.FINALIZE_SCHEMA}
        refuses(lambda:g.transition(replace(context,arguments=arguments)))
        rows=copy.deepcopy(context.selected_rows)
        next(item for item in rows if item["table"]=="metadata_audit_outbox")["row"].update(status="audited",audit_event_hash=receipt["audit_event_hash"])
        refuses(lambda:g.transition(replace(context,selected_rows=rows)))
        wrong=dict(selected,schema=local.APPROVAL_SCHEMA,purpose=local.PURPOSE)
        refuses(lambda:local.original_binding(wrong,**observed))
    elif name == "pending":
        for field,value in (("status","claimed"),("attempts",1),("claim_id","foreign"),("audit_event_hash",receipt["audit_event_hash"]),
                ("event_json","{}"),("actor_id","other"),("storage_format_version",1),("last_error","uncertain")):
            rows=copy.deepcopy(context.selected_rows)
            next(item for item in rows if item["table"]=="metadata_audit_outbox")["row"][field]=value
            refuses(lambda:g.transition(replace(context,selected_rows=rows)))
            wrong=copy.deepcopy(observed);wrong["outbox"][field]=value
            refuses(lambda:local.original_binding(selected,**wrong))
    elif name == "prefix":
        for rows in ([],observed["audit_rows"]*257):
            refuses(lambda:local.original_binding(selected,**dict(observed,audit_rows=rows)))
        for field in ("id","event_json","event_hash","prev_event_hash","actor_id"):
            wrong=copy.deepcopy(observed);wrong["audit_rows"][0][field]="changed"
            refuses(lambda:local.original_binding(selected,**wrong))
        wrong=copy.deepcopy(context.arguments);wrong["inclusionReceipt"]["signature"]="A"*86
        refuses(lambda:g.transition(replace(context,arguments=wrong)))
        refuses(lambda:local.original_binding(selected,**dict(observed,now_unix_ns=selected["expiresAtUnixNanos"])))
    elif name == "capacity":
        from serverware import authority_audit_capacity as capacity
        from scripts.test_authority_audit_capacity import aggregate_row,selection
        # Construct real source-format selected records for the pure finalizer;
        # these are row fixtures, not authenticated-root acquisition.
        rows=tuple(selection(item["table"],item["key"],present=item["present"],row=item["row"]) for item in context.selected_rows)
        counter=aggregate_row(live=1)
        rows=(*rows,selection(capacity.AGGREGATE_TABLE,{"aggregate_id":counter["aggregate_id"]},present=True,row=counter))
        current=replace(context,selected_rows=rows)
        result=g.transition(current)
        completed=capacity.finalize_capacity(current,result.mutations)
        changed=next(item for item in completed if item["table"]==capacity.AGGREGATE_TABLE)
        assert changed["row"]["live_count"]==changed["row"]["active_count"]==0
        assert changed["row"]["next_sequence"]==counter["next_sequence"]
        capacity.validate_capacity_transition(operation=g.FINALIZE,selected_rows=rows,mutations=completed)
        broken=tuple(item for item in completed if item["table"]!=capacity.AGGREGATE_TABLE)
        refuses(lambda:capacity.validate_capacity_transition(operation=g.FINALIZE,selected_rows=rows,mutations=broken))
    elif name == "foreground":
        from serverware import development_policy_commissioning as caller
        value={"input":{key:value for key,value in context.arguments.items() if key!="businessIntent"},
            "webauthnAuthorization":{"challengeId":"synthetic-only","credentialRecordId":"synthetic-only","assertion":{"fixture":True}}}
        assert caller.finalize_input(caller._canonical(value),f["prepared"].result,prepare_schema=g.PREPARE_SCHEMA)==value
        spec=f["contract"].operation_spec(g.FINALIZE)
        assert spec["assertionRequired"] and spec["globalAuditCapacity"]
        assert {item["mutation"] for item in spec["mutationTemplates"] if item["table"]=="metadata_audit_outbox"}=={"UPDATE"}
        from serverware.authority_store import audit_capacity_sql
        assert g.FINALIZE in audit_capacity_sql._source_contract()
    elif name == "final-deadline":
        from serverware import development_policy_commissioning as caller
        request={"input":dict(context.arguments)}
        original=copy.deepcopy(request)
        now=f["ns"];deadline=50_000_000_000;expiry=now+40_000_000_000
        actual=db.loads(receipt["inclusion_receipt_envelope_json"],None)["payload"]["expiresAtEpochNs"]
        assert caller._finalize_deadline(request,deadline,expiry,now_monotonic_ns=1_000_000_000,now_unix_ns=now)==(
            1_000_000_000+actual-now,actual)
        assert request==original
        assert caller._finalize_deadline(request,1_100_000_000,now+100_000_000,
            now_monotonic_ns=1_000_000_000,now_unix_ns=now)==(1_100_000_000,now+100_000_000)
        for value in (now,True,1.5,2**63):
            changed=copy.deepcopy(request)
            envelope=db.loads(changed["input"]["inclusionReceipt"]["inclusion_receipt_envelope_json"],None)
            envelope["payload"]["expiresAtEpochNs"]=value
            changed["input"]["inclusionReceipt"]["inclusion_receipt_envelope_json"]=db.dumps(envelope)
            refuses(lambda:caller._finalize_deadline(changed,deadline,expiry,now_monotonic_ns=1_000_000_000,now_unix_ns=now))
        old={"input":{"schema":g.FINALIZE_SCHEMA}}
        assert caller._finalize_deadline(old,deadline,expiry,now_monotonic_ns=1_000_000_000,now_unix_ns=now)==(deadline,expiry)
    elif name == "owner-order":
        tree=ast.parse(Path(local.__file__).read_text())
        owner=next(item for item in tree.body if isinstance(item,ast.ClassDef) and item.name=="LocalAuditInclusionIssuer")
        methods={item.name:item for item in owner.body if isinstance(item,ast.FunctionDef)}
        def calls(node):
            return [(item.lineno,item.func.attr if isinstance(item.func,ast.Attribute) else item.func.id if isinstance(item.func,ast.Name) else "")
                for item in ast.walk(node) if isinstance(item,ast.Call)]
        order=calls(methods["_append_pending"])
        at=lambda name:min(line for line,item in order if item==name)
        assert at("preparation_binding")<at("admit_signing_key")<at("signing_key")<at("_append_postgres_audit_event_on_connection")<at("commit")
        issue=calls(methods["issue"])
        assert min(line for line,item in issue if item=="_append_pending")<min(line for line,item in issue if item=="original_binding")<min(line for line,item in issue if item=="signed_original")
        dbtree=ast.parse(Path(db.__file__).read_text())
        functions={item.name:item for item in dbtree.body if isinstance(item,ast.FunctionDef)}
        default=functions["_append_postgres_audit_event"]
        assert {"_audit_pg_connect","_append_postgres_audit_event_on_connection"}<={name for _,name in calls(default)}
        append=functions["_append_postgres_audit_event_on_connection"]
        text=ast.get_source_segment(Path(db.__file__).read_text(),append)
        assert '_lock_postgres_audit(conn, "chain")' in text and "audit idempotency key was reused" in text
        assert text.count("INSERT INTO serverware_audit_events")==1 and "metadata_audit_outbox" not in text
        assert "retain_connection=self.connections.append" in Path(local.__file__).read_text()
    else:
        raise AssertionError(name)


class GenesisAuditDeliveryControls(unittest.TestCase):
    def check(self,name):
        environment={key:value for key,value in os.environ.items() if not key.startswith("SERVERWARE_")}
        with tempfile.TemporaryDirectory(prefix="serverware-genesis-delivery-") as directory:
            environment.update(SERVERWARE_DATA_DIR=directory,SERVERWARE_RELEASE_CHANNEL="dev",SERVERWARE_PROCESS_MODE="serverware-control-plane",
                SERVERWARE_AUDIT_STORE_RUNTIME_ROLE="synthetic_audit_runtime")
            command="import sys;sys.path.insert(0,sys.argv[1]);from scripts.test_authority_genesis_audit_delivery import scenario;scenario(sys.argv[2])"
            result=subprocess.run([sys.executable,"-I","-B","-c",command,str(ROOT),name],cwd=ROOT,
                env=environment,capture_output=True,text=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_explicit_delivery_profiles_and_fixed_writer(self):self.check("versions")
    def test_pending_prefix_signature_and_atomic_finalization(self):self.check("atomic")
    def test_v1_v2_semantics_and_no_terminal_adoption(self):self.check("old")
    def test_exact_untouched_pending_original_required(self):self.check("pending")
    def test_independent_prefix_signature_and_clock_refusals(self):self.check("prefix")
    def test_real_shared_capacity_finalizer_decrements_once(self):self.check("capacity")
    def test_foreground_admission_and_update_only_contract(self):self.check("foreground")
    def test_final_v3_call_is_clipped_to_original_inclusion_expiry(self):self.check("final-deadline")
    def test_actual_owner_append_commit_readback_sign_order(self):self.check("owner-order")


if __name__=="__main__":unittest.main()
