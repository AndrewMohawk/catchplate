#!/usr/bin/env python3
"""Genuine inactive revocation kernel under one caller-owned work ledger.

The context evidence is an explicit component projection, NOT a signed receipt,
physical authenticator, authenticated selection, complete-query proof, initialized
capacity or durable commit. No planner/registry or successful result is replaced.
All controls here are authored source-only and unrun.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_query_read_work as accounting
from catchplate import authority_transition_core as core
from catchplate import authority_transition_webauthn as candidate
import test_authority_audit_capacity_work as capacity_oracle
import test_authority_revocation_query_program as recipe_oracle
import test_webauthn_revoke_transition as context_oracle
import authority_revocation_trust_fixture as trust_oracle


OPERATION = "webauthn.credential.revoke"
HINTS = ("approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids", "registration_challenge_ids")


def wire(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + nodes(child) for child in value.values())
    if type(value) in (list, tuple):
        return 1 + sum(nodes(child) for child in value)
    return 1


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def framed(domain, *values):
    material = domain.encode("ascii") + b"\0"
    return digest(material + b"".join(len(value).to_bytes(8, "big") + value for value in values))


def selected(table, key, row):
    return {"table": table, "key": copy.deepcopy(key),
        "keyDigest": framed("catchplate.policyAuthorityBusinessKey/v1", table.encode("ascii"), wire(key)),
        "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None}


def mutation(selection, row):
    kind = "UPDATE" if selection["present"] else "INSERT"
    domain = "catchplate.policyAuthorityMutationTemplate/v1"
    template = {"schema": domain, "operation": OPERATION, "table": selection["table"],
        "mutation": kind, "before": "present" if kind == "UPDATE" else "absent",
        "after": "present", "predicate": "exact-primary-key-and-full-row-cas-v1", "cardinality": 1}
    # Template IDs use the contract's length-framed DOMAIN family, unlike the
    # domain-NUL row/event commitments. Both expectations are independent.
    domain_bytes, payload = domain.encode("ascii"), wire(template)
    template_id = digest(len(domain_bytes).to_bytes(8, "big") + domain_bytes
                         + len(payload).to_bytes(8, "big") + payload)
    return {"templateId": template_id, "operation": kind, "table": selection["table"],
        "key": copy.deepcopy(selection["key"]), "keyDigest": selection["keyDigest"],
        "expectedRow": copy.deepcopy(selection["row"]), "row": copy.deepcopy(row)}


class KernelFixture:
    """Reuse reviewed row shapes, independently rebuild every expected binding."""
    def __init__(self, *, separate_signer=False, approval=True, optional_audit=True, counter=False):
        seed = context_oracle.RevokeTransitionTests()
        seed.setUp()
        original = seed.context(separate_signer=separate_signer)
        self.values = copy.deepcopy(seed.values)
        if not approval:
            self.values["control_plane_approval_ids"] = []
        if not optional_audit:
            self.values["audit_event"] = None
        self.arguments = recipe_oracle.arguments(self.values)
        self.now = original.database_now
        self.request_digest = digest(b"pure candidate revoke fixture")
        self.operation_id = framed("catchplate.policyAuthorityOperation/v2",
                                   OPERATION.encode("ascii"), self.request_digest.encode("ascii"))
        self.signer_id = "credential-signer" if separate_signer else self.values["record_id"]
        rows = [selected(item["table"], item["key"], item["row"]) for item in original.selected_rows
                if item["table"] not in ("metadata_audit_outbox", "webauthn_trust_publications",
                    "webauthn_trust_publication_high_water")
                and (approval or item["table"] != "control_plane_approvals")]
        trust = trust_oracle.trust_rows()
        high_water = trust["webauthn_trust_publication_high_water"][0]
        publication = trust["webauthn_trust_publications"][0]
        for item in rows:
            if item["table"] == "webauthn_credentials":
                row = item["row"]
                row.update(trust_oracle.credential_fields())
        rows.extend((selected("webauthn_trust_publication_high_water",
            {"authority_scope": "webauthn-metadata"}, high_water),
            selected("webauthn_trust_publications", {"id": publication["id"]}, publication)))
        challenge = next(item["row"] for item in rows if item["table"] == "webauthn_challenges"
                         and item["key"] == {"id": "assertion-challenge"})
        self.raw_challenge = b"pure local candidate challenge"
        challenge["challenge"] = base64.urlsafe_b64encode(self.raw_challenge).decode("ascii").rstrip("=")
        signer = next(item["row"] for item in rows if item["table"] == "webauthn_credentials"
                      and item["key"] == {"id": self.signer_id})
        payload = {"operationId": self.operation_id, "credentialId": signer["credential_id"],
                   "rpId": "unit.example", "origin": "https://unit.example"}
        challenge["payload_json"] = wire(payload).decode("ascii")
        public = {**payload, "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1",
                                         wire(context_oracle.challenge_binding(challenge)))}
        evidence = {"operation": OPERATION, "operationId": self.operation_id,
            "requestDigest": self.request_digest, "credentialRecordId": self.signer_id,
            "credentialId": signer["credential_id"], "challengeId": challenge["id"],
            "challengeDigest": digest(wire(public)), "clientChallengeDigest": digest(self.raw_challenge),
            "rpId": "unit.example", "origin": "https://unit.example", "priorCounter": 2, "counter": 3,
            "trustHighWaterDigest": framed("catchplate.webauthnTrustHighWater/v1",
                wire(trust_oracle.trust_high_water_document(high_water))),
            "metadataPublicationSequence": high_water["publication_sequence"],
            "credentialPolicyDigest": framed("catchplate.policyAuthorityCredentialPolicy/v1",
                wire(trust_oracle.credential_policy_document(signer, high_water)))}
        for subject in self.subjects:
            rows.append(selected("metadata_audit_outbox",
                {"id": recipe_oracle.audit_identity(self.request_digest, subject)}, None))
        if counter:
            rows.append(context_oracle.counter_selected(context_oracle.counter_row()))
        self.context = core.KernelContext(operation=OPERATION, arguments=self.arguments,
            selected_rows=tuple(rows), database_now=self.now, request_digest=self.request_digest,
            verified_webauthn_evidence=evidence)

    @property
    def subjects(self):
        return (*self.values["control_plane_approval_ids"],
                *((None,) if self.values["audit_event"] is not None else ()))

    def lookup(self, table, item_id):
        return next(item for item in self.context.selected_rows
                    if item["table"] == table and item["key"] == {"id": item_id})

    def audit(self, subject, event_type, actor_type, actor_id, event):
        identity = recipe_oracle.audit_identity(self.request_digest, subject)
        event_bytes = wire(event)
        row = {"id": identity, "event_type": event_type, "actor_type": actor_type, "actor_id": actor_id,
            "event_json": event_bytes.decode("ascii"),
            "event_digest": framed("catchplate.metadataAuditOutboxEvent/v1", event_bytes),
            "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
            "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None,
            "created_at": self.now.astimezone(timezone.utc).isoformat()}
        return mutation(self.lookup("metadata_audit_outbox", identity), row)

    def expected(self):
        values = self.values
        timestamp = self.now.astimezone(timezone.utc).isoformat()
        target = self.lookup("webauthn_credentials", values["record_id"])
        updated = {**target["row"], "revoked_at": timestamp, "revoked_by": values["actor_id"],
            "revocation_reason": values["reason"], "revocation_source": values["source"], "updated_at": timestamp}
        cascade = [mutation(target, updated)]
        for item_id in values["oidc_session_ids"]:
            item = self.lookup("oidc_browser_sessions", item_id)
            cascade.append(mutation(item, {**item["row"], "status": "revoked", "revoked_at": timestamp,
                "updated_at": timestamp, "revocation_reason": "bound_webauthn_credential_revoked"}))
        for item_id in values["approval_grant_ids"]:
            item = self.lookup("approval_grants", item_id)
            cascade.append(mutation(item, {**item["row"], "state": "revoked", "uses_remaining": 0,
                "reserved_attempt_id": None, "reserved_at_epoch_ms": None, "reservation_expires_at_epoch_ms": None}))
        for item_id in values["control_plane_approval_ids"]:
            item = self.lookup("control_plane_approvals", item_id)
            row = item["row"]
            cascade.append(mutation(item, {**row, "status": "invalidated"}))
            cascade.append(self.audit(item_id, "control_plane.approval.invalidated", "system", None,
                {**{key: row.get(key) for key in ("action", "resource_id", "payload_digest", "requester_id", "approved_by")},
                 "approval_id": item_id, "approver_webauthn_credential_id": values["record_id"],
                 "reason": "approver_webauthn_credential_revoked"}))
        for item_id in values["registration_challenge_ids"]:
            item = self.lookup("webauthn_challenges", item_id)
            cascade.append(mutation(item, {**item["row"], "used_at": timestamp}))
        counts = {"revoked_grant_count": len(values["approval_grant_ids"]),
            "revoked_control_plane_approval_count": len(values["control_plane_approval_ids"]),
            "revoked_oidc_browser_session_count": len(values["oidc_session_ids"]),
            "invalidated_registration_challenge_count": len(values["registration_challenge_ids"])}
        if values["audit_event"] is not None:
            cascade.append(self.audit(None, "webauthn.credential_revoked", "admin", values["actor_id"],
                {**values["audit_event"], "revoked_at": timestamp, "revoked_by": values["actor_id"], **counts}))
        public = copy.deepcopy(updated)
        for field in ("transports", "attestation_trust_path"):
            public[field] = json.loads(public.get(field) or "[]")
        public["attestation_trusted"] = bool(public.get("attestation_trusted"))
        cascade_result = {"ok": True, "credential": public, **counts}
        signer = self.lookup("webauthn_credentials", self.signer_id)
        challenge = self.lookup("webauthn_challenges", "assertion-challenge")
        assertion = (mutation(signer, {**signer["row"], "sign_count": 3,
                                      "last_used_at": timestamp, "updated_at": timestamp}),
                     mutation(challenge, {**challenge["row"], "used_at": timestamp}))
        merged = {(item["table"], item["keyDigest"]): copy.deepcopy(item) for item in cascade}
        for item in assertion:
            address = item["table"], item["keyDigest"]
            if address in merged:
                merged[address]["row"].update({field: item["row"][field]
                    for field in ("sign_count", "last_used_at", "updated_at")})
            else:
                merged[address] = copy.deepcopy(item)
        final = tuple(sorted(merged.values(), key=lambda item: (item["table"], item["keyDigest"], item["operation"])))
        result = copy.deepcopy(cascade_result)
        if self.signer_id == values["record_id"]:
            result["credential"].update(sign_count=3, last_used_at=timestamp, updated_at=timestamp)
        business_rows = tuple(item for item in self.context.selected_rows
            if not (item["table"] == context_oracle.COUNTER_TABLE
                    and item["key"] == {"aggregate_id": context_oracle.COUNTER_ID}))
        return {"cascade": tuple(cascade), "cascade_result": cascade_result,
                "assertion": assertion, "mutations": final, "result": result,
                "work_units": 16 + 4 * len(cascade) + len(business_rows)}


def meter(**changes):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits(**changes))


def metric_tuple(work):
    return work.hash_work, work.input_bytes, work.json_nodes


class ExpectedWork:
    """Independent sizes and declared genuine pass classes, never meter output."""
    def __init__(self):
        self.hashes = self.input_bytes = self.json_nodes = 0
        self.encodings = self.parses = 0

    def graph(self, value, byte_passes=2, node_passes=2):
        self.input_bytes += byte_passes * len(wire(value))
        self.json_nodes += node_passes * nodes(value)

    def canonical(self, value):
        self.graph(value)
        self.encodings += 1

    def compare(self, left, right):
        self.graph(left)
        self.graph(right)

    def utf8(self, value):
        self.input_bytes += 2 * len(value.encode("utf-8"))
        self.json_nodes += 2

    def stored(self, value):
        size = len(value.encode("utf-8"))
        self.input_bytes += 2 * size
        self.json_nodes += size + 2
        self.parses += 1

    def codec(self, value):
        length = len(value)
        padded = 4 * ((length + 3) // 4)
        decoded = 3 * (padded // 4)
        reencoded = 4 * ((decoded + 2) // 3)
        self.input_bytes += length + 4 * padded + 2 * decoded + 5 * reencoded

    @property
    def total(self):
        return self.hashes, self.input_bytes, self.json_nodes


def argument_work(work, fixture):
    """Existing genuine _arguments passes, independently enumerated here."""
    values = fixture.values
    work.graph(fixture.context.arguments)
    work.graph(values)
    work.utf8(values["record_id"])
    work.utf8(values["actor_id"])
    if values["reason"] is not None:
        work.utf8(values["reason"])
    if values["audit_event"] is not None:
        work.canonical(values["audit_event"])
        work.graph(values["audit_event"])
    for field in HINTS:
        for item in values[field]:
            work.utf8(item)
        work.graph(values[field], 10, 10)
    work.canonical(values)
    # Synthesis scan+copy+real canonical/decode/loads; then both intent operands.
    work.graph(values, 8, 7)
    work.encodings += 1
    work.parses += 1
    work.compare(fixture.context.arguments["businessIntent"], fixture.context.arguments["businessIntent"])


def exact_work(work, context, table, key):
    candidates = tuple(item for item in context.selected_rows if item["table"] == table)
    work.graph(context.selected_rows)
    work.graph(candidates)
    for item in candidates:
        work.graph(key)
        work.compare(item["key"], key)


def mutation_work(work, change):
    work.graph(change["key"])
    if change["expectedRow"] is not None:
        work.graph(change["expectedRow"])
    work.graph(change["row"])


def selected_set_work(work, fixture, table, hint):
    """Whole supplied-table predicates, including every nonmatching row."""
    source = fixture.context.selected_rows
    present = tuple(item for item in source if item["table"] == table and item["present"])
    work.graph(source, 4, 4)
    work.graph(present)
    selected_items = []
    for item in present:
        row = item["row"]
        work.graph(row)
        if table == "oidc_browser_sessions":
            work.compare(row.get("bound_webauthn_credential_id"), fixture.values["record_id"])
            matches = row.get("bound_webauthn_credential_id") == fixture.values["record_id"]
            if matches:
                work.graph(row.get("status"))
                matches = row.get("status") in {"pending_webauthn", "active"}
        elif table in ("approval_grants", "control_plane_approvals"):
            work.compare(row.get("approver_webauthn_credential_id"), fixture.values["record_id"])
            matches = row.get("approver_webauthn_credential_id") == fixture.values["record_id"]
            if matches:
                field, required = ("state", "active") if table == "approval_grants" else ("status", "approved")
                work.compare(row.get(field), required)
                matches = row.get(field) == required
        else:
            if table != "webauthn_challenges":
                raise AssertionError("unexpected independent predicate table")
            work.compare(fixture.values["source"], "explicit")
            work.compare(row.get("challenge_type"), "registration")
            matches = row.get("challenge_type") == "registration" and row.get("used_at") is None
            if matches:
                work.graph(row.get("expires_at"))
                matches = datetime.fromisoformat(row["expires_at"]) > fixture.now
        if matches:
            selected_items.append(item)
    selected_tuple = tuple(selected_items)
    actual = [item["key"]["id"] for item in selected_tuple]
    work.graph(selected_tuple)
    work.graph(actual, 4, 4)
    work.compare(sorted(actual), hint)
    work.graph(selected_tuple)
    ordered = sorted(selected_tuple, key=lambda item: item["key"]["id"])
    work.graph(ordered)
    return tuple(ordered)


def audit_work(work, fixture, subject, change):
    label = "credential" if subject is None else "approval:" + subject
    purpose = "webauthn-revocation-audit:" + hashlib.sha256(label.encode("utf-8")).hexdigest()
    work.utf8(label)
    work.utf8(purpose)
    work.canonical({"schema": "catchplate.policyAuthorityDeterministicIdentity/v1",
        "operation": OPERATION, "requestDigest": fixture.request_digest, "purpose": purpose})
    work.hashes += 2
    exact_work(work, fixture.context, "metadata_audit_outbox", change["key"])
    event = json.loads(change["row"]["event_json"])
    # Actual single measure + dict(event) copy + canonical emission, followed
    # by ASCII decoding and one event commitment; not four semantic walks.
    work.graph(event, 4, 3)
    work.encodings += 1
    work.hashes += 1
    mutation_work(work, change)


def cascade_work(work, fixture, expected):
    values = fixture.values
    target = fixture.lookup("webauthn_credentials", values["record_id"])
    exact_work(work, fixture.context, "webauthn_credentials", target["key"])
    work.graph(target["row"], 4, 4)  # _row copy and later updated spread
    selections = {}
    for table, hint in (("oidc_browser_sessions", "oidc_session_ids"),
                        ("approval_grants", "approval_grant_ids"),
                        ("control_plane_approvals", "control_plane_approval_ids"),
                        ("webauthn_challenges", "registration_challenge_ids")):
        selections[table] = selected_set_work(work, fixture, table, values[hint])
    changes = {(item["table"], item["key"]["id"]): item for item in expected["cascade"]}
    target_change = changes["webauthn_credentials", values["record_id"]]
    mutation_work(work, target_change)
    for table in ("oidc_browser_sessions", "approval_grants", "control_plane_approvals", "webauthn_challenges"):
        for selected_item in selections[table]:
            row = selected_item["row"]
            work.graph(row, 4, 4)  # _row copy + update spread
            mutation_work(work, changes[table, row["id"]])
            if table == "control_plane_approvals":
                work.graph(row, 4, 4)  # event projection + spread
                identity = recipe_oracle.audit_identity(fixture.request_digest, row["id"])
                audit_work(work, fixture, row["id"], changes["metadata_audit_outbox", identity])
    counts = {key: expected["cascade_result"][key] for key in (
        "revoked_grant_count", "revoked_control_plane_approval_count",
        "revoked_oidc_browser_session_count", "invalidated_registration_challenge_count")}
    if values["audit_event"] is not None:
        work.graph(values["audit_event"])
        work.graph(counts)
        identity = recipe_oracle.audit_identity(fixture.request_digest, None)
        audit_work(work, fixture, None, changes["metadata_audit_outbox", identity])
    work.graph(target_change["row"])
    for field in ("transports", "attestation_trust_path"):
        work.stored(target_change["row"].get(field) or "[]")
    work.graph(expected["cascade"])
    work.graph(counts)
    work.canonical(expected["cascade_result"])


def trust_work(work, fixture, credential, evidence):
    """Actual proved trust lookup/policy/withdrawal passes, independently sized."""
    high = next(item for item in fixture.context.selected_rows
        if item["table"] == "webauthn_trust_publication_high_water")
    publication = next(item["row"] for item in fixture.context.selected_rows
        if item["table"] == "webauthn_trust_publications" and item["present"])
    high_water = high["row"]
    exact_work(work, fixture.context, high["table"], {"authority_scope": "webauthn-metadata"})
    work.graph(high_water)
    work.graph(fixture.context.selected_rows, 4, 4)
    work.compare(publication["status"], "pending")
    work.graph(publication)
    document = trust_oracle.trust_high_water_document(high_water)
    high_digest = framed("catchplate.webauthnTrustHighWater/v1", wire(document))
    policy = trust_oracle.credential_policy_document(credential, high_water)
    policy_digest = framed("catchplate.policyAuthorityCredentialPolicy/v1", wire(policy))
    for domain, value in (("catchplate.webauthnTrustHighWater/v1", document),
                          ("catchplate.policyAuthorityCredentialPolicy/v1", policy)):
        work.canonical(value)
        work.utf8(domain)
        work.input_bytes += 9 + len(wire(value))
        work.hashes += 1
    work.utf8(credential["public_key_cose"])
    work.input_bytes += len(credential["public_key_cose"].encode("utf-8"))
    work.hashes += 1
    for left, right in (
        (high_water["authority_scope"], "webauthn-metadata"),
        (publication["scope"], "global"), (publication["status"], "published"),
        (publication["bundle_digest"], high_water["publication_digest"]),
        (publication["payload_digest"], high_water["metadata_blob_digest"]),
        (publication["rollback_epoch"], high_water["rollback_epoch"]),
        (publication["sequence"], high_water["publication_sequence"]),
        (evidence["trustHighWaterDigest"], high_digest),
        (evidence["metadataPublicationSequence"], high_water["publication_sequence"]),
        (evidence["credentialPolicyDigest"], policy_digest),
        (credential["attestation_trust_bundle_digest"], publication["bundle_digest"]),
        (credential["attestation_trust_bundle_sequence"], publication["sequence"]),
    ):
        work.compare(left, right)
    work.stored(publication["withdrawn_credential_ids_json"])
    withdrawn = json.loads(publication["withdrawn_credential_ids_json"])
    for identifier in (credential["credential_id"], credential["id"]):
        work.graph(withdrawn)
        work.graph(identifier)


def assertion_work(work, fixture, expected):
    evidence = fixture.context.verified_webauthn_evidence
    credential = fixture.lookup("webauthn_credentials", fixture.signer_id)
    challenge = fixture.lookup("webauthn_challenges", "assertion-challenge")
    row, challenge_row = credential["row"], challenge["row"]
    binding = context_oracle.challenge_binding(challenge_row)
    payload = json.loads(challenge_row["payload_json"])
    public = {**payload, "challengeId": challenge_row["id"], "challenge": challenge_row["challenge"],
        "challengeRowDigest": framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1", wire(binding))}
    work.utf8(OPERATION)
    work.utf8(fixture.request_digest)
    work.hashes += 1
    exact_work(work, fixture.context, "webauthn_credentials", credential["key"])
    work.graph(row)
    exact_work(work, fixture.context, "webauthn_challenges", challenge["key"])
    work.graph(challenge_row)
    work.stored(challenge_row["payload_json"])
    work.graph(payload)
    work.graph(challenge_row)  # prepare the actual ten-field projection from its full source row
    work.canonical(binding)
    work.hashes += 1
    work.codec(challenge_row["challenge"])
    work.graph(challenge_row)  # actual complete challenge field-set construction
    for left, right in (
        (evidence["operation"], OPERATION), (evidence["operationId"], fixture.operation_id),
        (evidence["requestDigest"], fixture.request_digest),
        (row["user_id"], fixture.values["actor_id"]), (challenge_row["user_id"], fixture.values["actor_id"]),
        (row["credential_id"], evidence["credentialId"]), (row["sign_count"], evidence["priorCounter"]),
        (challenge_row["challenge_type"], "policy_authority"), (challenge_row["scope_key"], fixture.operation_id),
        (payload["operationId"], fixture.operation_id), (payload["credentialId"], evidence["credentialId"]),
        (payload["rpId"], evidence["rpId"]), (payload["origin"], evidence["origin"]),
        (evidence["challengeDigest"], digest(wire(public))),
        (evidence["clientChallengeDigest"], digest(fixture.raw_challenge)),
    ):
        work.compare(left, right)
    work.graph(challenge_row["expires_at"])
    work.canonical(public)
    work.hashes += 2
    trust_work(work, fixture, row, evidence)
    work.graph(row)
    mutation_work(work, expected["assertion"][0])
    work.graph(challenge_row)
    mutation_work(work, expected["assertion"][1])


def expected_work(fixture, expected=None):
    expected = fixture.expected() if expected is None else expected
    work = ExpectedWork()
    argument_work(work, fixture)
    target = fixture.lookup("webauthn_credentials", fixture.values["record_id"])
    exact_work(work, fixture.context, "webauthn_credentials", target["key"])
    work.graph(target["row"])
    work.compare(target["row"]["user_id"], fixture.values["actor_id"])
    assertion_work(work, fixture, expected)
    cascade_work(work, fixture, expected)
    ordered = {}
    for item in expected["cascade"]:
        work.graph(item)
        ordered[item["table"], item["keyDigest"]] = copy.deepcopy(item)
    for item in expected["assertion"]:
        address = item["table"], item["keyDigest"]
        if address in ordered:
            current = ordered[address]
            work.compare(current["expectedRow"], item["expectedRow"])
            work.graph(current["row"])
            work.graph(item["row"])
            updates = {field: item["row"][field] for field in ("sign_count", "last_used_at", "updated_at")}
            work.graph(updates)
            current["row"].update(updates)
        else:
            work.graph(item)
            ordered[address] = copy.deepcopy(item)
    work.graph(expected["cascade_result"])
    work.graph(expected["cascade_result"]["credential"])
    for item in ordered.values():
        if item["table"] == "webauthn_credentials":
            work.compare(item["key"], {"id": fixture.values["record_id"]})
            if item["key"] == {"id": fixture.values["record_id"]}:
                break
    for item in ordered.values():
        work.graph(item)
    work.graph(expected["mutations"])
    work.graph(fixture.context.selected_rows)
    work.canonical(expected["result"])
    return work


class WebAuthnRevocationWorkTests(unittest.TestCase):
    def transition(self, fixture, *, work):
        return candidate.WebAuthnCredentialRevokeKernel()._transition(fixture.context, work=work)

    def assert_expected(self, actual, expected):
        self.assertEqual(actual.mutations, expected["mutations"])
        self.assertEqual(actual.result, expected["result"])
        self.assertEqual(actual.work_units, expected["work_units"])

    def test_challenge_binding_charges_full_projection_source_and_ten_field_encoding(self):
        original = KernelFixture().lookup("webauthn_challenges", "assertion-challenge")["row"]
        expected_digest = framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1",
                                 wire(context_oracle.challenge_binding(original)))
        for retained in (False, True):
            row = copy.deepcopy(original)
            if retained:
                row.update(retention_recovery_id="fixture-recovery",
                    retention_recovery_row_digest=digest(b"retained source row"),
                    retention_reference_mask=1)
            independent = ExpectedWork()
            independent.graph(row)
            independent.canonical(context_oracle.challenge_binding(row))
            independent.hashes += 1
            shared = meter(max_input_bytes=independent.input_bytes,
                           max_json_nodes=independent.json_nodes)
            before = copy.deepcopy(row)
            with self.subTest(retained=retained):
                self.assertEqual(candidate._challenge_row_digest(row, work=shared), expected_digest)
                self.assertEqual(metric_tuple(shared), independent.total)
                self.assertEqual(row, before)
                self.assertNotEqual(expected_digest,
                    framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1", wire(row)))
                for limits in ({"max_input_bytes": independent.input_bytes - 1},
                               {"max_json_nodes": independent.json_nodes - 1}):
                    with self.assertRaises(accounting.QueryReadWorkError):
                        candidate._challenge_row_digest(row, work=meter(**limits))
                    self.assertEqual(row, before)

    def test_real_full_cascade_matches_independent_mutations_result_and_public_route(self):
        fixture = KernelFixture()
        expected = fixture.expected()
        before = copy.deepcopy((fixture.context.arguments, fixture.context.selected_rows,
                                fixture.context.verified_webauthn_evidence))
        actual = self.transition(fixture, work=meter())
        self.assert_expected(actual, expected)
        self.assertEqual(len(actual.mutations), 9)
        self.assertEqual(candidate.WebAuthnCredentialRevokeKernel().transition(fixture.context), actual)
        self.assertEqual(self.transition(fixture, work=None), actual)
        self.assertEqual((fixture.context.arguments, fixture.context.selected_rows,
                          fixture.context.verified_webauthn_evidence), before)

    def test_genuine_hash_mutation_and_both_transition_constructor_calls(self):
        fixture = KernelFixture()
        expected = fixture.expected()
        shared = meter()
        real_hash = hashlib.sha256
        real_mutation = core.mutation
        real_post_init = core.KernelTransition.__post_init__
        constructed = []

        def observe_constructor(instance):
            constructed.append(instance)
            return real_post_init(instance)

        with patch.object(hashlib, "sha256", wraps=real_hash) as hashes, \
                patch.object(core, "mutation", wraps=real_mutation) as mutations, \
                patch.object(core.KernelTransition, "__post_init__", observe_constructor):
            actual = self.transition(fixture, work=shared)
        self.assert_expected(actual, expected)
        self.assertEqual(hashes.call_count, 7 + 3 * len(fixture.subjects))
        self.assertEqual(shared.hash_work, hashes.call_count)
        self.assertEqual(mutations.call_count, len(expected["cascade"]) + 2)
        self.assertEqual(len(constructed), 2)
        self.assertEqual(constructed[0].mutations, expected["cascade"])
        self.assertEqual(constructed[0].result, expected["cascade_result"])
        self.assertIs(constructed[1], actual)

    def test_separate_signer_preserves_target_counter_and_self_signer_merges_exactly(self):
        for separate in (False, True):
            fixture = KernelFixture(separate_signer=separate)
            expected = fixture.expected()
            actual = self.transition(fixture, work=meter())
            self.assert_expected(actual, expected)
            self.assertEqual(len(actual.mutations), 10 if separate else 9)
            rows = {(item["table"], item["key"]["id"]): item["row"] for item in actual.mutations}
            target = rows["webauthn_credentials", fixture.values["record_id"]]
            signer = rows["webauthn_credentials", fixture.signer_id]
            self.assertEqual(signer["sign_count"], 3)
            self.assertEqual(target["sign_count"], 2 if separate else 3)
            self.assertEqual(actual.result["credential"]["sign_count"], target["sign_count"])
            if separate:
                self.assertIsNone(signer["revoked_at"])
            self.assertEqual(target["revoked_at"], fixture.now.isoformat())

    def test_no_optional_audit_and_no_audit_variants_keep_real_hash_formula(self):
        real_hash = hashlib.sha256
        for approval, optional in ((True, True), (True, False), (False, True), (False, False)):
            fixture = KernelFixture(approval=approval, optional_audit=optional)
            expected = fixture.expected()
            shared = meter()
            with self.subTest(approval=approval, optional=optional), \
                    patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                actual = self.transition(fixture, work=shared)
            self.assert_expected(actual, expected)
            self.assertEqual(hashes.call_count, 7 + 3 * (int(approval) + int(optional)))
            self.assertEqual(shared.hash_work, hashes.call_count)
            self.assertEqual(sum(item["table"] == "metadata_audit_outbox" for item in actual.mutations),
                             int(approval) + int(optional))

    def test_global_registration_and_whole_predicates_not_hint_only_row_selection(self):
        fixture = KernelFixture()
        # An eligible GLOBAL registration owned by another user is still used.
        registration = fixture.lookup("webauthn_challenges", "registration-other-user")["row"]
        self.assertNotEqual(registration["user_id"], fixture.values["actor_id"])
        extras = (
            selected("oidc_browser_sessions", {"id": "unrelated-session"},
                     {"id": "unrelated-session", "bound_webauthn_credential_id": "other", "status": "active"}),
            selected("webauthn_challenges", {"id": "expired-registration"},
                     {**registration, "id": "expired-registration", "challenge_type": "registration", "used_at": None,
                      "user_id": "third-user", "expires_at": fixture.now.isoformat()}),
        )
        fixture.context = replace(fixture.context, selected_rows=(*fixture.context.selected_rows, *extras))
        expected = fixture.expected()
        independent = expected_work(fixture, expected)
        shared = meter()
        actual = self.transition(fixture, work=shared)
        self.assert_expected(actual, expected)
        self.assertEqual(metric_tuple(shared), independent.total)
        changed_ids = {item["key"]["id"] for item in actual.mutations}
        self.assertIn("registration-other-user", changed_ids)
        self.assertNotIn("expired-registration", changed_ids)
        self.assertNotIn("unrelated-session", changed_ids)
        # This validates the supplied component inventory; it does not claim
        # the inventory itself was a complete authenticated database query.

    def test_omitted_extra_and_duplicate_hints_deny_without_changing_selected_rows(self):
        for field in HINTS:
            for mode in ("omitted", "extra", "duplicate"):
                fixture = KernelFixture()
                changed = copy.deepcopy(fixture.values)
                changed[field] = ([] if mode == "omitted" else
                    sorted(changed[field] + ["unselected-dependency"]) if mode == "extra" else
                    changed[field] + changed[field][:1])
                fixture.context = replace(fixture.context, arguments=recipe_oracle.arguments(changed))
                before = copy.deepcopy(fixture.context.selected_rows)
                with self.subTest(field=field, mode=mode), self.assertRaises(core.TransitionKernelError):
                    self.transition(fixture, work=meter())
                self.assertEqual(fixture.context.selected_rows, before)

    def test_actual_owner_assertion_counter_and_challenge_binding_guards(self):
        for table, item_id in (("webauthn_credentials", "credential-target"),
                              ("webauthn_credentials", "credential-signer"),
                              ("webauthn_challenges", "assertion-challenge")):
            fixture = KernelFixture(separate_signer=True)
            fixture.lookup(table, item_id)["row"]["user_id"] = "another-owner"
            with self.subTest(table=table, item_id=item_id), self.assertRaises(core.TransitionKernelError):
                self.transition(fixture, work=meter())
        for field, value in (("requestDigest", digest(b"other request")),
                             ("operationId", digest(b"other operation")), ("counter", 2),
                             ("counter", True), ("priorCounter", 1),
                             ("challengeDigest", digest(b"other row")),
                             ("clientChallengeDigest", digest(b"other bytes"))):
            fixture = KernelFixture()
            fixture.context = replace(fixture.context, verified_webauthn_evidence={
                **fixture.context.verified_webauthn_evidence, field: value})
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                self.transition(fixture, work=meter())
        for field, value in (("used_at", "2030-01-02T03:04:05+00:00"),
                             ("expires_at", "2030-01-02T03:04:05+00:00"),
                             ("scope_key", digest(b"other scope")),
                             ("payload_json", "{not json}"), ("payload_json", "[]"),
                             ("challenge", "not canonical=")):
            fixture = KernelFixture()
            fixture.lookup("webauthn_challenges", "assertion-challenge")["row"][field] = value
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                self.transition(fixture, work=meter())

    def test_real_audit_absence_and_exact_lookup_ambiguity_are_not_bypassed(self):
        fixture = KernelFixture()
        identity = recipe_oracle.audit_identity(fixture.request_digest, "approval-one")
        audit = fixture.lookup("metadata_audit_outbox", identity)
        audit.update(present=True, row={"id": identity, "status": "audited"})
        before = copy.deepcopy(fixture.context.selected_rows)
        with self.assertRaisesRegex(core.TransitionKernelError, "audit identity"):
            self.transition(fixture, work=meter())
        self.assertEqual(fixture.context.selected_rows, before)
        for duplicated in (False, True):
            fixture = KernelFixture()
            target = fixture.lookup("webauthn_credentials", fixture.values["record_id"])
            rows = (*fixture.context.selected_rows, copy.deepcopy(target)) if duplicated else tuple(
                item for item in fixture.context.selected_rows if item is not target)
            fixture.context = replace(fixture.context, selected_rows=rows)
            with self.subTest(duplicated=duplicated), self.assertRaisesRegex(core.TransitionKernelError, "absent or ambiguous"):
                self.transition(fixture, work=meter())

    def test_actual_exact_lookup_accounts_every_candidate_before_key_comparisons(self):
        fixture = KernelFixture(separate_signer=True)
        table = "webauthn_credentials"
        key = {"id": fixture.signer_id}
        source = fixture.context.selected_rows
        candidates = tuple(item for item in source if item["table"] == table)
        self.assertEqual(len(candidates), 2)
        expected_bytes = 2 * (len(wire(source)) + len(wire(candidates)))
        expected_nodes = 2 * (nodes(source) + nodes(candidates))
        for item in candidates:
            expected_bytes += 4 * len(wire(key)) + 2 * len(wire(item["key"]))
            expected_nodes += 4 * nodes(key) + 2 * nodes(item["key"])
        shared = meter(max_input_bytes=expected_bytes, max_json_nodes=expected_nodes)
        result = fixture.context._exact(table, key, work=shared)
        self.assertIs(result, fixture.lookup(table, fixture.signer_id))
        self.assertEqual(metric_tuple(shared), (0, expected_bytes, expected_nodes))
        for limits in ({"max_input_bytes": expected_bytes - 1}, {"max_json_nodes": expected_nodes - 1}):
            with self.subTest(limits=limits), self.assertRaises(accounting.QueryReadWorkError):
                fixture.context._exact(table, key, work=meter(**limits))

    def test_stored_json_real_parse_and_utf8_depth_reservations(self):
        real_loads = json.loads
        values = ('["雪😀"]', '{"x":1,"x":2}', '[' * 128 + '0' + ']' * 128,
                  wire({"quoted": '[{\\"}]' * 129}).decode("ascii"))
        for value in values:
            size = len(value.encode("utf-8"))
            expected = real_loads(value)
            shared = meter(max_input_bytes=2 * size, max_json_nodes=size + 2)
            with patch.object(json, "loads", wraps=real_loads) as loads:
                self.assertEqual(candidate._stored_json(value, work=shared), expected)
            self.assertEqual(loads.call_count, 1)
            self.assertEqual(metric_tuple(shared), (0, 2 * size, size + 2))
            for limits in ({"max_input_bytes": 2 * size - 1}, {"max_json_nodes": size + 1}):
                shared = meter(**limits)
                with patch.object(json, "loads", wraps=real_loads) as loads:
                    with self.assertRaises(accounting.QueryReadWorkError):
                        candidate._stored_json(value, work=shared)
                self.assertEqual(loads.call_count, 0)
                self.assertEqual(metric_tuple(shared), (0, size, 1))
        shared = meter()
        with patch.object(json, "loads", wraps=real_loads) as loads:
            with self.assertRaises(ValueError):
                candidate._stored_json('[' * 129 + '0' + ']' * 129, work=shared)
        self.assertEqual(loads.call_count, 0)
        self.assertEqual(metric_tuple(shared), (0, 129, 1))
        # Stored-row JSON retains the legacy parser (including duplicate-key
        # behavior); this is not the receipt parser's separate closed contract.
        with self.assertRaises(TypeError):
            candidate._stored_json({}, work=meter())
        with patch.object(json, "loads", wraps=real_loads) as loads:
            with self.assertRaises(accounting.QueryReadWorkError):
                candidate._stored_json('"\ud800"', work=meter())
        self.assertEqual(loads.call_count, 0)

    def test_challenge_codec_uses_real_validated_base64_with_exact_preallocation(self):
        real_decode = base64.b64decode
        real_encode = base64.urlsafe_b64encode
        for raw in (b'a', b'ab', b'abc', b'real component challenge'):
            value = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
            length = len(value)
            padded = 4 * ((length + 3) // 4)
            decoded = 3 * (padded // 4)
            reencoded = 4 * ((decoded + 2) // 3)
            expected_bytes = length + 4 * padded + 2 * decoded + 5 * reencoded
            shared = meter(max_input_bytes=expected_bytes)
            with patch.object(base64, "b64decode", wraps=real_decode) as decode, \
                    patch.object(base64, "urlsafe_b64encode", wraps=real_encode) as encode:
                self.assertEqual(candidate._challenge_bytes(value, work=shared), raw)
            self.assertEqual(metric_tuple(shared), (0, expected_bytes, 0))
            self.assertEqual((decode.call_count, encode.call_count), (1, 1))
            self.assertEqual(decode.call_args.kwargs, {"altchars": b"-_", "validate": True})
            with patch.object(base64, "b64decode", wraps=real_decode) as decode:
                with self.assertRaises(accounting.QueryReadWorkError):
                    candidate._challenge_bytes(value, work=meter(max_input_bytes=expected_bytes - 1))
            self.assertEqual(decode.call_count, 0)
        for invalid in ("Zh", "Zg=", "!g", "A", None):
            with self.subTest(invalid=invalid), self.assertRaises(core.TransitionKernelError):
                candidate._challenge_bytes(invalid, work=meter())

    def test_actual_shared_lookup_and_cascade_workers_keep_one_meter_and_none_routes(self):
        fixture = KernelFixture()
        expected = fixture.expected()
        shared = meter()
        real_exact = core.KernelContext._exact
        real_cascade = candidate._plan_credential_cascade
        real_public = candidate.plan_credential_cascade
        real_arguments = candidate._arguments
        lookups = []
        cascades = []

        def exact(context, table, key, *, work):
            lookups.append(work)
            return real_exact(context, table, key, work=work)

        def cascade(context, values, *, work):
            cascades.append(work)
            return real_cascade(context, values, work=work)

        with patch.object(core.KernelContext, "_exact", exact), \
                patch.object(candidate, "_plan_credential_cascade", cascade), \
                patch.object(candidate, "plan_credential_cascade", wraps=real_public) as public, \
                patch.object(candidate, "_arguments", wraps=real_arguments) as arguments:
            actual = self.transition(fixture, work=shared)
        self.assert_expected(actual, expected)
        self.assertEqual(len(lookups), 5 + len(fixture.subjects))
        self.assertTrue(all(work is shared for work in lookups))
        self.assertEqual(cascades, [shared])
        self.assertEqual(public.call_count, 0)
        self.assertIs(arguments.call_args.kwargs["work"], shared)
        lookups.clear()
        cascades.clear()
        with patch.object(core.KernelContext, "_exact", exact), \
                patch.object(candidate, "_plan_credential_cascade", cascade), \
                patch.object(candidate, "plan_credential_cascade", wraps=real_public) as public:
            none_result = self.transition(fixture, work=None)
        self.assertEqual(none_result, actual)
        self.assertEqual(public.call_count, 1)
        self.assertEqual(cascades, [None])
        self.assertTrue(all(work is None for work in lookups))

    def test_private_work_and_selected_inventory_are_closed_before_hashing(self):
        fixture = KernelFixture()

        class MeterSubclass(accounting._ValidationWork):
            pass

        for invalid in (object(), accounting.QueryReadValidationLimits(),
                        MeterSubclass(accounting.QueryReadValidationLimits())):
            with self.assertRaises(accounting.QueryReadWorkError):
                self.transition(fixture, work=invalid)
        original = fixture.context
        variants = (
            replace(original, operation="policy.activation.prepare"),
            replace(original, selected_rows=list(original.selected_rows)),
            replace(original, selected_rows=(*original.selected_rows, object())),
            replace(original, selected_rows=(original.selected_rows[0],) * 194),
        )
        real_hash = hashlib.sha256
        for context in variants:
            fixture.context = context
            with patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(core.TransitionKernelError):
                    self.transition(fixture, work=meter())
            self.assertEqual(hashes.call_count, 0)
        fixture.context = original
        real_canonical, real_mutation, real_loads = core.canonical_bytes, core.mutation, json.loads
        for limits in ({"max_input_bytes": 1}, {"max_json_nodes": 1}):
            with patch.object(core, "canonical_bytes", wraps=real_canonical) as canonical, \
                    patch.object(core, "mutation", wraps=real_mutation) as mutation_calls, \
                    patch.object(json, "loads", wraps=real_loads) as loads, \
                    patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.transition(fixture, work=meter(**limits))
            self.assertEqual((canonical.call_count, mutation_calls.call_count, loads.call_count, hashes.call_count),
                             (0, 0, 0, 0))

    def test_private_cascade_independent_work_and_public_semantics(self):
        for optional, approval in ((True, True), (False, True), (False, False)):
            fixture = KernelFixture(optional_audit=optional, approval=approval)
            expected = fixture.expected()
            work = ExpectedWork()
            cascade_work(work, fixture, expected)
            shared = meter(max_hashes=max(1, work.hashes), max_input_bytes=work.input_bytes,
                           max_json_nodes=work.json_nodes)
            actual = candidate._plan_credential_cascade(fixture.context, fixture.values, work=shared)
            self.assertEqual(actual.mutations, expected["cascade"])
            self.assertEqual(actual.result, expected["cascade_result"])
            self.assertEqual(actual.work_units, 8 + 4 * len(expected["cascade"]))
            self.assertEqual(metric_tuple(shared), work.total)
            self.assertEqual(work.hashes, 3 * len(fixture.subjects))
            self.assertEqual(candidate.plan_credential_cascade(fixture.context, fixture.values), actual)

    def test_full_independent_schedule_covers_shared_separate_empty_unicode_and_fallbacks(self):
        fixtures = [KernelFixture(), KernelFixture(separate_signer=True),
                    KernelFixture(optional_audit=False), KernelFixture(approval=False, optional_audit=False),
                    KernelFixture(counter=True)]
        unicode_fixture = KernelFixture()
        unicode_fixture.values["reason"] = "reason 雪😀"
        unicode_fixture.values["audit_event"]["note"] = "audit 雪😀"
        unicode_fixture.arguments = recipe_oracle.arguments(unicode_fixture.values)
        unicode_fixture.context = replace(unicode_fixture.context, arguments=unicode_fixture.arguments)
        fixtures.append(unicode_fixture)
        fallback = KernelFixture()
        fallback.lookup("webauthn_credentials", fallback.values["record_id"])["row"].update(
            transports=None, attestation_trust_path="")
        fixtures.append(fallback)
        for index, fixture in enumerate(fixtures):
            expected = fixture.expected()
            work = expected_work(fixture, expected)
            shared = meter(max_hashes=work.hashes, max_input_bytes=work.input_bytes,
                           max_json_nodes=work.json_nodes)
            with self.subTest(index=index):
                self.assert_expected(self.transition(fixture, work=shared), expected)
                self.assertEqual(metric_tuple(shared), work.total)
                self.assertEqual(work.hashes, 7 + 3 * len(fixture.subjects))

    def test_actual_encoder_and_four_parser_calls_match_independent_pass_oracle(self):
        fixture = KernelFixture()
        expected = fixture.expected()
        work = expected_work(fixture, expected)
        real_dumps, real_loads, real_hash = json.dumps, json.loads, hashlib.sha256
        shared = meter()
        with patch.object(json, "dumps", wraps=real_dumps) as encodings, \
                patch.object(json, "loads", wraps=real_loads) as parses, \
                patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            actual = self.transition(fixture, work=shared)
        self.assert_expected(actual, expected)
        self.assertEqual(metric_tuple(shared), work.total)
        self.assertEqual((hashes.call_count, encodings.call_count, parses.call_count),
                         (work.hashes, work.encodings, work.parses))
        self.assertEqual(parses.call_count, 5)  # intent + payload + withdrawal list + two credential fields

    def test_exact_whole_budget_and_each_one_less_bound_genuine_work(self):
        fixture = KernelFixture()
        expected = fixture.expected()
        work = expected_work(fixture, expected)
        exact = {"max_hashes": work.hashes, "max_input_bytes": work.input_bytes,
                 "max_json_nodes": work.json_nodes}
        admitted = meter(**exact)
        self.assert_expected(self.transition(fixture, work=admitted), expected)
        self.assertEqual(metric_tuple(admitted), work.total)
        real_hash = hashlib.sha256
        for field in exact:
            limits = dict(exact)
            limits[field] -= 1
            shared = meter(**limits)
            with self.subTest(field=field), patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.transition(fixture, work=shared)
            self.assertEqual(shared.hash_work, hashes.call_count)
            self.assertLessEqual(shared.hash_work, limits["max_hashes"])
            self.assertLessEqual(shared.input_bytes, limits["max_input_bytes"])
            self.assertLessEqual(shared.json_nodes, limits["max_json_nodes"])
            if field == "max_hashes":
                self.assertEqual(hashes.call_count, work.hashes - 1)

    def test_preconsumed_and_repeated_kernel_calls_never_reset_shared_allowance(self):
        fixture = KernelFixture()
        expected = fixture.expected()
        work = expected_work(fixture, expected)
        prior = (3, 53, 7)
        exact = {"max_hashes": work.hashes + prior[0], "max_input_bytes": work.input_bytes + prior[1],
                 "max_json_nodes": work.json_nodes + prior[2]}
        shared = meter(**exact)
        shared.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        self.assert_expected(self.transition(fixture, work=shared), expected)
        self.assertEqual(metric_tuple(shared), tuple(a + b for a, b in zip(work.total, prior)))
        for field in exact:
            limits = dict(exact)
            limits[field] -= 1
            short = meter(**limits)
            short.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            with self.subTest(field=field), self.assertRaises(accounting.QueryReadWorkError):
                self.transition(fixture, work=short)
        cumulative = meter(max_hashes=2 * work.hashes, max_input_bytes=2 * work.input_bytes,
                           max_json_nodes=2 * work.json_nodes)
        for _ in range(2):
            self.assert_expected(self.transition(fixture, work=cumulative), expected)
        self.assertEqual(metric_tuple(cumulative), tuple(2 * value for value in work.total))
        with self.assertRaises(accounting.QueryReadWorkError):
            self.transition(fixture, work=cumulative)

    def test_capacity_finalizer_and_its_real_validator_share_the_same_kernel_ledger(self):
        fixture = KernelFixture(counter=True)
        expected = fixture.expected()
        kernel_work = expected_work(fixture, expected)
        capacity_work = capacity_oracle.expected_work(fixture.context, expected["mutations"])
        complete = capacity_oracle.expected_result(fixture.context, expected["mutations"])
        total = tuple(a + b for a, b in zip(kernel_work.total, capacity_work.tuple()))
        shared = meter(max_hashes=total[0], max_input_bytes=total[1], max_json_nodes=total[2])
        real_validator = capacity._validate_capacity_transition
        seen = []

        def validate(**kwargs):
            seen.append(kwargs["work"])
            return real_validator(**kwargs)

        with patch.object(capacity, "_validate_capacity_transition", validate):
            business = self.transition(fixture, work=shared)
            actual = capacity._finalize_capacity(fixture.context, business.mutations, work=shared)
        self.assert_expected(business, expected)
        self.assertEqual(actual, complete)
        self.assertEqual(seen, [shared])
        self.assertEqual(metric_tuple(shared), total)
        counter = actual[-1]
        self.assertEqual((counter["row"]["revision"], counter["row"]["live_count"], counter["row"]["next_sequence"]),
                         (8, 2, 21))
        # Synthetic compact counter rows establish component arithmetic only;
        # this does not authenticate initialization, population or currentness.

    def test_event_and_result_encodings_are_reserved_before_real_allocation(self):
        fixture = KernelFixture()
        oversized = {"blob": "x" * (2 * 1024 * 1024)}
        real_canonical, real_mutation, real_hash = core.canonical_bytes, core.mutation, hashlib.sha256
        with patch.object(core, "canonical_bytes", wraps=real_canonical) as canonical, \
                patch.object(core, "mutation", wraps=real_mutation) as mutations, \
                patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            with self.assertRaisesRegex(core.TransitionKernelError, "audit event exceeds"):
                candidate._audit_mutation(fixture.context, subject=None,
                    event_type="webauthn.credential_revoked", actor_type="admin",
                    actor_id=fixture.values["actor_id"], event=oversized, work=meter())
        # Only the actual deterministic UUID material was emitted. The large
        # event fails its measured 2MiB bound before its dict-copy/serializer.
        self.assertEqual((canonical.call_count, mutations.call_count, hashes.call_count), (1, 0, 2))
        self.assertEqual(canonical.call_args.args[0]["schema"],
                         "catchplate.policyAuthorityDeterministicIdentity/v1")
        result = {"component": "encoding only", "ok": True}
        length, count = len(wire(result)), nodes(result)
        for limits in ({"max_input_bytes": 2 * length - 1}, {"max_json_nodes": 2 * count - 1}):
            with patch.object(core, "canonical_bytes", wraps=real_canonical) as canonical:
                with self.assertRaises(accounting.QueryReadWorkError):
                    candidate._transition_result(mutations=(), result=result, work_units=1, work=meter(**limits))
            self.assertEqual(canonical.call_count, 0)
        shared = meter(max_input_bytes=2 * length, max_json_nodes=2 * count)
        with patch.object(core, "canonical_bytes", wraps=real_canonical) as canonical:
            actual = candidate._transition_result(mutations=(), result=result, work_units=1, work=shared)
        self.assertIs(type(actual), core.KernelTransition)
        self.assertEqual(actual.result, result)
        self.assertEqual(metric_tuple(shared), (0, 2 * length, 2 * count))
        self.assertEqual(canonical.call_count, 1)


if __name__ == "__main__":
    unittest.main()
