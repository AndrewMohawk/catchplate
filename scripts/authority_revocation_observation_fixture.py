"""Reusable independent populations and records for mixed revocation admission.

The fixture composes actual source declarations with independently built
primary/count trees, proofs and literal QueryRead documents. It does not use a
production admission/composition result as an oracle. The supplied request
digest, assertion IDs, challenge, roots and aggregate state are synthetic:
there is no signature, trusted time, initialized population or current-root
authority. The three explicit UPDATEs exercise read/write composition; they
are deliberately NOT the complete revocation kernel's business effects.

No test or verification is run by importing this helper. Existing test modules
provide independent encodings/tree builders, not successful verifier stubs.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_query_reads as reads
from serverware import authority_transition_webauthn as candidate
import test_authority_complete_read_write as composition_oracle
import test_authority_revocation_query_program as recipe_oracle
import test_webauthn_revoke_transition as counter_oracle


OPERATION = "webauthn.credential.revoke"
CUTOFF_US = 1_000_007
REQUEST_DIGEST = "sha256:" + "6" * 64
TARGET_ID = "credential-雪"
ACTOR_ID = "user"
ASSERTION_CHALLENGE_ID = "used"
SEPARATE_SIGNER_ID = "credential-signer"


def wire(value):
    """Independent compact ASCII wire, never a production contract serializer."""
    return recipe_oracle.wire(value)


def framed(domain, *frames):
    value = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        value.update(len(frame).to_bytes(8, "big"))
        value.update(frame)
    return "sha256:" + value.hexdigest()


def business_key_digest(table, key):
    return framed("serverware.policyAuthorityBusinessKey/v1", table.encode("ascii"), wire(key))


def observation_record(document, ordered_rows):
    """Literal declared/resolved bytes and independent exact address framing.

    This source family has no deferred references and every ordinary query
    already declares its primary-key order. Resolution therefore preserves the
    literal document. Empty complete observations retain a zero-address record;
    exact absence keeps its one address with returned_row_count == 0.
    """
    encoded = wire(document)
    addresses = []
    for selected in ordered_rows:
        digest = business_key_digest(selected["table"], selected["key"])
        if digest != selected["keyDigest"]:
            raise AssertionError("independent selected key and QueryRead address disagree")
        addresses.append(reads.QueryReadAddress(selected["table"], wire(selected["key"]),
            digest, selected["present"]))
    return reads.QueryRead(document["queryId"], encoded, encoded, tuple(addresses),
        sum(selected["present"] for selected in ordered_rows))


def credential(identifier):
    """Coherent source row for all three fixed credential projection profiles."""
    return composition_oracle.write_oracle.credential(identifier,
        credential_id="public-" + identifier, user_id=ACTOR_ID,
        revoked_by=None, revocation_reason=None, revocation_source=None,
        last_used_at=None, updated_at="1970-01-01T00:00:01+00:00",
        transports='["usb"]', attestation_trust_path='["synthetic-fixture-root"]')


def assertion_challenge(signer):
    """Exact legacy challenge-row fields; a coherent row is not signed evidence."""
    operation_id = framed("serverware.policyAuthorityOperation/v2",
        OPERATION.encode("ascii"), REQUEST_DIGEST.encode("ascii"))
    payload = {"operationId": operation_id, "credentialId": signer["credential_id"],
        "rpId": "unit.example", "origin": "https://unit.example"}
    return {"id": ASSERTION_CHALLENGE_ID,
        "challenge": base64.urlsafe_b64encode(b"mixed revocation synthetic challenge").decode("ascii").rstrip("="),
        "challenge_type": "policy_authority", "user_id": ACTOR_ID,
        "scope_key": operation_id, "approval_request_id": None,
        "payload_json": wire(payload).decode("ascii"),
        "expires_at": "1970-01-01T00:00:03+00:00", "used_at": None,
        "created_at": "1970-01-01T00:00:01.000007+00:00"}


class RevocationObservationFixture:
    """Source-generated declarations over one independent read/write graph.

    Default: nine full declarations, eight distinct global rows (seven present
    and one absent audit address), four read heads and seven read/write heads.
    A separate signer adds one declaration/row. pending_count=2 produces a real
    two-member complete observation for order controls. Disabling the audit
    removes its query/address, but keeps every empty complete role and counter.
    """

    def __init__(self, *, separate_signer=False, pending_count=1, include_audit=True,
                 counter_present=True, audit_present=False):
        if (type(separate_signer) is not bool or type(include_audit) is not bool
                or type(counter_present) is not bool or type(audit_present) is not bool
                or audit_present and not include_audit
                or type(pending_count) is not int or not 1 <= pending_count <= 31):
            raise ValueError("fixture options must preserve the source shared 32-session bound")
        self.request_digest = REQUEST_DIGEST
        self.cutoff_us = CUTOFF_US
        self.signer_id = SEPARATE_SIGNER_ID if separate_signer else TARGET_ID
        self.assertion_binding = {"credentialRecordId": self.signer_id,
                                  "challengeId": ASSERTION_CHALLENGE_ID}

        rows = composition_oracle.default_rows()
        target = credential(TARGET_ID)
        signer = credential(self.signer_id)
        rows["webauthn_credentials"] = [target] + ([signer] if separate_signer else [])
        # Keep the literal IDs recognized by the inherited strict expiry oracle.
        # 'used' becomes an unused assertion challenge, not a registration member.
        rows["webauthn_challenges"] = [row for row in rows["webauthn_challenges"]
            if row["id"] != ASSERTION_CHALLENGE_ID] + [assertion_challenge(signer)]
        for ordinal in range(1, pending_count):
            rows["oidc_browser_sessions"].append(composition_oracle.read_oracle.session(
                f"pending-extra-{ordinal:02d}", "pending_webauthn", TARGET_ID))
        rows[counter_oracle.COUNTER_TABLE] = ([counter_oracle.counter_row(
            live_count=int(audit_present), active_count=int(audit_present))] if counter_present else [])

        self.values = recipe_oracle.source_values(record_id=TARGET_ID, actor_id=ACTOR_ID,
            oidc_session_ids=sorted(row["id"] for row in rows["oidc_browser_sessions"]
                if row["bound_webauthn_credential_id"] == TARGET_ID
                and row["status"] in ("active", "pending_webauthn")),
            approval_grant_ids=["grant"], control_plane_approval_ids=[],
            registration_challenge_ids=["future"],
            audit_event={"credential_record_id": TARGET_ID, "note": "synthetic audit-雪"}
                if include_audit else None)
        self.arguments = recipe_oracle.arguments(self.values)
        if audit_present:
            event = wire(self.values["audit_event"])
            rows["metadata_audit_outbox"] = [{
                "id": recipe_oracle.audit_identity(self.request_digest, None),
                "event_type": "webauthn.credential_revoked", "actor_type": "admin", "actor_id": ACTOR_ID,
                "event_json": event.decode("ascii"),
                "event_digest": framed("serverware.metadataAuditOutboxEvent/v1", event),
                "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
                "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None,
                "created_at": "1970-01-01T00:00:01.000007+00:00",
            }]
        self.documents = tuple(recipe_oracle.expected_program(self.values,
            cutoff_us=self.cutoff_us, request_digest=self.request_digest,
            signer=self.signer_id, challenge=ASSERTION_CHALLENGE_ID,
            evidence=True, framework=True))
        self.query_program = capacity.add_capacity_query(OPERATION,
            candidate.WebAuthnCredentialRevokeKernel().queries_with_evidence_at_cutoff(
                arguments=copy.deepcopy(self.arguments), cutoff_us=self.cutoff_us,
                request_digest=self.request_digest, evidence=copy.deepcopy(self.assertion_binding)))
        # This comparison checks the real source recipe during fixture setup;
        # it never supplies expected bytes from production serialization.
        if tuple(query.contract_value() for query in self.query_program) != self.documents:
            raise AssertionError("actual source recipe differs from independent full declarations")

        self.read_write = composition_oracle.ReadWriteFixture(rows, arguments=self.arguments)
        read = self.read_write.read
        counter_contract = next(item for item in read.contracts if item.table == counter_oracle.COUNTER_TABLE)
        if counter_contract.key_columns != ("aggregate_id",):
            raise AssertionError("counter source primary key changed")

        selected_by_address = {}
        ordered_addresses = []
        point_bindings = []
        for document in self.documents:
            table = document["table"]
            if document["schema"] == "serverware.policyAuthorityCompleteIndexQuery/v1":
                info = read.joins[document["role"]]
                by_digest = {selected["keyDigest"]: selected for selected in info.selected}
                # The independently rebuilt counted tree defines member order,
                # never the global primary-key order or a production join result.
                keys = [by_digest[leaf.primary_key_digest]["key"]
                        for leaf in info.index.matches(info.interval)]
            else:
                key = copy.deepcopy(document["absentKey"])
                if tuple(sorted(key)) != read.trees[table].columns:
                    raise AssertionError("point declaration does not bind the full source primary key")
                keys = [key]
                point_bindings.append((document["queryId"], table, wire(key)))
            addresses = []
            for key in keys:
                selected = read.trees[table].selected(key)
                address = table, business_key_digest(table, key)
                previous = selected_by_address.get(address)
                if previous is not None and wire(previous) != wire(selected):
                    raise AssertionError("overlapping source queries disagree on their shared row")
                selected_by_address[address] = selected
                addresses.append(address)
            ordered_addresses.append(tuple(addresses))

        # Replace the inherited arbitrary absent-point selection, then construct
        # genuine proofs from the SAME complete independent before populations.
        read.selected = tuple(selected_by_address[address] for address in sorted(selected_by_address))
        read.proofs = tuple(read.trees[selected["table"]].proof(selected) for selected in read.selected)
        self.selected_rows = read.selected
        self.before_proofs = read.proofs
        self.ordered_rows = tuple(tuple(selected_by_address[address] for address in addresses)
                                  for addresses in ordered_addresses)
        self.point_bindings = tuple(point_bindings)
        self.query_reads = tuple(observation_record(document, ordered)
                                for document, ordered in zip(self.documents, self.ordered_rows))

        # Selection/proof repair must not remove a real writer dependency or
        # silently retain the old unrelated point query's invented address.
        for mutation in self.read_write.mutations:
            if (mutation["table"], mutation["keyDigest"]) not in selected_by_address:
                raise AssertionError("source query union omitted a fixture mutation dependency")
        if any(selected["table"] == "metadata_audit_outbox"
               and selected["key"] == {"id": "absent-point"} for selected in read.selected):
            raise AssertionError("unrequested inherited absent point survived selection closure")

    def inputs(self):
        """Fresh raw kwargs, not a prior observation or authorization result."""
        return {**self.read_write.arguments(), "request_digest": self.request_digest,
            "assertion_binding": copy.deepcopy(self.assertion_binding),
            "query_reads": copy.deepcopy(self.query_reads)}
