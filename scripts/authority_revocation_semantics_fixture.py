"""Independent complete revocation effects, proofs and signed receipt fixtures.

The deterministic Ed25519 receipt is genuinely signed and verified by tests.
Its verifier key, identity pins, capability, clocks and expected-before vectors
are synthetic caller trust inputs, not provisioned/current database authority.
Expected effects never come from the kernel, capacity finalizer or proof engine.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_contract
from catchplate import authority_transition_core as core
from catchplate import authority_transition_webauthn as candidate
import authority_revocation_observation_fixture as observation
import test_authority_audit_capacity_work as capacity_oracle
import test_authority_complete_read_write as tree_oracle
import test_authority_revocation_proof_bundle as retained_oracle
import test_authority_revocation_query_program as recipe_oracle
import test_webauthn_assertion_work as receipt_oracle
import test_webauthn_revocation_work as kernel_oracle


OPERATION = "webauthn.credential.revoke"
wire = kernel_oracle.wire
framed = kernel_oracle.framed


class _KernelImages(kernel_oracle.KernelFixture):
    """Reuse the independent image recipe with this tree fixture's exact ID.

    Only the oracle's lookup spelling is adapted: its historical fixture calls
    the assertion challenge 'assertion-challenge'; these independent tree
    builders pin literal expiry instants for 'past', 'future' and 'used'.
    No production lookup or successful transition is substituted.
    """
    def __init__(self, fixture):
        self.values = fixture.values
        self.arguments = fixture.arguments
        self.now = fixture.database_now
        self.request_digest = fixture.request_digest
        self.operation_id = fixture.operation_id
        self.signer_id = fixture.signer_id
        self.raw_challenge = fixture.receipt.challenge
        self.context = fixture.context

    def lookup(self, table, item_id):
        if table == "webauthn_challenges" and item_id == "assertion-challenge":
            item_id = "used"
        return super().lookup(table, item_id)


class SemanticFixture:
    """One full source program and independently reconstructed before/after DB.

    The base fixture supplies row shapes only. Its three sample UPDATEs are
    discarded. Every asserted kernel effect and the exact counter CAS instead
    becomes an independent tree-builder action, including absent audit INSERTs.
    """
    def __init__(self, *, separate_signer=False, approval=True, include_audit=True,
                 pending_count=1):
        seed = observation.RevocationObservationFixture(separate_signer=separate_signer,
            pending_count=pending_count, include_audit=include_audit)
        self.rows = copy.deepcopy(seed.read_write.rows)
        self.values = copy.deepcopy(seed.values)
        self.values["control_plane_approval_ids"] = ["approval"] if approval else []
        self.arguments = recipe_oracle.arguments(self.values)
        self.cutoff_us = observation.CUTOFF_US
        self.database_now = datetime(1970, 1, 1, 0, 0, 1, 7, timezone.utc)
        self.signer_id = seed.signer_id
        self.assertion_binding = copy.deepcopy(seed.assertion_binding)
        for row in self.rows["webauthn_credentials"]:
            row["sign_count"] = 2
        for row in self.rows["control_plane_approvals"]:
            row["status"] = "approved" if approval else "denied"
        # The registration range is genuinely global, not an actor-only filter.
        next(row for row in self.rows["webauthn_challenges"] if row["id"] == "future")["user_id"] = "other-user"

        authorization = {"schema": "catchplate.policyAuthorityV9Authorization/v1",
            "operation": OPERATION, "handler": "revoke_webauthn_credential",
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": copy.deepcopy(self.arguments)}
        self.request_digest = framed("catchplate.policyAuthorityV9Request/v1", wire(authorization))
        self.operation_id = framed("catchplate.policyAuthorityOperation/v2",
            OPERATION.encode("ascii"), self.request_digest.encode("ascii"))
        self.request = {"schema": "catchplate.policyAuthorityV9Request/v1", "operation": OPERATION,
            "operationId": self.operation_id, "requestDigest": self.request_digest,
            "handler": "revoke_webauthn_credential",
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": copy.deepcopy(self.arguments)}

        self.receipt = receipt_oracle.ReceiptFixture()
        self.receipt.request_digest = self.request_digest
        self.receipt.operation_id = self.operation_id
        signer = next(row for row in self.rows["webauthn_credentials"] if row["id"] == self.signer_id)
        challenge = next(row for row in self.rows["webauthn_challenges"] if row["id"] == "used")
        challenge["challenge"] = base64.urlsafe_b64encode(self.receipt.challenge).decode("ascii").rstrip("=")
        challenge["scope_key"] = self.operation_id
        payload = {"operationId": self.operation_id, "credentialId": signer["credential_id"],
            "rpId": self.receipt.rp_id, "origin": self.receipt.origin}
        challenge["payload_json"] = wire(payload).decode("ascii")
        public = {**payload, "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1", wire(challenge))}
        self.receipt.evidence = self.receipt.sign({**self.receipt.evidence,
            "operationId": self.operation_id, "requestDigest": self.request_digest,
            "credentialRecordId": self.signer_id, "credentialId": signer["credential_id"],
            "challengeId": "used", "challengeDigest": kernel_oracle.digest(wire(public)),
            "trustHighWaterDigest": framed("catchplate.webauthnTrustHighWater/v1", wire(
                observation.trust_high_water_document(self.rows["webauthn_trust_publication_high_water"][0]))),
            "metadataPublicationSequence": self.rows["webauthn_trust_publication_high_water"][0]["publication_sequence"],
            "credentialPolicyDigest": framed("catchplate.policyAuthorityCredentialPolicy/v1", wire(
                observation.credential_policy_document(signer, self.rows["webauthn_trust_publication_high_water"][0])))})
        self.documents = tuple(recipe_oracle.expected_program(self.values,
            cutoff_us=self.cutoff_us, request_digest=self.request_digest, signer=self.signer_id,
            challenge="used", evidence=True, framework=True))
        self.query_program = capacity.add_capacity_query(OPERATION,
            candidate.WebAuthnCredentialRevokeKernel().queries_with_evidence_at_cutoff(
                arguments=copy.deepcopy(self.arguments), cutoff_us=self.cutoff_us,
                request_digest=self.request_digest, evidence=copy.deepcopy(self.assertion_binding)))
        if tuple(query.contract_value() for query in self.query_program) != self.documents:
            raise AssertionError("source program differs from independent semantic declarations")

        self.read_write = tree_oracle.ReadWriteFixture(self.rows, actions=[], arguments=self.arguments)
        self._select_program_union()
        self._context()
        self.kernel_fixture = _KernelImages(self)
        self.kernel_expected = self.kernel_fixture.expected()
        business = self.kernel_expected["mutations"]
        if any(item["table"] == "metadata_audit_outbox" for item in business):
            selected_counter = next(item for item in self.selected_rows
                if item["table"] == "policy_authority_bounded_aggregate_states")
            counter = kernel_oracle.mutation(selected_counter,
                capacity_oracle.after_counter(self.context, business))
            finalized = (*business, counter)
        else:
            finalized = business
        self.final_mutations = tuple(sorted(copy.deepcopy(finalized),
            key=lambda item: (item["table"], item["keyDigest"], item["operation"])))
        self.work_units = sum(document["workUnits"] for document in self.documents)
        self.work_units += self.kernel_expected["work_units"] + int(len(finalized) != len(business))
        self.rebuild_claim(self.final_mutations)

    def _select_program_union(self):
        read = self.read_write.read
        selected = {}
        ordered = []
        resolved_documents = []
        for document in self.documents:
            table = document["table"]
            resolved, keys = observation.source_selection(document, read)
            resolved_documents.append(resolved)
            addresses = []
            for key in keys:
                item = read.trees[table].selected(key)
                address = table, item["keyDigest"]
                selected[address] = item
                addresses.append(address)
            ordered.append(addresses)
        read.selected = tuple(selected[address] for address in sorted(selected))
        read.proofs = tuple(read.trees[item["table"]].proof(item) for item in read.selected)
        self.selected_rows, self.before_proofs = read.selected, read.proofs
        self.ordered_rows = tuple(tuple(selected[address] for address in addresses) for addresses in ordered)
        self.query_reads = tuple(observation.observation_record(document, members, resolved=resolved)
            for document, members, resolved in zip(self.documents, self.ordered_rows, resolved_documents))
        self.resolved_documents = tuple(resolved_documents)
        self.resolved_program = observation.resolved_program(self.query_program, self.resolved_documents)
        if any((item["table"], item["keyDigest"]) not in selected for item in self.read_write.mutations):
            raise AssertionError("a full mutation is absent from the genuine source query union")

    def _context(self):
        self.context = core.KernelContext(operation=OPERATION, arguments=copy.deepcopy(self.arguments),
            selected_rows=copy.deepcopy(self.selected_rows), database_now=self.database_now,
            request_digest=self.request_digest, verified_webauthn_evidence=copy.deepcopy(self.receipt.evidence),
            query_reads=copy.deepcopy(self.query_reads))

    def rebuild_claim(self, mutations):
        """Rebuild genuine proofs even for deliberately wrong semantic effects.

        This lets negatives pass real proof reconstruction and fail only the
        independent kernel/capacity comparison, without a successful stub.
        """
        actions = [(item["table"], item["key"], item["operation"], item["row"]) for item in mutations]
        self.read_write = tree_oracle.ReadWriteFixture(self.rows, actions=actions, arguments=self.arguments)
        self._select_program_union()
        self._context()
        self.kernel_fixture = _KernelImages(self)
        self.bundle, self.transition = retained_oracle.expected_documents(self)
        self.expected_before = {"businessBeforeRoots": copy.deepcopy(self.bundle["inputs"]["businessBeforeRoots"]),
            "authorizationBeforeRoots": copy.deepcopy(self.bundle["inputs"]["authorizationBeforeRoots"]),
            "indexBeforeHeads": retained_oracle.counted_heads(self)}

    def inputs(self):
        return {"bundle": copy.deepcopy(self.bundle), "transition": copy.deepcopy(self.transition),
            "request": copy.deepcopy(self.request), "evidence": copy.deepcopy(self.receipt.evidence),
            "verifier_identity": copy.deepcopy(self.receipt.identity),
            "verifier_public_key": self.receipt.key.public_key(), "capability_id": self.receipt.capability_id,
            "database_now": self.database_now, "now_epoch_ns": self.receipt.now,
            "deadline_epoch_ns": self.receipt.now + 120_000_000_000, "maximum_age_ns": 300_000_000_000,
            "expected_before": copy.deepcopy(self.expected_before)}
