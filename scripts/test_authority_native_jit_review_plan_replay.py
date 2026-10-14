#!/usr/bin/env python3
"""Actual native-review owner replay with genuinely signed synthetic originals.

Independent primary/count trees, real Ed25519 enrollment/head signatures and
the existing synthetic Nitro PKI cross the actual stream, reader and kernel.
Positive observations delegate to the actual implementations; no successful
reader, proof or kernel is mocked. Negative fault injections corrupt only
already replayed writer inputs or consume the original work/time allowance.
Configuration/trust policies are explicit test inputs, not cold admission.
There is no SQL acquisition, real OIDC/WebAuthn ceremony, hardware, authorized
service selection, commit, ACK, disclosure, decision or provider execution.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _violations.append(event)
        raise AssertionError("native review replay tests forbid external effects")


if __name__ == "__main__":
    # Match the retained/native component suites: import canonical validators
    # in the development-only offline profile, never a launched authority.
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts import test_authority_audit_capacity as counters
from scripts import test_authority_native_jit_retained_history as retained_fixture
from scripts import test_authority_native_jit_review_open as reviewer_fixture
from scripts import test_native_jit_review_open_owner as opening_fixture
from serverware import authority_current_root_authorization as root_authorization
from serverware import authority_native_jit_review_plan_owner as owner
from serverware import authority_native_jit_review_plan_stream as stream
from serverware import authority_release_private_request as request_source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_index_range import IndependentIndex
from test_authority_native_jit_review_current_chunks import frames, native
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json

reads, wire, kernel = owner.reads, owner.wire, owner.kernel
crypto = opening_fixture.crypto
canonical, sha = crypto.canonical, crypto.sha256
NOW, MONO, SECOND = opening_fixture.NOW, opening_fixture.BOOT, opening_fixture.SECOND
TOKEN = reviewer_fixture.TOKEN  # Public synthetic fixture bytes, never provisioned.
LIVE = (NOW, MONO, MONO, NOW + 29 * SECOND, MONO + 29 * SECOND, 29 * SECOND, 0)


def meter():
    return _ValidationWork(QueryReadValidationLimits())


@contextmanager
def fixture_clocks():
    # All real proof validators still execute; their shared processing instant
    # is deterministic and inside the fixture's original signed intervals.
    with patch.object(time, "time_ns", new=lambda: NOW), \
            patch.object(time, "monotonic_ns", new=lambda: MONO):
        yield


def role_descriptor(key, name):
    public = key.public_key()
    return {"publicKeyPem": public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
        "spkiDigest": sha(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
        "measurementDigest": sha(("synthetic native-review " + name).encode("ascii"))}


def fractional_opening(pki):
    """Create new signed originals for the exact fractional configuration."""
    opening = opening_fixture.Fixture(pki, retained_fixture.Fixture(pki))
    opening.configuration["roles"]["planner"].update(
        requestTimeoutSeconds=1.25, databaseConnectTimeoutSeconds=0.75)
    opening.configuration_digest = crypto.framed(opening.configuration["schema"], canonical(opening.configuration))
    opening.assignment["controlPlaneConfigurationDigest"] = opening.configuration_digest
    opening.assignment_original = opening.sign_assignment()
    opening.config.update(controlPlaneConfigurationDigest=opening.configuration_digest,
        assignmentOriginal=opening.assignment_original)
    opening.challenge.update(controlPlaneConfigurationDigest=opening.configuration_digest,
        openingAssignmentSha256=sha(opening.assignment_original.encode("ascii")),
        ownerScopeDigest=sha(canonical(opening.config)))
    opening.refresh()
    return opening


def full_vector(trees):
    """Complete source inventory, with independently reconstructed tree roots.

    Source field projection is reused, so this is not an independent codec
    oracle. Neither a missing primary nor a counted descriptor is inferred.
    """
    vector = reads.vector
    document = vector._source_bindings_on_work(work=meter())
    document["primaryRoots"] = [{"table": table, "rootRevision": trees[table].root.root_revision,
        "rootDigest": trees[table].root.root_digest, "leafCount": trees[table].root.leaf_count}
        for table in vector.PRIMARY_TABLES]
    counted = []
    for identity in vector.INDEX_IDS:
        profile = vector.projection.profile_for(identity)
        tree, leaves = trees[profile.table], []
        for row in tree.rows.values():
            selected = tree.selected(tree.key(row))
            leaf = vector.projection.project_row(identity, row, primary_key_digest=selected["keyDigest"],
                primary_row_digest=sql_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                    profile.table.encode("ascii"), sql_json(row)))
            if leaf is not None:
                leaves.append(leaf)
        root = IndependentIndex(leaves, profile=profile).root
        counted.append({"indexId": identity, "table": profile.table,
            "countedProfile": vector.counted.PROFILE, "projectionDigest": profile.projection_digest,
            "projectionManifestDigest": document["projectionManifestDigest"],
            "indexRevision": 1 if leaves else 0, "rootDigest": root.digest, "leafCount": root.count})
    document["countedRoots"] = counted
    return document


class OriginalFixture:
    """Synthetic signed bytes only; no owner success object is supplied."""

    def __init__(self, pki, *, operation=wire.AUTHORIZE, opening=None,
            authorization_original=None, preparation_original=None, challenge_original=None,
            revoked=False, installed_effects=()):
        self.opening = opening or opening_fixture.Fixture(pki, retained_fixture.Fixture(pki))
        self.reviewer = reviewer_fixture.ReviewerFixture()
        # The retained request really permits alpha/beta, not the generic
        # reviewer component's different identity. Preserve its actual policy.
        self.reviewer.session["user_id"] = "oidc:alpha"
        self.reviewer.credential["user_id"] = "oidc:alpha"
        self.reviewer.binding["subject_id"] = "oidc:alpha"
        self.reviewer.rebind_roles()
        if revoked:
            self.reviewer.credential["revoked_at"] = reviewer_fixture.iso(80)
        self.challenge = (self.opening.command["challengeOriginal"]
            if challenge_original is None else challenge_original)
        self.authorization, self.preparation = authorization_original, preparation_original
        arguments = {"approval_request_id": self.opening.retained.approval["id"],
            "session_id": self.reviewer.session["id"], "challenge_sha256": sha(self.challenge.encode("ascii"))}
        if operation == wire.RECEIPT:
            arguments.update(authorization_sha256=sha(authorization_original.encode("ascii")),
                preparation_sha256=sha(preparation_original.encode("ascii")))
        self.request = request_source._derive_request(operation, arguments)
        self.operation = operation
        self.rows = self._rows(installed_effects)
        grouped = {table: [] for table in reads.vector.PRIMARY_TABLES}
        owned, queries = {}, []
        names = reads._NAMES if operation == wire.RECEIPT else reads._BASE_NAMES
        for name in names:
            query = reads._query(operation, name,
                reads._selector(name, self.request, owned, self.reviewer.publication["id"]))
            row = self.rows[name]
            if row is not None:
                expected = {column for column, _kind in reads.chunks._COLUMNS[query.table]}
                if set(row) != expected or any(row[key] != value for key, value in query.absent_key.items()):
                    raise AssertionError("signed replay fixture is not the complete exact selected SQL row")
                grouped[query.table].append(row)
            owned[name] = row
            queries.append(query)
        self.trees = {table: IndependentTree(rows, table=table,
            columns=reads.primary_contract.PRIMARY_KEY_COLUMNS[table]) for table, rows in grouped.items()}
        self.vector = full_vector(self.trees)
        self.vector_original = reads.vector._encode_on_work(self.vector, work=meter())
        self.root_key = Ed25519PrivateKey.from_private_bytes(b"R" * 32)
        self.role_keys = {name: Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)
            for name, number in (("computation", 61), ("completion", 62), ("state", 63))}
        self.enrollment = self._enrollment()
        self.originals = {"schema": reads.SCHEMA, "operation": operation,
            "requestDigest": self.request["requestDigest"], "databaseNowEpochNs": NOW,
            "trustPublicationId": self.reviewer.publication["id"],
            "completeRootVectorOriginal": self.vector_original}
        for prefix, nonce in (("head", "1"), ("finalHead", "2")):
            query, observation = self._head(nonce)
            self.originals[prefix + "QueryOriginal"] = query
            self.originals[prefix + "ObservationOriginal"] = observation
        records = []
        for name, query in zip(names, queries, strict=True):
            row, tree = self.rows[name], self.trees[query.table]
            chunks = (canonical({"rows": []}),) if row is None else tuple(
                canonical({"rows": [part]}) for part in frames(native(row)))
            records.append({"chunks": chunks, "proof": canonical(tree.proof(tree.selected(query.absent_key)))})
        self.originals["rows"] = tuple(records)

    def _rows(self, installed_effects):
        current = self.reviewer
        rows = {"session": current.session, "credential": current.credential,
            "trust_high_water": current.high, "trust_publication": current.publication,
            "rbac_authority": current.rbac, "reviewer_role": current.binding,
            "policy_high_water": {"scope": "global", "policy_id": "synthetic-policy",
                "sequence": 1, "rollback_epoch": 0,
                "policy_hash": self.opening.retained.approval["policy_hash"], "updated_at": reviewer_fixture.iso()},
            "approval": self.opening.retained.approval, "retained_pair": self.opening.retained.row}
        if self.operation == wire.RECEIPT:
            rows.update(receipt=None, audit=None,
                receipt_capacity=counters.aggregate_row(kind="jit-review-receipts",
                    partition=reads.quota._aggregate_key("jit-review-receipts", "global")[1]),
                audit_capacity=counters.aggregate_row())
            for effect in installed_effects:
                for name in ("receipt", "receipt_capacity", "audit", "audit_capacity"):
                    query = reads._query(self.operation, name,
                        reads._selector(name, self.request, {}, current.publication["id"]))
                    if effect["table"] == query.table and effect["key"] == query.absent_key:
                        rows[name] = effect["row"]
        return copy.deepcopy(rows)

    def _enrollment(self):
        payload = {"schema": root_authorization.ENROLLMENT_PAYLOAD_SCHEMA,
            "sourceRevision": reads.vector.authority.SOURCE_REVISION,
            "databaseId": "synthetic-native-review-originals", "generationDigest": sha(b"synthetic generation"),
            "initialVector": self.vector, "maxControlAgeNs": 30 * SECOND,
            "maxClockSkewNs": 0, "maxRecords": 32,
            **{name: role_descriptor(key, name) for name, key in self.role_keys.items()}}
        return root_authorization._produce_enrollment_on_work(payload=payload,
            root_private_key=self.root_key, root_public_key=self.root_key.public_key(), work=meter())

    def _head(self, nonce):
        head = reads.head
        enrolled = json.loads(self.enrollment)["payload"]
        enrollment_digest = root_authorization.plan._frame(
            root_authorization.ENROLLMENT_IDENTITY_DOMAIN, (self.enrollment,), meter())
        vector_digest = reads.vector._digest_on_work(self.vector_original, work=meter())
        query = head._encode_query_on_work(enrollment_digest=enrollment_digest,
            context_digest=self.request["requestDigest"], expected_vector_digest=vector_digest,
            challenge=nonce * 64, operation=self.operation, work=meter())
        payload = {"schema": head._profile(self.operation)[3],
            "sourceRevision": reads.vector.authority.SOURCE_REVISION,
            "enrollmentDigest": enrollment_digest, "databaseId": enrolled["databaseId"],
            "generationDigest": enrolled["generationDigest"],
            "producerMeasurementDigest": enrolled["state"]["measurementDigest"], "operation": self.operation,
            "queryDigest": head._query_digest_on_work(query, meter(), operation=self.operation),
            "challenge": nonce * 64, "contextDigest": self.request["requestDigest"],
            "issuedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 20 * SECOND,
            "sequence": 0, "headDigest": enrollment_digest, "vectorDigest": vector_digest,
            "fence": 0, "pendingRequestDigest": None, "pendingDecisionDigest": None}
        return query, head._sign_on_work(payload=payload, enrollment_bytes=self.enrollment,
            root_public_key=self.root_key.public_key(), state_private_key=self.role_keys["state"],
            now_epoch_ns=NOW, operation=self.operation, work=meter())

    def prepared(self):
        return stream.encode_on_work(self.originals, operation=self.operation,
            request_digest=self.request["requestDigest"], live_window=LIVE, deadline_ns=LIVE[4], work=meter())

    def plan_owner(self, *, root_key=None, enrollment=None):
        reader = reads.NativeJitReviewCurrentReader(operation=self.operation, dsn="dbname=never-connect-synthetic",
            connect_timeout_seconds=2, database_role="synthetic_reader", tls_client_dn="synthetic",
            tls_client_serial="1", tls_issuer_dn="synthetic", query_manifest_digest=self.vector["queryManifestDigest"],
            root_public_key=self.root_key.public_key() if root_key is None else root_key,
            enrollment_original=self.enrollment if enrollment is None else enrollment,
            current_root_client=reads.transport.CurrentRootDecisionClient(
                path="/synthetic-native-review-do-not-connect.sock", timeout_seconds=1,
                expected_peer_uid=123, expected_peer_gid=123))
        return owner.NativeJitReviewPlanOwner(read_planner=reader, configuration_payload=self.opening.configuration,
            configuration_root_key=self.opening.root.public_key(), authn_policy=self.reviewer.authn,
            trust_policy=self.reviewer.trust, live_window=LIVE, deadline_ns=LIVE[4], work=meter())

    def replay(self, selected=None, *, token=TOKEN):
        manifest, chunks = self.prepared()
        selected = self.plan_owner() if selected is None else selected
        return selected.replay(self.request, session_token_original=token, challenge_original=self.challenge,
            authorization_original=self.authorization, preparation_original=self.preparation,
            read_manifest_original=manifest, read_frames=chunks)

    def rebuilt_after(self, mutations):
        """Apply full rows to independent trees, not the production radix writer."""
        trees = dict(self.trees)
        for table in {mutation["table"] for mutation in mutations}:
            old = self.trees[table]
            rows = copy.deepcopy(old.rows)
            changes = [mutation for mutation in mutations if mutation["table"] == table]
            for mutation in changes:
                key = sql_json(mutation["key"])
                if rows.get(key) != mutation["expectedRow"]:
                    raise AssertionError("independent rebuild old row differs from genuine effect")
                if mutation["row"] is None:
                    del rows[key]
                else:
                    rows[key] = copy.deepcopy(mutation["row"])
            trees[table] = IndependentTree(list(rows.values()), table=table, columns=old.columns,
                revision=old.root.root_revision + len(changes))
        return full_vector(trees)


class NativeReviewPlanOriginalReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = crypto.SyntheticNitro()

    def setUp(self):
        self.clock = fixture_clocks()
        self.clock.__enter__()
        self.addCleanup(self.clock.__exit__, None, None, None)

    def tearDown(self):
        self.assertEqual(_violations, [], "external-effect refusal is not a passing negative control")

    def receipt_fixture(self, *, fractional=False):
        case = OriginalFixture(self.pki, opening=fractional_opening(self.pki) if fractional else None)
        authorized = case.replay()
        grant = json.loads(authorized.result_original)
        grant.pop("canDecide")
        grant["schema"] = wire.AUTHORIZATION_SCHEMA
        case.opening.grant = grant
        authorization = case.opening.sign_grant()
        preparation = {"schema": wire.PREPARATION_SCHEMA, "operation": wire.PREPARATION_OPERATION,
            "authorizationSha256": sha(authorization.encode("ascii")), "scope": grant["scope"],
            "identity": case.opening.challenge["identity"],
            "reviewDigest": case.opening.retained.child["arguments"]["redacted_display_digest"],
            "reviewFormat": wire.REVIEW_FORMAT, "preparedAtEpochNs": NOW,
            "expiresAtEpochNs": grant["expiresAtEpochNs"]}
        prepared = case.opening.sign_native(preparation, purpose="preparation")
        return OriginalFixture(self.pki, operation=wire.RECEIPT, opening=case.opening,
            authorization_original=authorization, preparation_original=prepared)

    def test_actual_authorize_replays_fractional_configuration_and_all_nine_signed_rows(self):
        case = OriginalFixture(self.pki, opening=fractional_opening(self.pki))
        selected = case.plan_owner()
        original = canonical(case.opening.configuration)
        self.assertEqual(selected._configuration_original, original)
        # A later caller mutation cannot change the held signed configuration.
        case.opening.configuration["roles"]["planner"]["requestTimeoutSeconds"] = 2.5
        result = case.replay(selected)
        value = json.loads(result.result_original)
        self.assertEqual(value["schema"], kernel.AUTHORIZE_RESULT)
        self.assertEqual(value["requestDigest"], case.request["requestDigest"])
        self.assertEqual(value["scope"]["reviewerId"], "oidc:alpha")
        self.assertEqual(value["scope"]["approvalRequestId"], case.opening.retained.approval["id"])
        self.assertEqual(value["scope"]["controlPlaneConfigurationDigest"],
            crypto.framed(case.opening.configuration["schema"], original))
        self.assertEqual(json.loads(selected._configuration_original)["roles"]["planner"]["requestTimeoutSeconds"], 1.25)
        self.assertIs(value["canDecide"], False)
        self.assertEqual(json.loads(result.mutations_original), [])
        self.assertEqual(result.before_vector_original, case.vector_original)
        self.assertIs(result.after_vector_original, result.before_vector_original)
        self.assertEqual(len(json.loads(result.read_manifest_original)["rowChunkCounts"]), 9)
        self.assertNotEqual(case.originals["headQueryOriginal"], case.originals["finalHeadQueryOriginal"])
        self.assertNotIn(TOKEN, result.read_manifest_original + result.result_original + result.request_original)
        self.assertTrue(all(TOKEN not in raw for raw in result.read_frames))
        with self.assertRaises(FrozenInstanceError):
            result.operation = wire.RECEIPT
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            case.replay(selected)

    def test_actual_fractional_receipt_replay_derives_exactly_four_unsigned_uncommitted_effects(self):
        case = self.receipt_fixture(fractional=True)
        result = case.replay()
        value, mutations = json.loads(result.result_original), json.loads(result.mutations_original)
        self.assertEqual(value["schema"], kernel.RECEIPT_RESULT)
        self.assertIs(value["canDecide"], False)
        self.assertEqual(sorted((entry["table"], entry["operation"]) for entry in mutations),
            [("approval_review_receipts", "INSERT"), ("metadata_audit_outbox", "INSERT"),
             (reads.audit_capacity.AGGREGATE_TABLE, "UPDATE"), (reads.audit_capacity.AGGREGATE_TABLE, "UPDATE")])
        self.assertEqual(len(json.loads(result.read_manifest_original)["rowChunkCounts"]), 13)
        self.assertNotIn("acknowledgmentOriginal", value)
        self.assertNotIn("signatureBase64Url", value)
        self.assertEqual(value["authorizationSha256"], sha(case.authorization.encode("ascii")))
        self.assertEqual(value["preparationSha256"], sha(case.preparation.encode("ascii")))
        self.assertEqual(result.before_vector_original, case.vector_original)
        before, after = json.loads(result.before_vector_original), json.loads(result.after_vector_original)
        self.assertEqual(after, case.rebuilt_after(mutations))
        self.assertEqual(result.after_vector_original, canonical(after))
        self.assertEqual(after["countedRoots"], before["countedRoots"])
        changes = {"approval_review_receipts": (1, 1), "metadata_audit_outbox": (1, 1),
            reads.audit_capacity.AGGREGATE_TABLE: (2, 0)}
        for old, new in zip(before["primaryRoots"], after["primaryRoots"], strict=True):
            if old["table"] in changes:
                revisions, leaves = changes[old["table"]]
                self.assertEqual(new["rootRevision"] - old["rootRevision"], revisions)
                self.assertEqual(new["leafCount"] - old["leafCount"], leaves)
                self.assertNotEqual(old["rootDigest"], new["rootDigest"])
            else:
                self.assertEqual(new, old)
        self.assertNotIn(TOKEN, result.before_vector_original + result.after_vector_original + result.mutations_original)

    def test_receipt_writer_uses_same_replay_and_only_four_authenticated_effect_rows(self):
        case = self.receipt_fixture()
        with patch.object(reads, "admit_original_reads_on_work", wraps=reads.admit_original_reads_on_work) as replay, \
                patch.object(owner.primary, "evaluate_primary_radix_batch",
                    wraps=owner.primary.evaluate_primary_radix_batch) as writer:
            actual = case.replay()
        self.assertEqual(replay.call_count, 1)
        self.assertEqual(writer.call_count, 1)
        inputs = writer.call_args.kwargs
        self.assertEqual(len(inputs["selected_rows"]), 4)
        self.assertEqual(len(inputs["before_proofs"]), 4)
        self.assertEqual(len(inputs["mutations"]), 4)
        self.assertEqual({value.table for value in inputs["table_contracts"]},
            {value.table for value in reads.primary_contract.primary_table_contracts(wire.RECEIPT)})
        self.assertEqual({value["table"] for value in inputs["selected_rows"]},
            {"approval_review_receipts", "metadata_audit_outbox", reads.audit_capacity.AGGREGATE_TABLE})
        self.assertEqual(json.loads(actual.after_vector_original),
            case.rebuilt_after(json.loads(actual.mutations_original)))

    def test_writer_refuses_corruption_after_genuine_original_replay(self):
        case = self.receipt_fixture()
        actual_writer = owner.primary.evaluate_primary_radix_batch
        for fault in ("duplicate-effect", "old-row", "proof"):
            def corrupted(**inputs):
                if fault == "proof":
                    proofs = copy.deepcopy(inputs["before_proofs"])
                    proofs[0]["rootDigest"] = "sha256:" + "f" * 64
                    inputs["before_proofs"] = proofs
                else:
                    mutations = list(copy.deepcopy(inputs["mutations"]))
                    if fault == "duplicate-effect":
                        mutations[-1] = mutations[0]
                    else:
                        changed = next(value for value in mutations if value["operation"] == "UPDATE")
                        changed["expectedRow"]["live_count"] += 1
                    inputs["mutations"] = tuple(mutations)
                return actual_writer(**inputs)
            selected = case.plan_owner()
            with self.subTest(fault=fault), patch.object(owner.primary, "evaluate_primary_radix_batch",
                    side_effect=corrupted) as writer:
                with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
                    case.replay(selected)
                self.assertEqual(writer.call_count, 1)
                self.assertTrue(selected._used and selected._failed)

    def test_complete_vector_rejects_changed_unrelated_and_counted_descriptors(self):
        case = self.receipt_fixture()
        actual_merge = owner.root_replay._merge
        for fault in ("unrelated-primary", "counted"):
            def corrupted(*args):
                after = actual_merge(*args)
                if fault == "counted":
                    after["countedRoots"][0]["indexRevision"] += 1
                else:
                    next(value for value in after["primaryRoots"]
                        if value["table"] == "credentials")["rootRevision"] += 1
                return after
            with self.subTest(fault=fault), patch.object(owner.root_replay, "_merge", side_effect=corrupted):
                with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
                    case.replay()

    def test_writer_budget_exhaustion_refuses_before_engine_without_replacing_parent(self):
        case = self.receipt_fixture()
        actual_stage = reads.NativeJitReviewReadBudget.stage
        for field, maximum in (("hashes", "max_hashes"), ("input_bytes", "max_input_bytes"),
                ("json_nodes", "max_json_nodes")):
            @contextmanager
            def exhausted(budget, name):
                with actual_stage(budget, name) as work:
                    if name == "receipt-roots":
                        counter = "hash_work" if field == "hashes" else field
                        work.charge(**{field: getattr(work.limits, maximum) - getattr(work, counter)})
                    yield work
            selected = case.plan_owner()
            with self.subTest(field=field), patch.object(reads.NativeJitReviewReadBudget, "stage", exhausted), \
                    patch.object(owner.primary, "evaluate_primary_radix_batch",
                        wraps=owner.primary.evaluate_primary_radix_batch) as writer:
                with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
                    case.replay(selected)
                self.assertEqual(writer.call_count, 0)
                self.assertTrue(selected._failed)

    def test_original_shorter_expiry_still_bounds_root_and_vector_work(self):
        case = self.receipt_fixture()
        actual_kernel = kernel._evaluate_with_reads_on_work
        for module, name in ((owner.primary, "evaluate_primary_radix_batch"),
                (owner.delta, "_validate_on_work")):
            observed = {"epoch": NOW}
            actual = getattr(module, name)
            def kernel_observation(**arguments):
                result = actual_kernel(**arguments)
                observed["expiry"] = result[0].result["expiresAtEpochNs"]
                return result
            def late(*args, **kwargs):
                result = actual(*args, **kwargs)
                observed["epoch"] = observed["expiry"]
                return result
            selected = case.plan_owner()
            with self.subTest(stage=name), \
                    patch.object(time, "time_ns", new=lambda: observed["epoch"]), \
                    patch.object(time, "monotonic_ns", new=lambda: MONO + observed["epoch"] - NOW), \
                    patch.object(kernel, "_evaluate_with_reads_on_work", side_effect=kernel_observation), \
                    patch.object(module, name, side_effect=late) as completed:
                with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
                    case.replay(selected)
                self.assertEqual(completed.call_count, 1)
                self.assertLess(observed["expiry"], LIVE[3])
                self.assertTrue(selected._failed)

    def test_fractional_configuration_change_without_new_signed_assignment_refuses(self):
        case = OriginalFixture(self.pki, opening=fractional_opening(self.pki))
        case.opening.configuration["roles"]["planner"]["requestTimeoutSeconds"] = 1.5
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            case.replay()

    def test_kernel_configuration_and_strict_branch_failures_precede_original_replay(self):
        opening = fractional_opening(self.pki)
        challenge = opening.command["challengeOriginal"]
        request = request_source._derive_request(wire.AUTHORIZE, {
            "approval_request_id": opening.retained.approval["id"], "session_id": "session-one",
            "challenge_sha256": sha(challenge.encode("ascii"))})
        for branch, value in (("configuration_payload", {"timeout": float("nan")}),
                ("configuration_payload", {"timeout": float("inf")}),
                ("configuration_payload", {"timeout": float("-inf")}),
                ("configuration_payload", {"value": "x" * reads.vector.authority.MAX_REQUEST_BYTES}),
                ("request", {"value": 1.25}), ("authn_policy", {"value": 1.25}),
                ("trust_policy", {"value": 1.25}), (None, None)):
            parent = meter()
            budget = reads.NativeJitReviewReadBudget(wire.AUTHORIZE, parent_work=parent,
                live_window=LIVE, deadline_ns=LIVE[4])
            arguments = dict(operation=wire.AUTHORIZE, request=request, read_originals={},
                session_token_original=TOKEN, challenge_original=challenge,
                configuration_payload=opening.configuration, configuration_root_key=opening.root.public_key(),
                current_root_public_key=opening.root.public_key(), current_root_enrollment_original=b"{}",
                authn_policy={}, trust_policy={}, live_window=LIVE, read_budget=budget, work=parent)
            if branch is not None:
                arguments[branch] = value
            with self.subTest(branch=branch), fixture_clocks(), patch.object(reads, "admit_original_reads_on_work",
                    side_effect=AssertionError("capture reached original replay")) as replay:
                if branch is None:
                    # The valid fractional control must cross this boundary;
                    # expiry or another earlier refusal cannot pass negatives.
                    with self.assertRaisesRegex(AssertionError, "capture reached original replay"):
                        kernel.evaluate_on_work(**arguments)
                    self.assertEqual(replay.call_count, 1)
                    self.assertFalse(budget._failed)
                else:
                    with self.assertRaises(ValueError):
                        kernel.evaluate_on_work(**arguments)
                    self.assertEqual(replay.call_count, 0)
                    self.assertTrue(budget._failed)

    def test_kernel_combined_configuration_size_and_depth_boundaries(self):
        opening = fractional_opening(self.pki)
        challenge = opening.command["challengeOriginal"]
        request = request_source._derive_request(wire.AUTHORIZE, {
            "approval_request_id": opening.retained.approval["id"], "session_id": "session-one",
            "challenge_sha256": sha(challenge.encode("ascii"))})
        maximum = reads.vector.authority.MAX_REQUEST_BYTES
        strict = {"request": request, "authn": {}, "trust": {}}
        empty = {"timeout": 1.25, "padding": ""}
        overhead = len(canonical({**strict, "configuration": empty}))
        cases = []
        for extra in (0, 1):
            configuration = {**empty, "padding": "x" * (maximum - overhead + extra)}
            self.assertEqual(len(canonical({**strict, "configuration": configuration})), maximum + extra)
            cases.append(("combined-bytes", maximum + extra, configuration, extra == 0))
        for depth in (31, 32):
            configuration = {"timeout": 1.25}
            for _ in range(depth - 1):
                configuration = {"nested": configuration}
            # Both standalone configurations fit depth 32. The kernel's
            # enclosing graph adds one level: combined depth 32 fits, 33 fails.
            cases.append(("combined-depth", depth + 1, configuration, depth == 31))
        for boundary, value, configuration, accepted in cases:
            with self.subTest(boundary=boundary, value=value):
                # These deliberately synthetic policies test capture only.
                # Each branch passes its real standalone decoder; no signed
                # configuration admission or successful original replay is claimed.
                original = canonical(configuration)
                self.assertEqual(canonical(owner._configuration(original, meter())), original)
                strict_original = canonical(strict)
                self.assertEqual(canonical(owner._json(strict_original, maximum, meter())), strict_original)
                parent = meter()
                budget = reads.NativeJitReviewReadBudget(wire.AUTHORIZE, parent_work=parent,
                    live_window=LIVE, deadline_ns=LIVE[4])
                arguments = dict(operation=wire.AUTHORIZE, request=request, read_originals={},
                    session_token_original=TOKEN, challenge_original=challenge,
                    configuration_payload=configuration, configuration_root_key=opening.root.public_key(),
                    current_root_public_key=opening.root.public_key(), current_root_enrollment_original=b"{}",
                    authn_policy={}, trust_policy={}, live_window=LIVE, read_budget=budget, work=parent)
                with patch.object(reads, "admit_original_reads_on_work",
                        side_effect=AssertionError("combined capture reached original replay")) as replay:
                    if accepted:
                        with self.assertRaisesRegex(AssertionError, "combined capture reached original replay"):
                            kernel.evaluate_on_work(**arguments)
                    else:
                        with self.assertRaises(ValueError):
                            kernel.evaluate_on_work(**arguments)
                    self.assertEqual(replay.call_count, 1 if accepted else 0)
                    self.assertEqual(budget._failed, not accepted)

    def test_wrong_token_and_root_pin_refuse_real_prepared_originals(self):
        case = OriginalFixture(self.pki)
        for changes in ({"token": b"z" * 64}, {"selected": case.plan_owner(
                root_key=Ed25519PrivateKey.from_private_bytes(b"W" * 32).public_key())}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(owner.NativeJitReviewPlanOwnerError):
                case.replay(**changes)

    def test_authenticated_revoked_credential_refuses_despite_valid_roots_and_native_signature(self):
        case = OriginalFixture(self.pki, revoked=True)
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            case.replay()

    def test_changed_native_signature_refuses_after_request_and_root_scope_are_rejoined(self):
        opening = opening_fixture.Fixture(self.pki, retained_fixture.Fixture(self.pki))
        challenge = json.loads(opening.command["challengeOriginal"])
        challenge["signature"] = "ed25519:" + crypto.encoded(b"x" * 64)
        case = OriginalFixture(self.pki, opening=opening, challenge_original=canonical(challenge).decode("ascii"))
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            case.replay()

    def test_authenticated_existing_receipt_is_not_reissued_or_acknowledged(self):
        case = self.receipt_fixture()
        actual = case.replay()
        existing = OriginalFixture(self.pki, operation=wire.RECEIPT, opening=case.opening,
            authorization_original=case.authorization, preparation_original=case.preparation,
            installed_effects=json.loads(actual.mutations_original))
        with self.assertRaises(owner.NativeJitReviewPlanOwnerError):
            existing.replay()


if __name__ == "__main__":
    unittest.main()
