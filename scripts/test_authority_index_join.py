#!/usr/bin/env python3
"""Actual primary-membership/index joins against independent tree encodings.

No database, authority registry, projector result, verified token or successful
verifier is substituted. Independent fixtures build both trees and all expected
BusinessKey, full-row, projection and interval commitments. The supplied root
pair remains declared data: these tests do not establish a signed checkpoint,
currentness, maintained SQL indexes, or enabled WebAuthn transition kernels.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_index_contract as contract
from catchplate import authority_index_join as joined
from catchplate import authority_index_projection as projection
from catchplate import authority_index_range as ranges
from catchplate import authority_radix_mutation as primary
import test_authority_index_range as index_fixture
import test_authority_radix_mutation as primary_fixture


COUNTED_PROFILE = "catchplate.policyAuthorityCountedIndex/v1"
DESCRIPTOR_DOMAIN = "catchplate.policyAuthorityIndexProjectionDescriptor/v1"
PARTITION_DOMAIN = "catchplate.policyAuthorityIndexPartition/v1"
CREDENTIAL = "webauthn_credential_id"
REGISTRATION = "webauthn_registration_unused_global"
I64 = 2**63 - 1
INDEX_IDS = (
    "webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active",
    "webauthn_control_approval_approved", "webauthn_publication_bundle_digest",
    "webauthn_publication_status", "webauthn_publication_generation",
    "oidc_session_token_digest", "oidc_activation_delivery_session_id",
    "oidc_activation_delivery_old_token_digest", "oidc_activation_delivery_new_token_digest",
    "oidc_activation_delivery_assertion_digest", "oidc_activation_delivery_challenge_id",
    "webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
    "webauthn_challenge_created_global", "webauthn_challenge_created_user",
    "webauthn_challenge_terminal_unreferenced_global", "webauthn_challenge_scope_unused",
    "webauthn_challenge_value",
)
CHALLENGE_TIMESTAMPS = {
    "webauthn_challenge_unused_global": "expires_at",
    "webauthn_challenge_unused_user": "expires_at",
    "webauthn_challenge_created_global": "created_at",
    "webauthn_challenge_created_user": "created_at",
    "webauthn_challenge_terminal_unreferenced_global": "used_at",
}
CHALLENGE_INDEX_IDS = (*CHALLENGE_TIMESTAMPS,
    "webauthn_challenge_scope_unused", "webauthn_challenge_value")


def utf8_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def framed(domain, *frames):
    material = bytearray()
    for value in (domain.encode("ascii"), *frames):
        material.extend(len(value).to_bytes(8, "big"))
        material.extend(value)
    return "sha256:" + hashlib.sha256(material).hexdigest()


def descriptor(index_id):
    """Independent literal source-profile oracle, not _Definition.document()."""
    if index_id == CREDENTIAL:
        table = "webauthn_credentials"
        row_fields = [["id", "text"], ["credential_id", "text"]]
        selector_fields = [["credential_id", "text"]]
        membership = "all-rows-including-revoked"
        partition_fields = ["credential_id"]
        order, interval = "zero16", "whole-equality-partition"
    elif index_id == REGISTRATION:
        table = "webauthn_challenges"
        row_fields = [["id", "text"], ["challenge_type", "text"],
                      ["used_at", "nullable-text"], ["expires_at", "utc-expiry"]]
        selector_fields = [["expires_after_us", "int64"]]
        membership = "challenge_type-registration/used_at-is-null"
        partition_fields = []
        order, interval = "signed64-expiry-microseconds/zero8", "expiry-strictly-after-cutoff"
    else:
        # Explicit expected descriptors, not the production definition registry.
        table, row_fields, selector_fields, membership, partition_fields, order, interval = {
            "webauthn_credential_user_history": (
                "webauthn_credentials", [["id", "text"], ["user_id", "text"]],
                [["user_id", "text"]], "all-rows-including-revoked", ["user_id"],
                "zero16", "whole-equality-partition"),
            "webauthn_credential_live_trust": (
                "webauthn_credentials", [["id", "text"], ["revoked_at", "nullable-text"],
                ["attestation_trusted", "int32"]], [],
                "revoked_at-is-null/attestation_trusted-nonzero", [], "zero16", "whole-equality-partition"),
            "webauthn_registration_unused_user": (
                "webauthn_challenges", [["id", "text"], ["challenge_type", "text"],
                ["used_at", "nullable-text"], ["expires_at", "utc-expiry"], ["user_id", "text"]],
                [["user_id", "text"], ["expires_after_us", "int64"]],
                "challenge_type-registration/used_at-is-null/no-approval-request-filter", ["user_id"],
                "signed64-expiry-microseconds/zero8", "expiry-strictly-after-cutoff"),
            "webauthn_session_credential_status": (
                "oidc_browser_sessions", [["id", "text"], ["bound_webauthn_credential_id", "nullable-text"],
                ["status", "session-status"]], [["credential_record_id", "text"], ["status", "live-session-status"]],
                "binding-nonnull/status-pending_webauthn-or-active/no-expiry-filter", ["credential_record_id", "status"],
                "zero16", "whole-equality-partition"),
            "webauthn_grant_approver_active": (
                "approval_grants", [["id", "text"], ["approver_webauthn_credential_id", "nullable-text"],
                ["state", "text"]], [["credential_record_id", "text"]],
                "binding-nonnull/state-active/no-expiry-uses-or-reservation-filter", ["credential_record_id"],
                "zero16", "whole-equality-partition"),
            "webauthn_control_approval_approved": (
                "control_plane_approvals", [["id", "text"], ["approver_webauthn_credential_id", "nullable-text"],
                ["status", "text"]], [["credential_record_id", "text"]],
                "binding-nonnull/status-approved/no-expiry-filter", ["credential_record_id"],
                "zero16", "whole-equality-partition"),
            "webauthn_publication_bundle_digest": (
                "webauthn_trust_publications", [["id", "text"], ["scope", "global-scope"],
                ["status", "publication-status"], ["bundle_digest", "text"]], [["bundle_digest", "text"]],
                "global/pending-or-published", ["bundle_digest"], "zero16", "whole-equality-partition"),
            "webauthn_publication_status": (
                "webauthn_trust_publications", [["id", "text"], ["scope", "global-scope"],
                ["status", "publication-status"]], [["status", "publication-status"]],
                "global/pending-or-published", ["status"], "zero16", "whole-equality-partition"),
            "webauthn_publication_generation": (
                "webauthn_trust_publications", [["id", "text"], ["scope", "global-scope"],
                ["status", "publication-status"], ["rollback_epoch", "int64"], ["sequence", "int64"]],
                [["minimum_rollback_epoch", "int64"], ["minimum_sequence", "int64"]],
                "global/pending-or-published", [], "signed64-rollback-epoch/signed64-sequence",
                "generation-pair-inclusive-to-partition-end/not-a-maximum-claim"),
            "oidc_session_token_digest": (
                "oidc_browser_sessions", [["id", "text"], ["token_digest", "text"]],
                [["token_digest", "text"]], "all-rows-including-expired-or-revoked", ["token_digest"],
                "zero16", "whole-equality-partition"),
            "oidc_activation_delivery_session_id": (
                "oidc_session_activation_deliveries", [["id", "text"], ["session_id", "text"]],
                [["session_id", "text"]], "all-rows-including-expired-or-consumed", ["session_id"],
                "zero16", "whole-equality-partition"),
            "oidc_activation_delivery_old_token_digest": (
                "oidc_session_activation_deliveries", [["id", "text"], ["old_token_digest", "text"]],
                [["old_token_digest", "text"]], "all-rows-including-expired-or-consumed", ["old_token_digest"],
                "zero16", "whole-equality-partition"),
            "oidc_activation_delivery_new_token_digest": (
                "oidc_session_activation_deliveries", [["id", "text"], ["new_token_digest", "text"]],
                [["new_token_digest", "text"]], "all-rows-including-expired-or-consumed", ["new_token_digest"],
                "zero16", "whole-equality-partition"),
            "oidc_activation_delivery_assertion_digest": (
                "oidc_session_activation_deliveries", [["id", "text"], ["assertion_digest", "text"]],
                [["assertion_digest", "text"]], "all-rows-including-expired-or-consumed", ["assertion_digest"],
                "zero16", "whole-equality-partition"),
            "oidc_activation_delivery_challenge_id": (
                "oidc_session_activation_deliveries", [["id", "text"], ["challenge_id", "text"]],
                [["challenge_id", "text"]], "all-rows-including-expired-or-consumed", ["challenge_id"],
                "zero16", "whole-equality-partition"),
            "webauthn_challenge_unused_global": (
                "webauthn_challenges", [["id", "challenge-id"], ["expires_at", "utc-expiry"],
                ["used_at", "nullable-utc-expiry"]], [["cutoff_us", "int64"], ["direction", "challenge-direction"]],
                "used_at-is-null", [], "signed64-expires_at/generated-challenge-id-text-order",
                "source-direction-timestamp-cutoff"),
            "webauthn_challenge_unused_user": (
                "webauthn_challenges", [["id", "challenge-id"], ["expires_at", "utc-expiry"],
                ["used_at", "nullable-utc-expiry"], ["user_id", "text"]],
                [["user_id", "text"], ["cutoff_us", "int64"], ["direction", "challenge-direction"]],
                "used_at-is-null", ["user_id"], "signed64-expires_at/generated-challenge-id-text-order",
                "source-direction-timestamp-cutoff"),
            "webauthn_challenge_created_global": (
                "webauthn_challenges", [["id", "challenge-id"], ["created_at", "utc-expiry"]],
                [["cutoff_us", "int64"], ["direction", "challenge-direction"]],
                "all-rows-including-terminal", [], "signed64-created_at/generated-challenge-id-text-order",
                "source-direction-timestamp-cutoff"),
            "webauthn_challenge_created_user": (
                "webauthn_challenges", [["id", "challenge-id"], ["created_at", "utc-expiry"], ["user_id", "text"]],
                [["user_id", "text"], ["cutoff_us", "int64"], ["direction", "challenge-direction"]],
                "all-rows-including-terminal", ["user_id"], "signed64-created_at/generated-challenge-id-text-order",
                "source-direction-timestamp-cutoff"),
            "webauthn_challenge_terminal_unreferenced_global": (
                "webauthn_challenges", [["id", "challenge-id"], ["used_at", "nullable-utc-expiry"],
                ["retention_reference_mask", "reference-mask"]],
                [["cutoff_us", "int64"], ["direction", "challenge-direction"]],
                "used_at-is-nonnull/authenticated-reference-mask-zero", [],
                "signed64-used_at/generated-challenge-id-text-order", "source-direction-timestamp-cutoff"),
            "webauthn_challenge_scope_unused": (
                "webauthn_challenges", [["id", "challenge-id"], ["challenge_type", "text"], ["user_id", "text"],
                ["scope_key", "nullable-text"], ["used_at", "nullable-utc-expiry"]],
                [["challenge_type", "text"], ["user_id", "text"], ["scope_key", "nullable-text"]],
                "used_at-is-null/no-expiry-filter", ["challenge_type", "user_id", "scope_key"],
                "zero8/generated-challenge-id-text-order", "whole-equality-partition"),
            "webauthn_challenge_value": (
                "webauthn_challenges", [["id", "challenge-id"], ["challenge", "text"]],
                [["challenge", "text"]], "all-rows-including-terminal", ["challenge"],
                "zero8/generated-challenge-id-text-order", "whole-equality-partition"),
        }[index_id]
    result = {
        "schema": "catchplate.policyAuthorityIndexProjection/v1",
        "countedProfile": COUNTED_PROFILE, "indexId": index_id, "table": table,
        "primaryKeyColumn": "id",
        "primaryKeyCommitment": "catchplate.policyAuthorityBusinessKey/v1",
        "primaryRowCommitment": "catchplate.policyAuthorityAuthenticatedRow/v1",
        "keyBytes": [32, 16, 32], "rowFields": row_fields,
        "selectorFields": selector_fields, "membership": membership,
        "partitionFields": partition_fields, "partitionDomain": PARTITION_DOMAIN,
        "partitionEncoding": "sorted-compact-UTF8-JSON/exact-typed-fields",
        "textEncoding": "exact-UTF8/no-NUL/no-normalization",
        "nullableTextEncoding": "null-or-exact-text/no-null-empty-alias",
        "maxTextBytes": 4096, "maxPartitionBytes": 32768,
        "integerBounds": {"int32": [-(2**31), 2**31 - 1], "int64": [-(2**63), I64]},
        "textEnums": {"session-status": ["pending_webauthn", "active", "revoked"],
                      "live-session-status": ["pending_webauthn", "active"],
                      "publication-status": ["pending", "published"],
                      "global-scope": ["global"]},
        "selectorFieldsClosed": True, "referencedFieldsValidatedBeforeMembership": True,
        "orderCodec": order, "intervalRule": interval,
        "expiryEncoding": "UTC-isoformat-auto-fraction/signed64-microseconds",
        "expiryEpoch": "1970-01-01T00:00:00+00:00",
        "expiryFraction": "absent-if-zero/otherwise-exact-six-digits",
        "signedOrderEncoding": "signed64-plus-2^63/eight-byte-big-endian",
        "partitionFraming": "u64be-length/every-frame-including-domain",
        "keySuffix": "BusinessKey/v1-lowercase-SHA256-hex",
    }
    if index_id in CHALLENGE_INDEX_IDS:
        result["keyBytes"] = [32, 8, 1, 32, 7]
        result["keySuffix"] = "UUID36-class0-padded16-or-sha256-class1/zero7/exact-text-order"
        result["challengeIdAdmission"] = "fresh-only/canonical-lowercase-UUID36-or-sha256/no-legacy-adoption"
        if index_id in CHALLENGE_TIMESTAMPS:
            result["textEnums"]["challenge-direction"] = ["at-or-before", "strictly-after", "all"]
    return result


def expected_profile(index_id):
    document = descriptor(index_id)
    return contract.IndexProfile(index_id, document["table"],
                                 framed(DESCRIPTOR_DOMAIN, utf8_json(document)))


def partition(profile, values):
    return framed(PARTITION_DOMAIN, COUNTED_PROFILE.encode("ascii"),
                  profile.index_id.encode("ascii"), profile.table.encode("ascii"),
                  profile.projection_digest.encode("ascii"), utf8_json(values))[7:]


def ordered_integer(value):
    return (value + 2**63).to_bytes(8, "big").hex()


def timestamp_us(value):
    """Independent exact UTC fixture clock conversion, without floating point."""
    if type(value) is not str or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?\+00:00", value) is None:
        raise AssertionError("fixture timestamp must have exact canonical UTC spelling")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AssertionError("fixture timestamp must be a real UTC date") from exc
    if parsed.isoformat() != value:
        raise AssertionError("fixture timestamp must omit an all-zero fractional part")
    elapsed = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds


def challenge_order_suffix(value):
    """Independent generated-ID order tail; no primary-key hash substitution."""
    if type(value) is str and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        return "00" + "".join(value.split("-")) + "0" * 46
    if type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return "01" + value[7:] + "0" * 14
    raise AssertionError("fixture challenge ID must be canonical UUID36 or sha256 text")


def expected_interval(profile, selector):
    definition = descriptor(profile.index_id)
    part = {name: selector[name] for name in definition["partitionFields"]}
    prefix = partition(profile, part)
    lower = prefix + "0" * 96
    successor = int(prefix, 16) + 1
    upper = None if successor == 2**256 else f"{successor:064x}" + "0" * 96
    if profile.index_id in (REGISTRATION, "webauthn_registration_unused_user"):
        cutoff = selector["expires_after_us"]
        if cutoff == I64:
            return contract.KeyInterval(lower, lower)
        lower = prefix + ordered_integer(cutoff + 1) + "0" * 80
    elif profile.index_id == "webauthn_publication_generation":
        lower = (prefix + ordered_integer(selector["minimum_rollback_epoch"])
                 + ordered_integer(selector["minimum_sequence"]) + "0" * 64)
    elif profile.index_id in CHALLENGE_TIMESTAMPS:
        cutoff, direction = selector["cutoff_us"], selector["direction"]
        if direction == "at-or-before":
            if cutoff != I64:
                upper = prefix + ordered_integer(cutoff + 1) + "0" * 80
        elif direction == "strictly-after":
            if cutoff == I64:
                return contract.KeyInterval(lower, lower)
            lower = prefix + ordered_integer(cutoff + 1) + "0" * 80
        elif direction != "all":
            raise AssertionError("fixture challenge direction must be explicit")
    return contract.KeyInterval(lower, upper)


def expected_leaf(profile, row, selected, proof, *, expiry_us=None):
    name = profile.index_id
    values = {field: row[field] for field in descriptor(name)["partitionFields"] if field in row}
    order = "0" * 32
    if name in CHALLENGE_INDEX_IDS:
        if name in ("webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
                    "webauthn_challenge_scope_unused") and row["used_at"] is not None:
            return None
        if name == "webauthn_challenge_terminal_unreferenced_global" and (
                row["used_at"] is None or row["retention_reference_mask"] != 0):
            return None
        time_order = (ordered_integer(timestamp_us(row[CHALLENGE_TIMESTAMPS[name]]))
                      if name in CHALLENGE_TIMESTAMPS else "0" * 16)
        return contract.IndexLeaf(partition(profile, values) + time_order + challenge_order_suffix(row["id"]),
                                  selected["keyDigest"], proof["rowDigest"])
    if name in (REGISTRATION, "webauthn_registration_unused_user"):
        if row["challenge_type"] != "registration" or row["used_at"] is not None:
            return None
        if expiry_us is None:
            expiry_us = timestamp_us(row["expires_at"])
        if type(expiry_us) is not int:
            raise AssertionError("fixture expiry is independently supplied integer microseconds")
        order = ordered_integer(expiry_us) + "0" * 16
    elif name == "webauthn_credential_live_trust":
        if row["revoked_at"] is not None or row["attestation_trusted"] == 0:
            return None
    elif name == "webauthn_session_credential_status":
        if row["bound_webauthn_credential_id"] is None or row["status"] == "revoked":
            return None
        values = {"credential_record_id": row["bound_webauthn_credential_id"], "status": row["status"]}
    elif name in ("webauthn_grant_approver_active", "webauthn_control_approval_approved"):
        field, required = (("state", "active") if name == "webauthn_grant_approver_active"
                           else ("status", "approved"))
        if row["approver_webauthn_credential_id"] is None or row[field] != required:
            return None
        values = {"credential_record_id": row["approver_webauthn_credential_id"]}
    elif name == "webauthn_publication_generation":
        order = ordered_integer(row["rollback_epoch"]) + ordered_integer(row["sequence"])
    return contract.IndexLeaf(partition(profile, values) + order + selected["keyDigest"][7:],
                              selected["keyDigest"], proof["rowDigest"])


def graph_nodes(value):
    if type(value) is dict:
        return 1 + len(value) + sum(graph_nodes(child) for child in value.values())
    if type(value) is list:
        return 1 + sum(graph_nodes(child) for child in value)
    return 1


def primary_metrics(tree, selected_rows, before_proofs):
    document = {
        "contracts": [{"table": tree.table, "keyColumns": ["id"],
                       "writeAccess": False, "rootClass": "business"}],
        "businessRoots": [{"table": tree.table, "rootRevision": tree.root.root_revision,
                           "rootDigest": tree.root.root_digest, "leafCount": tree.root.leaf_count}],
        "authorizationRoots": [], "selected": list(selected_rows),
        "proofs": list(before_proofs), "mutations": [],
    }
    count = len(selected_rows)
    return {"selected_rows": count, "mutations": 0, "proof_vectors": 64 * count,
            "proof_child_slots": 1024 * count, "recomputed_ancestors": 0,
            "hash_work": 66 + 70 * count,
            "input_bytes": len(primary_fixture.wire_json(document)), "json_nodes": graph_nodes(document)}


def context_document(fixture):
    return {
        "schema": "catchplate.policyAuthorityIndexPrimaryContext/v1",
        "profile": {"indexId": fixture.profile.index_id, "table": fixture.profile.table,
                    "projectionDigest": fixture.profile.projection_digest},
        "indexRevision": fixture.anchor.index_revision,
        "indexRoot": {"digest": fixture.index.root.digest, "count": fixture.index.root.count},
        "primaryRoot": {"table": fixture.primary.table,
                        "rootRevision": fixture.primary.root.root_revision,
                        "rootDigest": fixture.primary.root.root_digest,
                        "leafCount": fixture.primary.root.leaf_count},
        "selector": fixture.selector,
    }


def values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


class JoinFixture:
    def __init__(self, rows, *, index_id=CREDENTIAL, selector=None, expiry_us=None,
                 primary_revision=7, index_revision=11):
        self.profile = expected_profile(index_id)
        self.selector = ({"credential_id": "credential-雪"} if selector is None else copy.deepcopy(selector))
        self.primary = primary_fixture.IndependentTree(rows, table=self.profile.table, revision=primary_revision)
        self.all_selected = tuple(self.primary.selected({"id": row["id"]}) for row in rows)
        self.all_proofs = tuple(self.primary.proof(row) for row in self.all_selected)
        leaves = [expected_leaf(self.profile, row, selected, proof,
                                expiry_us=None if expiry_us is None else expiry_us[row["id"]])
                  for row, selected, proof in zip(rows, self.all_selected, self.all_proofs)]
        self.index = index_fixture.IndependentIndex([leaf for leaf in leaves if leaf is not None], self.profile)
        self.interval = expected_interval(self.profile, self.selector)
        self.frontier = self.index.frontier(self.interval)
        selected_keys = {leaf.primary_key_digest for leaf in self.index.matches(self.interval)}
        self.selected = tuple(row for row in self.all_selected if row["keyDigest"] in selected_keys)
        self.proofs = tuple(proof for proof in self.all_proofs if proof["keyDigest"] in selected_keys)
        self.anchor = joined.IndexPrimaryAnchor(index_id, index_revision, self.index.root, self.primary.root)

    def arguments(self):
        return {"anchor": self.anchor, "selector": copy.deepcopy(self.selector),
                "frontier": self.frontier, "selected_rows": copy.deepcopy(self.selected),
                "before_proofs": copy.deepcopy(self.proofs),
                "limits": joined.IndexJoinLimits(primary_fixture.LIMITS, ranges.IndexRangeLimits())}


class AuthorityIndexJoinTests(unittest.TestCase):
    def setUp(self):
        # Deliberately repeated credential_id exercises a join over component
        # trees, not PostgreSQL's separate credential_id UNIQUE constraint.
        self.rows = [
            {"id": "live-雪", "credential_id": "credential-雪", "revoked_at": None,
             "sign_count": 4, "metadata": {"note": "☃", "flags": [True, None]}},
            {"id": "retired", "credential_id": "credential-雪", "revoked_at": "historical",
             "sign_count": 0, "metadata": {}},
            {"id": "elsewhere", "credential_id": "other-partition", "revoked_at": None},
        ]
        self.fixture = JoinFixture(self.rows)

    def verify(self, fixture=None, **changes):
        args = (self.fixture if fixture is None else fixture).arguments()
        args.update(changes)
        return joined.join_index_range(**args)

    def assert_exact(self, fixture):
        result = self.verify(fixture)
        self.assertEqual(result.anchor, fixture.anchor)
        self.assertEqual(result.interval, fixture.interval)
        self.assertEqual(result.leaves, fixture.index.matches(fixture.interval))
        context_wire = primary_fixture.wire_json(context_document(fixture))
        self.assertEqual(result.context_digest, primary_fixture.wire_digest(
            "catchplate.policyAuthorityIndexPrimaryContext/v1", context_wire))
        expected_primary = primary_metrics(fixture.primary, fixture.selected, fixture.proofs)
        expected_index = index_fixture.metric_oracle(fixture.profile, fixture.index.root,
                                                     fixture.interval, fixture.frontier)
        self.assertEqual(values(result.metrics.primary), expected_primary)
        self.assertEqual(values(result.metrics.index), expected_index)
        self.assertEqual(result.metrics.context_hashes, 69)
        self.assertEqual(result.metrics.projection_hashes, 2 + 2 * len(fixture.selected))
        self.assertEqual(result.metrics.context_bytes, len(context_wire))
        self.assertEqual(result.metrics.total_hashes,
                         expected_primary["hash_work"] + expected_index["hashes"] + 69
                         + 2 + 2 * len(fixture.selected))
        self.assertEqual(result.metrics.total_input_bytes,
                         expected_primary["input_bytes"] + expected_index["input_bytes"] + len(context_wire))
        return result

    def arguments_for_index(self, tree):
        args = self.fixture.arguments()
        args["anchor"] = replace(self.fixture.anchor, index_root=tree.root)
        args["frontier"] = tree.frontier(self.fixture.interval)
        return args

    def test_real_membership_and_complete_range_match_independent_context_and_metrics(self):
        result = self.assert_exact(self.fixture)
        self.assertEqual(len(result.leaves), 2)
        self.assertEqual(result.metrics.primary.hash_work, 206)
        self.assertEqual(result.anchor.primary_root.leaf_count, 3)
        # Outside-partition subtrees remain authenticated, not returned rows.
        self.assertTrue(any(type(node) is contract.OpaqueSubtree for node in self.fixture.frontier))
        selected = self.fixture.selected[0]
        sql_path = primary_fixture.sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1",
                                               self.fixture.primary.table.encode(),
                                               primary_fixture.sql_json(selected["key"]))
        self.assertNotEqual(selected["keyDigest"], sql_path)
        for leaf in result.leaves:
            self.assertEqual(leaf.key[-64:], leaf.primary_key_digest[7:])

    def test_all_eleven_source_profiles_join_real_rows_with_independent_encodings(self):
        # Preserve the historical test ID while exercising the exact current 24 profiles.
        challenge = {
            "challenge_type": "authentication", "challenge": "challenge-雪", "user_id": "alice",
            "scope_key": None, "used_at": None, "retention_reference_mask": 0,
            "created_at": "1969-12-31T23:59:59.999999+00:00",
            "expires_at": "1970-01-01T00:00:00.000001+00:00",
        }
        cases = (
            (CREDENTIAL, {"credential_id": "雪"}, {"credential_id": "雪", "revoked_at": "old"}),
            ("webauthn_credential_user_history", {"user_id": "alice"},
             {"user_id": "alice", "revoked_at": "old"}),
            ("webauthn_credential_live_trust", {}, {"revoked_at": None, "attestation_trusted": -1}),
            (REGISTRATION, {"expires_after_us": 0},
             {"challenge_type": "registration", "used_at": None, "expires_at": "1970-01-01T00:00:00.000001+00:00"}),
            ("webauthn_registration_unused_user", {"user_id": "alice", "expires_after_us": 0},
             {"challenge_type": "registration", "used_at": None, "expires_at": "1970-01-01T00:00:00.000001+00:00",
              "user_id": "alice", "approval_request_id": "retained-not-filtered"}),
            ("webauthn_session_credential_status", {"credential_record_id": "record", "status": "active"},
             {"bound_webauthn_credential_id": "record", "status": "active", "expires_at": "old"}),
            ("webauthn_grant_approver_active", {"credential_record_id": "record"},
             {"approver_webauthn_credential_id": "record", "state": "active", "uses_remaining": 0,
              "reserved_at": "retained", "expires_at": "old"}),
            ("webauthn_control_approval_approved", {"credential_record_id": "record"},
             {"approver_webauthn_credential_id": "record", "status": "approved", "expires_at": "old"}),
            ("webauthn_publication_bundle_digest", {"bundle_digest": "bundle"},
             {"scope": "global", "status": "pending", "bundle_digest": "bundle"}),
            ("webauthn_publication_status", {"status": "published"},
             {"scope": "global", "status": "published"}),
            ("webauthn_publication_generation", {"minimum_rollback_epoch": -1, "minimum_sequence": 2},
             {"scope": "global", "status": "published", "rollback_epoch": -1, "sequence": 2}),
            ("oidc_session_token_digest", {"token_digest": "token"},
             {"token_digest": "token", "status": "revoked", "expires_at": "old"}),
            ("oidc_activation_delivery_session_id", {"session_id": "session"}, {"session_id": "session"}),
            ("oidc_activation_delivery_old_token_digest", {"old_token_digest": "old-token"},
             {"old_token_digest": "old-token"}),
            ("oidc_activation_delivery_new_token_digest", {"new_token_digest": "new-token"},
             {"new_token_digest": "new-token"}),
            ("oidc_activation_delivery_assertion_digest", {"assertion_digest": "assertion"},
             {"assertion_digest": "assertion"}),
            ("oidc_activation_delivery_challenge_id", {"challenge_id": "challenge"}, {"challenge_id": "challenge"}),
            ("webauthn_challenge_unused_global", {"cutoff_us": 0, "direction": "strictly-after"}, challenge),
            ("webauthn_challenge_unused_user", {"user_id": "alice", "cutoff_us": 0, "direction": "strictly-after"},
             challenge),
            ("webauthn_challenge_created_global", {"cutoff_us": -2, "direction": "strictly-after"}, challenge),
            ("webauthn_challenge_created_user", {"user_id": "alice", "cutoff_us": -2, "direction": "strictly-after"},
             challenge),
            ("webauthn_challenge_terminal_unreferenced_global", {"cutoff_us": 0, "direction": "at-or-before"},
             {**challenge, "used_at": "1970-01-01T00:00:00+00:00"}),
            ("webauthn_challenge_scope_unused",
             {"challenge_type": "authentication", "user_id": "alice", "scope_key": None}, challenge),
            ("webauthn_challenge_value", {"challenge": "challenge-雪"}, challenge),
        )
        self.assertEqual(len(INDEX_IDS), 24)
        self.assertEqual(projection.INDEX_IDS, INDEX_IDS)
        self.assertEqual(tuple(name for name, _, _ in cases), INDEX_IDS)
        for name, selector, row in cases:
            with self.subTest(index=name):
                ids = (("12345678-1234-4234-8234-123456789abc", "sha256:" + "a" * 64)
                       if name in CHALLENGE_INDEX_IDS else ("id-雪",))
                fixture = JoinFixture([{"id": identifier, **row} for identifier in ids], index_id=name,
                                      selector=selector, expiry_us={identifier: 1 for identifier in ids})
                self.assertEqual(projection.profile_for(name), fixture.profile)
                self.assertEqual(len(self.assert_exact(fixture).leaves), len(ids))
                if name in CHALLENGE_TIMESTAMPS:
                    for cutoff in (-(2**63), -1, 0, 1, I64):
                        for direction in ("at-or-before", "strictly-after", "all"):
                            query = {**selector, "cutoff_us": cutoff, "direction": direction}
                            self.assertEqual(projection.query_interval(name, query), expected_interval(fixture.profile, query))

    def test_registration_microsecond_cutoff_and_generation_lexicographic_boundaries(self):
        rows = [{"id": label, "challenge_type": "registration", "used_at": None, "expires_at": stamp}
                for label, stamp in (("before", "1969-12-31T23:59:59.999999+00:00"),
                                     ("equal", "1970-01-01T00:00:00+00:00"),
                                     ("after", "1970-01-01T00:00:00.000001+00:00"))]
        expiry = {"before": -1, "equal": 0, "after": 1}
        fixture = JoinFixture(rows, index_id=REGISTRATION, selector={"expires_after_us": 0}, expiry_us=expiry)
        self.assertEqual(len(self.assert_exact(fixture).leaves), 1)
        self.assertEqual(fixture.selected[0]["key"], {"id": "after"})
        generation = "webauthn_publication_generation"
        rows = [{"id": str(index), "scope": "global", "status": "pending", "rollback_epoch": epoch,
                 "sequence": sequence} for index, (epoch, sequence) in enumerate(((-1, 9), (0, 2), (0, 3), (1, -5)))]
        fixture = JoinFixture(rows, index_id=generation,
                              selector={"minimum_rollback_epoch": 0, "minimum_sequence": 2})
        self.assertEqual(len(self.assert_exact(fixture).leaves), 3)

    def test_empty_ranges_still_bind_and_revalidate_the_primary_root_context(self):
        for fixture in (JoinFixture([], primary_revision=0, index_revision=0),
                        JoinFixture(self.rows, selector={"credential_id": "no-such-credential"})):
            with self.subTest(population=fixture.primary.root.leaf_count):
                result = self.assert_exact(fixture)
                self.assertEqual(result.leaves, ())
                self.assertEqual(result.metrics.primary.hash_work, 66)
                self.assertEqual(result.metrics.projection_hashes, 2)
                bad = forged(fixture.anchor.primary_root, root_revision=True)
                with self.assertRaises(contract.IndexRangeError):
                    self.verify(fixture, anchor=forged(fixture.anchor, primary_root=bad))
        fixture = JoinFixture([{"id": "one", "challenge_type": "registration", "used_at": None,
                                "expires_at": "1970-01-01T00:00:00+00:00"}], index_id=REGISTRATION,
                              selector={"expires_after_us": I64}, expiry_us={"one": 0})
        self.assertEqual(fixture.interval.lower, fixture.interval.upper)
        self.assertEqual(self.assert_exact(fixture).leaves, ())
        self.assertTrue(fixture.frontier)

    def test_primary_and_proof_input_orders_are_independent_of_index_leaf_order(self):
        expected = self.verify()
        result = self.verify(selected_rows=tuple(reversed(self.fixture.selected)),
                             before_proofs=self.fixture.proofs)
        self.assertEqual(result, expected)
        self.assertEqual(self.verify(before_proofs=tuple(reversed(self.fixture.proofs))), expected)

    def test_valid_index_with_false_row_digest_rejects_at_actual_join(self):
        leaves = list(self.fixture.index.leaves.values())
        leaves[0] = replace(leaves[0], primary_row_digest=index_fixture.digest("not-the-full-row"))
        tree = index_fixture.IndependentIndex(leaves, self.fixture.profile)
        args = self.arguments_for_index(tree)
        # Both independent tree and actual range verifier accept this declared
        # tree; only the real primary-row join establishes its mismatch.
        ranges.reconstruct_complete_index_range(profile=tree.profile, expected_root=tree.root,
            interval=self.fixture.interval, frontier=args["frontier"], limits=ranges.IndexRangeLimits())
        with self.assertRaisesRegex(joined.IndexJoinError, "row projection differs"):
            joined.join_index_range(**args)

    def test_fresh_authenticated_row_with_stale_index_commitment_is_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["metadata"]["note"] = "changed full-row field not used by projection"
        fresh = JoinFixture(rows, primary_revision=8)
        with self.assertRaisesRegex(joined.IndexJoinError, "row projection differs"):
            self.verify(selected_rows=fresh.selected, before_proofs=fresh.proofs,
                        anchor=replace(self.fixture.anchor, primary_root=fresh.primary.root))

    def test_valid_index_wrong_suffix_order_or_partition_cannot_replace_row_projection(self):
        original = next(leaf for leaf in self.fixture.index.leaves.values()
                        if leaf.primary_key_digest == self.fixture.selected[0]["keyDigest"])
        changed_keys = (original.key[:64] + "1" + original.key[65:],
                        original.key[:96] + ("1" if original.key[96] != "1" else "2") + original.key[97:])
        for bad_key in changed_keys:
            with self.subTest(key=bad_key):
                leaves = [replace(leaf, key=bad_key) if leaf == original else leaf
                          for leaf in self.fixture.index.leaves.values()]
                tree = index_fixture.IndependentIndex(leaves, self.fixture.profile)
                with self.assertRaisesRegex(joined.IndexJoinError, "row projection differs"):
                    joined.join_index_range(**self.arguments_for_index(tree))
        rows = copy.deepcopy(self.rows)
        rows[0]["credential_id"] = "moved-to-another-partition"
        fresh = JoinFixture(rows, primary_revision=8)
        fresh_row = fresh.all_selected[0]
        fresh_proof = fresh.all_proofs[0]
        leaves = [replace(leaf, primary_row_digest=fresh_proof["rowDigest"]) if leaf == original else leaf
                  for leaf in self.fixture.index.leaves.values()]
        args = self.arguments_for_index(index_fixture.IndependentIndex(leaves, self.fixture.profile))
        args.update(anchor=replace(args["anchor"], primary_root=fresh.primary.root),
                    selected_rows=(fresh_row, fresh.all_selected[1]),
                    before_proofs=(fresh_proof, fresh.all_proofs[1]))
        with self.assertRaisesRegex(joined.IndexJoinError, "row projection differs"):
            joined.join_index_range(**args)

    def test_same_count_extra_or_absent_primary_member_cannot_join_index_identity(self):
        for extra in (self.fixture.all_selected[2], self.fixture.primary.selected({"id": "absent"})):
            with self.subTest(present=extra["present"]):
                selected = (self.fixture.selected[0], extra)
                proofs = tuple(self.fixture.primary.proof(row) for row in selected)
                with self.assertRaisesRegex(joined.IndexJoinError, "absent, extra"):
                    self.verify(selected_rows=selected, before_proofs=proofs)

    def test_missing_extra_duplicate_rows_and_proofs_are_not_a_bijection(self):
        selected, proofs = self.fixture.selected, self.fixture.proofs
        cases = ({"selected_rows": selected[:1]}, {"before_proofs": proofs[:1]},
                 {"selected_rows": selected + (self.fixture.all_selected[2],)},
                 {"before_proofs": proofs + (proofs[0],)},
                 {"selected_rows": (selected[0], selected[0])},
                 {"before_proofs": (proofs[0], proofs[0])})
        for changes in cases:
            with self.subTest(fields=tuple(changes)), self.assertRaises(contract.IndexRangeError):
                self.verify(**changes)

    def test_changed_primary_row_key_proof_and_root_revision_reject_before_projection(self):
        cases = []
        changed = copy.deepcopy(self.fixture.selected)
        changed[0]["row"]["sign_count"] += 1
        cases.append({"selected_rows": changed})
        changed = copy.deepcopy(self.fixture.selected)
        changed[0]["key"] = {"id": "other-id"}
        cases.append({"selected_rows": changed})
        for field, value in (("rootRevision", 8), ("rootRevision", True),
                             ("rootDigest", index_fixture.digest("stale-root")),
                             ("rowDigest", index_fixture.digest("stale-row"))):
            changed = copy.deepcopy(self.fixture.proofs)
            changed[0][field] = value
            primary_fixture.refresh_proof_digest(changed[0])
            cases.append({"before_proofs": changed})
        changed = copy.deepcopy(self.fixture.proofs)
        changed[0]["siblings"][20]["childDigests"][0] = index_fixture.digest("false-child")
        primary_fixture.refresh_proof_digest(changed[0])
        cases.append({"before_proofs": changed})
        for changes in cases:
            with self.subTest(field=tuple(changes)), self.assertRaisesRegex(joined.IndexJoinError, "membership reconstruction"):
                self.verify(**changes)

    def test_cross_table_source_index_and_projection_profiles_are_not_interchangeable(self):
        foreign = primary_fixture.IndependentTree(self.rows, table="webauthn_challenges", revision=7)
        selected = tuple(foreign.selected({"id": row["key"]["id"]}) for row in self.fixture.selected)
        with self.assertRaises(contract.IndexRangeError):
            self.verify(selected_rows=selected, before_proofs=tuple(foreign.proof(row) for row in selected))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(anchor=forged(self.fixture.anchor, primary_root=foreign.root))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(anchor=forged(self.fixture.anchor, index_id="not_source_admitted"))
        wrong_profile = replace(self.fixture.profile, projection_digest=index_fixture.digest("other-codec"))
        wrong_tree = index_fixture.IndependentIndex(list(self.fixture.index.leaves.values()), wrong_profile)
        with self.assertRaises(contract.IndexRangeError):
            joined.join_index_range(**self.arguments_for_index(wrong_tree))
        # Another admitted same-table index still has a distinct source profile
        # and selector shape; it cannot reuse this root/interval commitment.
        with self.assertRaises(contract.IndexRangeError):
            self.verify(anchor=replace(self.fixture.anchor, index_id="webauthn_credential_user_history"),
                        selector={"user_id": "credential-雪"})

    def test_nonnull_selector_and_nonmember_row_are_rejected_after_genuine_membership(self):
        changed = copy.deepcopy(self.fixture.selected)
        changed[0]["contractSelector"] = "caller-supplied-selector"
        with self.assertRaisesRegex(joined.IndexJoinError, "not an exact member"):
            self.verify(selected_rows=changed)
        row = {"id": "used", "challenge_type": "registration", "used_at": "already-used",
               "expires_at": "1970-01-01T00:00:00.000001+00:00"}
        fixture = JoinFixture([row], index_id=REGISTRATION, selector={"expires_after_us": 0}, expiry_us={"used": 1})
        selected, proof = fixture.all_selected[0], fixture.all_proofs[0]
        # A valid index tree falsely includes a row excluded by the fixed codec.
        invented = contract.IndexLeaf(partition(fixture.profile, {}) + ordered_integer(1) + "0" * 16
                                      + selected["keyDigest"][7:], selected["keyDigest"], proof["rowDigest"])
        tree = index_fixture.IndependentIndex([invented], fixture.profile)
        with self.assertRaisesRegex(joined.IndexJoinError, "row projection differs"):
            self.verify(fixture, anchor=replace(fixture.anchor, index_root=tree.root),
                        frontier=tree.frontier(fixture.interval), selected_rows=(selected,), before_proofs=(proof,))

    def test_omission_and_duplicate_primary_commitments_in_frontier_are_rejected(self):
        frontier = self.fixture.frontier
        leaf_index = next(index for index, node in enumerate(frontier) if type(node) is contract.IndexLeaf)
        with self.assertRaises(contract.IndexRangeError):
            self.verify(frontier=frontier[:leaf_index] + frontier[leaf_index + 1:])
        leaves = list(self.fixture.index.matches(self.fixture.interval))
        leaves[1] = replace(leaves[1], primary_key_digest=leaves[0].primary_key_digest)
        tree = index_fixture.IndependentIndex(leaves, self.fixture.profile)
        with self.assertRaisesRegex(contract.IndexRangeError, "repeats a returned primary-key"):
            joined.join_index_range(**self.arguments_for_index(tree))

    def test_canonical_selector_unicode_and_expiry_inputs_are_not_coerced(self):
        for selector in ({}, {"credential_id": "credential-雪", "extra": 1},
                         {"credential_id": True}, {"credential_id": b"bytes"},
                         {"credential_id": "a\x00b"}, {"credential_id": "\ud800"},
                         {"credential_id": "é" * 2049}):
            with self.subTest(selector=repr(selector)), self.assertRaises(contract.IndexRangeError):
                self.verify(selector=selector)
        # Canonical normalization is deliberately absent: these are two distinct
        # exact-text partitions, not alternate spellings of an admitted query.
        fixture = JoinFixture([{"id": "one", "credential_id": "é"}], selector={"credential_id": "e\u0301"})
        self.assertEqual(self.assert_exact(fixture).leaves, ())
        for stamp in ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000000+00:00",
                      "1970-01-01T00:00:00.1+00:00", "1970-01-01T01:00:00+01:00",
                      "1970-02-30T00:00:00+00:00"):
            row = {"id": "one", "challenge_type": "registration", "used_at": None, "expires_at": stamp}
            fixture = JoinFixture([row], index_id=REGISTRATION, selector={"expires_after_us": -1}, expiry_us={"one": 0})
            with self.subTest(stamp=stamp), self.assertRaises(contract.IndexRangeError):
                self.verify(fixture)

    def test_fixed_profile_nonmembers_still_validate_every_referenced_field(self):
        # Direct codec controls are intentionally distinct from join authority:
        # a complete empty index query cannot prove omitted primary population.
        cases = (
            ("webauthn_credential_live_trust", {"revoked_at": "old", "attestation_trusted": 1},
             "attestation_trusted", True),
            ("webauthn_credential_live_trust", {"revoked_at": None, "attestation_trusted": 0},
             "revoked_at", 0),
            (REGISTRATION, {"challenge_type": "authentication", "used_at": None,
                            "expires_at": "1970-01-01T00:00:00+00:00"}, "expires_at", "not-a-time"),
            (REGISTRATION, {"challenge_type": "registration", "used_at": "already-used",
                            "expires_at": "1970-01-01T00:00:00+00:00"}, "expires_at", None),
            ("webauthn_registration_unused_user", {"challenge_type": "authentication", "used_at": None,
              "expires_at": "1970-01-01T00:00:00+00:00", "user_id": "user"}, "user_id", False),
            ("webauthn_session_credential_status", {"bound_webauthn_credential_id": None, "status": "active"},
             "status", "unknown"),
            ("webauthn_session_credential_status", {"bound_webauthn_credential_id": "record", "status": "revoked"},
             "bound_webauthn_credential_id", False),
            ("webauthn_grant_approver_active", {"approver_webauthn_credential_id": None, "state": "active"},
             "state", None),
            ("webauthn_grant_approver_active", {"approver_webauthn_credential_id": "record", "state": "inactive"},
             "approver_webauthn_credential_id", False),
            ("webauthn_control_approval_approved", {"approver_webauthn_credential_id": None, "status": "approved"},
             "status", None),
            ("webauthn_control_approval_approved", {"approver_webauthn_credential_id": "record", "status": "rejected"},
             "approver_webauthn_credential_id", False),
        )
        for name, data, invalid_field, invalid_value in cases:
            with self.subTest(index=name, data=data):
                row = {"id": "nonmember", **data}
                profile = expected_profile(name)
                tree = primary_fixture.IndependentTree([row], table=profile.table)
                selected = tree.selected({"id": "nonmember"})
                proof = tree.proof(selected)
                commitments = {"primary_key_digest": selected["keyDigest"], "primary_row_digest": proof["rowDigest"]}
                self.assertIsNone(expected_leaf(profile, row, selected, proof, expiry_us=0))
                self.assertIsNone(projection.project_row(name, row, **commitments))
                malformed = {**row, invalid_field: invalid_value}
                with self.assertRaises(projection.IndexProjectionError):
                    projection.project_row(name, malformed, **commitments)
                missing = dict(row)
                del missing[invalid_field]
                with self.assertRaises(projection.IndexProjectionError):
                    projection.project_row(name, missing, **commitments)

    def test_exact_utf8_integer_and_nullable_binding_boundaries(self):
        for text in ("x" * 4096, "é" * 2048):
            with self.subTest(encoding=text[:1]):
                fixture = JoinFixture([{"id": "bounded", "credential_id": text}], selector={"credential_id": text})
                self.assertEqual(len(self.assert_exact(fixture).leaves), 1)
        selected, proof = self.fixture.selected[0], self.fixture.proofs[0]
        commitments = {"primary_key_digest": selected["keyDigest"], "primary_row_digest": proof["rowDigest"]}
        for text in ("x" * 4097, "é" * 2049):
            with self.subTest(size=len(text)):
                with self.assertRaises(projection.IndexProjectionError):
                    projection.query_interval(CREDENTIAL, {"credential_id": text})
                with self.assertRaises(projection.IndexProjectionError):
                    projection.project_row(CREDENTIAL, {"id": "bounded", "credential_id": text}, **commitments)
        live = "webauthn_credential_live_trust"
        for integer in (-(2**31), 2**31 - 1):
            fixture = JoinFixture([{"id": "bounded", "revoked_at": None, "attestation_trusted": integer}],
                                  index_id=live, selector={})
            self.assertEqual(len(self.assert_exact(fixture).leaves), 1)
        for integer in (True, False, -(2**31) - 1, 2**31):
            with self.subTest(int32=integer), self.assertRaises(projection.IndexProjectionError):
                projection.project_row(live, {"id": "bounded", "revoked_at": None,
                                             "attestation_trusted": integer}, **commitments)
        generation = "webauthn_publication_generation"
        for integer in (-(2**63), I64):
            for name, selector in ((REGISTRATION, {"expires_after_us": integer}),
                                   (generation, {"minimum_rollback_epoch": integer, "minimum_sequence": integer})):
                with self.subTest(index=name, int64=integer):
                    self.assertEqual(projection.query_interval(name, selector),
                                     expected_interval(expected_profile(name), selector))
        for integer in (True, False, -(2**63) - 1, 2**63):
            for name, selector in ((REGISTRATION, {"expires_after_us": integer}),
                                   (generation, {"minimum_rollback_epoch": integer, "minimum_sequence": 0}),
                                   (generation, {"minimum_rollback_epoch": 0, "minimum_sequence": integer})):
                with self.subTest(index=name, int64=integer), self.assertRaises(projection.IndexProjectionError):
                    projection.query_interval(name, selector)
        for name, binding, row_extra, selector_extra in (
            ("webauthn_session_credential_status", "bound_webauthn_credential_id", {"status": "active"}, {"status": "active"}),
            ("webauthn_grant_approver_active", "approver_webauthn_credential_id", {"state": "active"}, {}),
            ("webauthn_control_approval_approved", "approver_webauthn_credential_id", {"status": "approved"}, {}),
        ):
            with self.subTest(nullable_index=name):
                selector = {"credential_record_id": "", **selector_extra}
                fixture = JoinFixture([{"id": "blank", binding: "", **row_extra}], index_id=name, selector=selector)
                self.assertEqual(len(self.assert_exact(fixture).leaves), 1)
                blank = fixture.all_selected[0]
                blank_proof = fixture.all_proofs[0]
                row = {"id": "blank", binding: None, **row_extra}
                self.assertIsNone(expected_leaf(fixture.profile, row, blank, blank_proof))
                self.assertIsNone(projection.project_row(name, row, primary_key_digest=blank["keyDigest"],
                                                         primary_row_digest=blank_proof["rowDigest"]))

    def test_lossy_or_cyclic_primary_graphs_are_not_accepted_as_verified_rows(self):
        for malformed in (1.0, Decimal("1"), b"bytes", "\ud800"):
            selected = copy.deepcopy(self.fixture.selected)
            selected[0]["row"]["extra"] = malformed
            with self.subTest(kind=type(malformed)), self.assertRaises(joined.IndexJoinError):
                self.verify(selected_rows=selected)
        selected = copy.deepcopy(self.fixture.selected)
        selected[0]["row"]["cycle"] = selected[0]["row"]
        with self.assertRaises(joined.IndexJoinError):
            self.verify(selected_rows=selected)

    def test_exact_dataclass_contexts_are_revalidated_even_when_constructors_were_bypassed(self):
        base = self.fixture.arguments()
        bad_anchors = [None, object.__new__(joined.IndexPrimaryAnchor),
                       forged(self.fixture.anchor, index_revision=True),
                       forged(self.fixture.anchor, index_revision=-1),
                       forged(self.fixture.anchor, index_revision=0),
                       forged(self.fixture.anchor, index_root=forged(self.fixture.index.root, count=True)),
                       forged(self.fixture.anchor, primary_root=forged(self.fixture.primary.root, leaf_count=True)),
                       forged(self.fixture.anchor, primary_root=object.__new__(primary.PrimaryRoot))]
        for anchor in bad_anchors:
            with self.subTest(kind=type(anchor)), self.assertRaises(contract.IndexRangeError):
                self.verify(anchor=anchor)
        limits = base["limits"]
        for malformed in (None, object.__new__(joined.IndexJoinLimits),
                          forged(limits, max_total_hashes=True), forged(limits, max_total_input_bytes=0),
                          forged(limits, primary=forged(limits.primary, max_json_depth=True)),
                          forged(limits, index=forged(limits.index, max_entries=True))):
            with self.subTest(kind=type(malformed)), self.assertRaises(contract.IndexRangeError):
                self.verify(limits=malformed)

    def test_no_constructed_observation_callback_or_non_tuple_proof_inventory_is_accepted(self):
        observation = self.verify()
        for changes in ({"anchor": observation}, {"frontier": observation}, {"frontier": list(self.fixture.frontier)},
                        {"selected_rows": list(self.fixture.selected)}, {"before_proofs": list(self.fixture.proofs)},
                        {"selector": lambda row: True}, {"before_proofs": (observation,) * 2}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(contract.IndexRangeError):
                self.verify(**changes)
        with self.assertRaises(TypeError):
            joined.join_index_range(**self.fixture.arguments(), projector=lambda row: row)

    def test_inputs_unchanged_and_output_is_frozen_detached_without_raw_rows(self):
        args = self.fixture.arguments()
        before = copy.deepcopy(args)
        result = joined.join_index_range(**args)
        self.assertEqual(args, before)
        self.assertEqual(set(values(result)), {"anchor", "interval", "leaves", "context_digest", "metrics"})
        self.assertIsNot(result.anchor, args["anchor"])
        self.assertIsNot(result.anchor.primary_root, args["anchor"].primary_root)
        self.assertIsNot(result.anchor.index_root, args["anchor"].index_root)
        for leaf in result.leaves:
            self.assertTrue(all(leaf is not raw for raw in args["frontier"]))
        expected = copy.deepcopy(result)
        args["selected_rows"][0]["row"].clear()
        args["before_proofs"][0]["siblings"].clear()
        args["selector"]["credential_id"] = "changed"
        object.__setattr__(args["anchor"].primary_root, "root_revision", 999)
        self.assertEqual(result, expected)
        for value, field in ((result, "context_digest"), (result.anchor, "index_revision"),
                             (result.metrics, "total_hashes"), (result.leaves[0], "key")):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, None)

    def test_primary_phase_returns_owned_verified_snapshot_even_if_caller_mutates_afterward(self):
        args = self.fixture.arguments()
        expected = joined.join_index_range(**copy.deepcopy(args))
        actual = primary.evaluate_primary_radix_memberships

        def observe(**kwargs):
            verified = actual(**kwargs)
            args["selected_rows"][0]["row"]["credential_id"] = "changed-after-verification"
            args["before_proofs"][0]["rowDigest"] = index_fixture.digest("changed-after-verification")
            args["selector"]["credential_id"] = "changed-after-context-snapshot"
            object.__setattr__(args["anchor"], "index_revision", 999)
            object.__setattr__(args["anchor"].primary_root, "root_revision", 999)
            return verified

        # This observation hook delegates every call to the real engine and
        # returns its unchanged genuine result. It models controlled mutation,
        # not a concurrent-thread or alternate verified-token protocol.
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", side_effect=observe) as observed:
            self.assertEqual(joined.join_index_range(**args), expected)
            self.assertEqual(observed.call_count, 1)

    def test_declared_revision_pair_and_primary_cardinality_are_not_currentness_authority(self):
        before = self.verify()
        root = replace(self.fixture.primary.root, root_revision=999, leaf_count=7)
        proofs = copy.deepcopy(self.fixture.proofs)
        for proof in proofs:
            proof["rootRevision"] = 999
            primary_fixture.refresh_proof_digest(proof)
        result = self.verify(anchor=replace(self.fixture.anchor, primary_root=root, index_revision=888),
                             before_proofs=proofs)
        self.assertEqual(result.leaves, before.leaves)
        self.assertNotEqual(result.context_digest, before.context_digest)
        self.assertEqual(result.anchor.primary_root.leaf_count, 7)
        # Consistently rebound caller descriptors remain relative evidence,
        # not authenticated revision/cardinality or a trusted same-checkpoint join.

    def test_exact_phase_and_combined_budgets_pass_and_one_less_rejects(self):
        observed = self.assert_exact(self.fixture)
        pm, im = observed.metrics.primary, observed.metrics.index
        primary_limits = primary.PrimaryRadixLimits(pm.selected_rows, 1, pm.proof_vectors,
            pm.proof_child_slots, pm.hash_work, pm.input_bytes, 128, pm.json_nodes)
        index_limits = ranges.IndexRangeLimits(im.entries, im.leaves, im.opened_nodes, im.hashes, im.input_bytes)
        limits = joined.IndexJoinLimits(primary_limits, index_limits,
                                       observed.metrics.total_hashes, observed.metrics.total_input_bytes)
        self.assertEqual(self.verify(limits=limits), observed)
        for field in ("max_total_hashes", "max_total_input_bytes"):
            with self.subTest(field=field), self.assertRaises(contract.IndexRangeError):
                self.verify(limits=replace(limits, **{field: getattr(limits, field) - 1}))
        for field in ("max_selected_rows", "max_proof_vectors", "max_proof_child_slots", "max_hashes",
                      "max_input_bytes", "max_json_nodes"):
            with self.subTest(primary=field), self.assertRaises(contract.IndexRangeError):
                self.verify(limits=replace(limits, primary=replace(primary_limits,
                            **{field: getattr(primary_limits, field) - 1})))
        for field in ("max_entries", "max_leaves", "max_opened_nodes", "max_hashes", "max_input_bytes"):
            with self.subTest(index=field), self.assertRaises(contract.IndexRangeError):
                self.verify(limits=replace(limits, index=replace(index_limits,
                            **{field: getattr(index_limits, field) - 1})))

    def test_shared_budget_clamps_real_phases_and_reserves_all_projection_hashes(self):
        observed = self.verify()
        limits = replace(self.fixture.arguments()["limits"],
                         max_total_hashes=observed.metrics.total_hashes,
                         max_total_input_bytes=observed.metrics.total_input_bytes)
        range_actual, primary_actual = joined.reconstruct_complete_index_range, primary.evaluate_primary_radix_memberships
        with mock.patch.object(joined, "reconstruct_complete_index_range", wraps=range_actual) as range_calls, \
                mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=primary_actual) as primary_calls:
            self.assertEqual(self.verify(limits=limits), observed)
        range_limits = range_calls.call_args.kwargs["limits"]
        self.assertEqual(range_limits.max_hashes, observed.metrics.total_hashes - 69 - 2)
        self.assertEqual(range_limits.max_input_bytes,
                         min(limits.index.max_input_bytes, observed.metrics.total_input_bytes - observed.metrics.context_bytes))
        primary_limits = primary_calls.call_args.kwargs["limits"]
        self.assertEqual(primary_limits.max_hashes, observed.metrics.primary.hash_work)
        self.assertEqual(primary_limits.max_input_bytes, observed.metrics.primary.input_bytes)
        # Insufficient range-phase allowance fails before any primary proof
        # work, not after unbounded work followed by a final total comparison.
        tight = replace(limits, max_total_hashes=69 + 2 + observed.metrics.index.hashes - 1)
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=primary_actual) as calls:
            with self.assertRaises(contract.IndexRangeError):
                self.verify(limits=tight)
            self.assertEqual(calls.call_count, 0)

    def test_context_allowance_is_cold_conservative_and_enforced_before_hashing(self):
        expected = self.verify()
        self.assertEqual(self.verify(), expected)
        self.assertEqual(expected.metrics.context_hashes, 69)
        actual_hash = hashlib.sha256
        tiny = replace(self.fixture.arguments()["limits"], max_total_hashes=68)
        with mock.patch.object(hashlib, "sha256", wraps=actual_hash) as hashes:
            with self.assertRaisesRegex(joined.IndexJoinError, "combined work"):
                self.verify(limits=tiny)
            self.assertEqual(hashes.call_count, 0)
        # Successful totals are deliberately cold-cache conservative charges;
        # unlike counted-range hashes, they do not promise actual-call equality.

    def test_full_256_member_join_stays_inside_default_combined_component_bounds(self):
        fixture = JoinFixture([{"id": f"member-{index:03}", "credential_id": "credential-雪"}
                               for index in range(256)], primary_revision=256, index_revision=256)
        result = self.assert_exact(fixture)
        self.assertEqual(len(result.leaves), 256)
        self.assertEqual(result.metrics.primary.proof_vectors, 16384)
        self.assertEqual(result.metrics.primary.proof_child_slots, 262144)
        self.assertEqual(result.metrics.primary.hash_work, 17986)
        self.assertEqual(result.metrics.projection_hashes, 514)
        self.assertLessEqual(result.metrics.total_hashes, 1100000)
        self.assertLessEqual(result.metrics.total_input_bytes, 64 * 1024 * 1024 + 4194304 + 262144)


if __name__ == "__main__":
    unittest.main()
