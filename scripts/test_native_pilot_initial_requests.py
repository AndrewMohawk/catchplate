#!/usr/bin/env python3
"""Eight pure synthetic initial-request controls, not acquisition evidence.

Histories use real deterministic in-memory test signatures. Runtime/guest,
cursor, process, clock and entropy values are synthetic public fixtures. No
live-owner acceptance, protected I/O, entropy/clock sampling, issuer, network,
receipt, currentness decision, startup or cleanup is exercised or mocked.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_initial_requests as acquisition
from serverware import native_pilot_initial_requests_profile as profile
from test_native_pilot_ordinary_commissioning import fixture as ordinary_fixture, runtimes, ENDPOINT_ROLES
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, framed, labelled, sha

REQUEST_DOMAIN = b"serverware.policyCustodyEndpointRequest/v3"


def fixture(*, complete=True):
    f = ordinary_fixture()
    if complete:
        # Explicit test-only approved CSA subjects, not derived missing cursors.
        row = f["fragment"]["services"][ROLES[3]]
        for index in (1, 4):
            target = ROLES[index]
            names = []
            for kind in ("service", "checkpoint"):
                name = "initial-subject-" + str(index) + "-" + kind
                public = f["initial_policy"]["services"][target]["authorities"][kind]
                raw = base64.urlsafe_b64decode(public["publicKeySpkiBase64"] + "==")[-32:]
                row["credentials"].append({"name": name,
                    "original": {"path": "/etc/serverware/synthetic-" + name, "sha256": sha(raw)},
                    "length": 32, "signing": None})
                names.append(name)
            row["service"]["currentSubjects"].append({
                "subject": {"authority": "endpoint", "identity": {"endpoint_role": ENDPOINT_ROLES[index]}},
                "serviceRole": target, "pin": {"endpointVerifyingKeyCredential": names[0],
                    "checkpointAuthorityVerifyingKeyCredential": names[1],
                    "consumeCursor": {"sequenceHighWater": 0, "expectedNextSequence": 1,
                        "expectedPredecessorReceiptSha256": labelled("SYNTHETIC initial anchor / " + target)}}})
    built = runtimes(f)
    contexts = {}
    for role in ROLES:
        guest = {"configurationSha256": sha(canonical(f["cold"][role])),
            "deliverySha256": labelled("SYNTHETIC public guest only / " + role),
            "runtimeConfigurationSha256": sha(built[role]), "serviceRole": role,
            "uid": f["cold"][role]["uid"], "gid": f["cold"][role]["gid"],
            "issuedAtBoottimeNs": str(f["now"]), **{name: f["launch"][name] for name in (
                "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "invocationId",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")}}
        contexts[role] = {"configurationOriginal": canonical(f["cold"][role]), "runtimeOriginal": built[role],
            "historyOriginal": f["histories"][role], "guest": guest}
    kwargs = {"preparation_original": canonical(f["preparation"]), "resources_original": canonical(f["resources"]),
        "launch_original": canonical(f["launch"]), "window": copy.deepcopy(f["window"]),
        "boot": tuple(f["window"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")),
        "now_boottime_ns": f["now"]}
    return f, contexts, kwargs


def replace_runtime(contexts, role, value):
    contexts[role]["runtimeOriginal"] = canonical(value)
    contexts[role]["guest"]["runtimeConfigurationSha256"] = sha(canonical(value))


def export(selection, kwargs):
    issued = kwargs["now_boottime_ns"] + 1
    rows = {}
    for index, role in enumerate(ROLES):
        raw = profile.request_original(selection[role], entropy=bytes([index + 1]) * 32, issued_at_boottime_ns=issued)
        rows[role] = {name: selection[role][name] for name in profile.ROW_FIELDS[:4]}
        rows[role].update(requestOriginal=raw.decode("ascii"), requestSha256=framed(REQUEST_DOMAIN, (raw,)))
    return {"apiVersion": "serverware.nativePilotInitialTrustRequests/v1",
        "launchSha256": sha(kwargs["launch_original"]), "preparationSha256": sha(kwargs["preparation_original"]),
        "resourcesSha256": sha(kwargs["resources_original"]), "requestedAtBoottimeNanos": issued,
        "startupDeadlineBoottimeNs": kwargs["window"]["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": kwargs["window"]["lifetimeDeadlineBoottimeNs"], "requests": rows}


class InitialRequestControls(unittest.TestCase):
    def test_authenticated_five_wrapper_selection_and_exact_original_pins(self):
        _, contexts, kwargs = fixture()
        selected = profile.select(contexts, **kwargs)
        self.assertEqual(tuple(selected), ROLES)
        for index, role in enumerate(ROLES):
            history = json.loads(contexts[role]["historyOriginal"])
            self.assertEqual(selected[role]["endpointRole"], ENDPOINT_ROLES[index])
            self.assertEqual(selected[role]["checkpointSha256"], history["initialCheckpoint"]["checkpointSha256"])
            self.assertEqual(selected[role]["runtimeConfigurationSha256"], sha(contexts[role]["runtimeOriginal"]))
            self.assertEqual(selected[role]["initialHistorySha256"], sha(contexts[role]["historyOriginal"]))
            self.assertEqual(selected[role]["floor"]["consumeCursor"]["sequenceHighWater"], 0)
            self.assertEqual(selected[role]["floor"]["consumeCursor"]["expectedNextSequence"], 1)

    def test_native_spelling_independent_nonce_and_digest_for_all_five(self):
        _, contexts, kwargs = fixture()
        selected = profile.select(contexts, **kwargs)
        value = export(selected, kwargs)
        checked = profile.shape(canonical(value))
        self.assertEqual(checked, value)
        self.assertNotIn("currentness", checked)
        for index, role in enumerate(ROLES):
            row = checked["requests"][role]
            request = json.loads(row["requestOriginal"])
            self.assertEqual(request["requestEntropyBase64"], encoded(bytes([index + 1]) * 32))
            self.assertEqual(set(request["operation"]["body"]), {"accepted_floor"})
            expected_nonce = sha(canonical([request[name] for name in (
                "apiVersion", "endpointRole", "requestEntropyBase64", "requestedAtBoottimeNanos", "deadline", "operation")]))
            self.assertEqual(request["requestNonceSha256"], expected_nonce)
            self.assertEqual(row["requestSha256"], framed(REQUEST_DOMAIN, (row["requestOriginal"].encode("ascii"),)))
        checked["requests"][ROLES[0]]["checkpointSha256"] = labelled("changed returned copy")
        self.assertNotEqual(checked, value)

    def test_missing_and_conflicting_actual_cursor_targets_refuse(self):
        _, incomplete, kwargs = fixture(complete=False)
        with self.assertRaises(ValueError):
            profile.select(incomplete, **kwargs)
        _, contexts, kwargs = fixture()
        current = json.loads(contexts[ROLES[3]]["runtimeOriginal"])
        duplicate = copy.deepcopy(current["serviceSigningPin"])
        duplicate["consumeCursor"]["expectedPredecessorReceiptSha256"] = labelled("conflicting independent anchor")
        current["currentSubjects"].append({"subject": {"authority": "endpoint",
            "identity": {"endpoint_role": ENDPOINT_ROLES[3]}}, "pin": duplicate})
        replace_runtime(contexts, ROLES[3], current)
        with self.assertRaises(ValueError):
            profile.select(contexts, **kwargs)

    def test_pin_scope_and_initial_anchor_substitutions_refuse(self):
        _, original, kwargs = fixture()
        for change in ("checkpoint", "socket", "time", "high", "typed-initial-commitment", "identity"):
            contexts = copy.deepcopy(original)
            current = json.loads(contexts[ROLES[3]]["runtimeOriginal"])
            pin = current["currentSubjects"][0]["pin"]
            if change == "checkpoint":
                pin["signedCurrentKeyAuthorization"] = json.loads(contexts[ROLES[1]]["historyOriginal"])["initialCheckpoint"]
            elif change == "socket":
                pin["declaredSocketPath"] = "/run/serverware-custody-business/" + ROLES[1] + "/listener.sock"
            elif change == "time":
                pin["consumeHeadObservedAtBoottimeNanos"] += 1
            elif change == "high":
                pin["consumeCursor"].update(sequenceHighWater=1, expectedNextSequence=2)
            elif change == "typed-initial-commitment":
                pin["consumeCursor"]["expectedPredecessorReceiptSha256"] = json.loads(
                    contexts[ROLES[0]]["historyOriginal"])["initialCheckpoint"]["payload"]["predecessorCheckpointSha256"]
            else:
                pin["endpointProcessIdentity"]["endpointPid"] += 1
            replace_runtime(contexts, ROLES[3], current)
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.select(contexts, **kwargs)

    def test_authentic_history_root_signatures_and_explicit_wrapper_required(self):
        _, original, kwargs = fixture()
        for change in ("signature", "root", "legacy"):
            contexts = copy.deepcopy(original)
            wrapper = json.loads(contexts[ROLES[0]]["historyOriginal"])
            if change == "signature":
                wrapper["initialCheckpoint"]["authoritySignatureBase64"] = encoded(bytes(64))
            elif change == "root":
                current = json.loads(contexts[ROLES[0]]["runtimeOriginal"])
                current["runtime"]["authorityHistoryRootKeyId"] = labelled("wrong independent root")
                replace_runtime(contexts, ROLES[0], current)
            else:
                wrapper = wrapper["history"]
            contexts[ROLES[0]]["historyOriginal"] = canonical(wrapper)
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                profile.select(contexts, **kwargs)

    def test_original_clock_domain_window_and_measured_source_joins(self):
        _, contexts, original = fixture()
        for change in ("boot", "expired", "window", "preparation", "resources"):
            kwargs = copy.deepcopy(original)
            if change == "boot":
                kwargs["boot"] = (encoded(bytes([9]) * 16), *kwargs["boot"][1:])
            elif change == "expired":
                kwargs["now_boottime_ns"] = int(kwargs["window"]["startupDeadlineBoottimeNs"])
            elif change == "window":
                kwargs["window"]["startupDeadlineBoottimeNs"] = str(int(kwargs["window"]["startupDeadlineBoottimeNs"]) + 1)
            elif change == "preparation":
                value = json.loads(kwargs["preparation_original"])
                value["services"][ROLES[0]]["processId"] += 1
                kwargs["preparation_original"] = canonical(value)
            else:
                value = json.loads(kwargs["resources_original"])
                value["services"][ROLES[0]]["directories"]["journal"]["identity"]["inode"] += 1
                kwargs["resources_original"] = canonical(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.select(contexts, **kwargs)
        selected = profile.select(contexts, **original)[ROLES[0]]
        for bad in (b"", bytes(31), bytes(33)):
            with self.assertRaises(ValueError):
                profile.request_original(selected, entropy=bad, issued_at_boottime_ns=original["now_boottime_ns"])
        with self.assertRaises(ValueError):
            profile.request_original(selected, entropy=bytes(32), issued_at_boottime_ns=selected["deadline"])
        # Pure retained-source projection only: this supplied fixture expiry
        # is not represented as an authenticated live generation grant.
        source = {name: value for name, value in original.items() if name != "now_boottime_ns"}
        source.update(contexts=contexts, grant_deadline=original["now_boottime_ns"] + 2)
        clipped = acquisition.InitialRequests._select(source, original["now_boottime_ns"])
        self.assertTrue(all(row["deadline"] == source["grant_deadline"] for row in clipped.values()))
        with self.assertRaises(ValueError):
            acquisition.InitialRequests._select(source, source["grant_deadline"])
        with self.assertRaises(ValueError):
            profile.request_original(clipped[ROLES[0]], entropy=bytes(32),
                issued_at_boottime_ns=source["grant_deadline"])

    def test_public_export_is_closed_canonical_and_exact_request_bound(self):
        _, contexts, kwargs = fixture()
        original = export(profile.select(contexts, **kwargs), kwargs)
        for change in ("api", "extra", "missing-role", "hash", "checkpoint", "time", "spelling"):
            value = copy.deepcopy(original)
            row = value["requests"][ROLES[0]]
            if change == "api":
                value["apiVersion"] = "serverware.nativePilotInitialTrustRequests/v2"
            elif change == "extra":
                value["currentness"] = True
            elif change == "missing-role":
                del value["requests"][ROLES[-1]]
            elif change == "hash":
                row["requestSha256"] = labelled("wrong request")
            elif change == "checkpoint":
                row["checkpointSha256"] = labelled("wrong checkpoint")
            elif change == "time":
                value["requestedAtBoottimeNanos"] += 1
            else:
                request = json.loads(row["requestOriginal"])
                body = request["operation"]["body"]
                body["acceptedFloor"] = body.pop("accepted_floor")
                row["requestOriginal"] = canonical(request).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile.shape(canonical(value))
        raw = canonical(original)
        for malformed in (raw + b"\n", raw.replace(b'"apiVersion":', b'"apiVersion":"duplicate","apiVersion":', 1)):
            with self.assertRaises(ValueError):
                profile.shape(malformed)

    def test_public_data_and_direct_construction_do_not_mint_live_owner(self):
        # Only early type/token refusals; never construct a fake live owner.
        with self.assertRaises(ValueError):
            acquisition.InitialRequests.prepare({"stage": "resources", "approved": True})
        with self.assertRaises(ValueError):
            acquisition.InitialRequests(object(), None)
        with self.assertRaises(ValueError):
            acquisition.close({"_closed": True})


if __name__ == "__main__":
    unittest.main()
