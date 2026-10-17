#!/usr/bin/env python3
"""Eight pure SYNTHETIC multi-role helper controls, not live startup evidence.

Every key, process observation, cursor, timestamp and decision is test-only.
Existing checkpoint/anchor/grant signatures are independently framed in memory;
no issuer, owner, file, socket, entropy source, journal or native service runs.
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

from catchplate import custody_generation_grants as grants
from catchplate import native_pilot_current_head_profile as head
from catchplate import native_pilot_initial_requests_profile as requests
from catchplate import native_pilot_ordinary_initial_profile as initial
from catchplate import native_pilot_ordinary_runtime_profile as runtime
from test_native_pilot_current_head import configuration_raw, signed_result, WINDOW_DOMAIN
from test_native_pilot_generation_scope import key_fixture
from test_native_pilot_initial_requests import fixture as single_fixture
from test_native_pilot_ordinary_commissioning import private
from test_native_pilot_ordinary_generations import context as generation_context, scope_fixture, result as grant_result
from test_native_pilot_ordinary_initial import checkpoint, sign_anchor, DOMAINS
from test_native_pilot_ordinary_keys import ROLES, PROCESS_DOMAIN, canonical, encoded, framed, labelled, sha

HELPER = ROLES[-1]
HELPER_ROLES = ("settlement-store", "fence-authority", "cgroup-executor", "termination-ledger")


def refresh(wrapper, *, endpoint_role=None):
    """TEST ONLY: issue new genuine synthetic signatures, never mutate a role label alone."""
    role = wrapper["initialState"]["serviceRole"]
    keys = {name: private(role + "/" + name) for name in ("root", "checkpoint", "service")}
    state, history = wrapper["initialState"], wrapper["history"]
    anchor = history["firstRetainedEpoch"]
    epoch, identity = anchor["retainedEpoch"], anchor["retainedEpoch"]["endpointProcessIdentity"]
    if endpoint_role is not None:
        identity["endpointRole"] = endpoint_role
    names = ("endpointRole", "endpointUid", "endpointGid", "endpointPid", "endpointStartTimeTicks",
        "endpointPidfdInode", "endpointPidfdStatSha256", "executableDevice", "executableInode",
        "executableLength", "executableSha256", "executableImaSha256", "executableFsVeritySha256")
    identity["identitySha256"] = framed(PROCESS_DOMAIN, (canonical([identity[name] for name in names]),))
    state["endpointProcessIdentitySha256"] = identity["identitySha256"]
    roots = {name: framed(domain, (canonical(state),)) for name, domain in DOMAINS.items()}
    payload = wrapper["initialCheckpoint"]["payload"]
    payload.update(endpointRole=identity["endpointRole"], endpointProcessIdentitySha256=identity["identitySha256"],
        predecessorCheckpointSha256=roots["predecessorCheckpointSha256"])
    wrapper["initialCheckpoint"] = checkpoint(payload, epoch["checkpointAuthority"], keys["checkpoint"])
    epoch.update(endpointProcessIdentitySha256=identity["identitySha256"],
        checkpointSha256=wrapper["initialCheckpoint"]["checkpointSha256"],
        durableEpochHeadSha256=roots["durableEpochHeadSha256"])
    anchor["prunedHistoryRootSha256"] = roots["prunedHistoryRootSha256"]
    sign_anchor(history, keys)
    return wrapper


def fixture(*, lifetime_boottime_ns=9_000_000):
    """Same three-value interface as initial_requests fixture; all facts synthetic."""
    f, _, _ = single_fixture()
    for item in (f["window"], f["launch"], f["preparation"]):
        item["lifetimeDeadlineBoottimeNs"] = str(lifetime_boottime_ns)
    f["preparation"]["configurationSha256"] = sha(canonical(f["launch"]))
    f["resources"]["preparationSha256"] = sha(canonical(f["preparation"]))
    for role in ROLES:
        wrapper = json.loads(f["histories"][role])
        wrapper["initialState"].update(lifetimeDeadlineBoottimeNs=str(lifetime_boottime_ns),
            preparationSha256=sha(canonical(f["preparation"])), resourcesSha256=sha(canonical(f["resources"])),
            launchSha256=sha(canonical(f["launch"])))
        wrapper["initialCheckpoint"]["payload"]["validUntilBoottime"]["absoluteBoottimeNanos"] = lifetime_boottime_ns
        f["histories"][role] = canonical(refresh(wrapper))
    primary = json.loads(f["histories"][HELPER])
    members = {role: canonical(refresh(copy.deepcopy(primary), endpoint_role=role)) for role in HELPER_ROLES}
    self_role = primary["initialCheckpoint"]["payload"]["endpointRole"]
    assert members[self_role] == f["histories"][HELPER]
    f["helper_histories"] = members
    f["fragment"]["apiVersion"] = "catchplate.nativePilotOrdinaryRuntimePolicy/v2"
    # The helper's own explicit pins avoid collisions with CSA subjects such
    # as the independently distinct DRS settlement-store process.
    current = f["fragment"]["services"][ROLES[3]]
    current["service"]["currentSubjects"] = [row for row in current["service"]["currentSubjects"] if row["serviceRole"] != HELPER]
    current["credentials"] = [row for row in current["credentials"] if not row["name"].startswith("initial-subject-4-")]
    row = f["fragment"]["services"][HELPER]
    public = f["initial_policy"]["services"][HELPER]["authorities"]["service"]
    raw_key = base64.urlsafe_b64decode(public["publicKeySpkiBase64"] + "==")[-32:]
    row["credentials"].append({"name": "helper-service-public",
        "original": {"path": "/etc/catchplate/synthetic-helper-service-public", "sha256": sha(raw_key)},
        "length": 32, "signing": None})
    row["service"].update(initialEndpointRoles=list(HELPER_ROLES), initialEndpointPins={role: {
        "endpointVerifyingKeyCredential": "helper-service-public",
        "checkpointAuthorityVerifyingKeyCredential": "current-head-key",
        "consumeCursor": {"sequenceHighWater": 0, "expectedNextSequence": 1,
            "expectedPredecessorReceiptSha256": labelled("SYNTHETIC helper start anchor / " + role)}} for role in HELPER_ROLES})
    built, contexts = {}, {}
    from test_native_pilot_endpoint_commissioning import peer
    for role in ROLES:
        built[role] = runtime.build(role, fragment=f["fragment"], history_originals=f["histories"],
            preparation_raw=canonical(f["preparation"]), resources_raw=canonical(f["resources"]),
            launch_raw=canonical(f["launch"]), configuration_raw=canonical(f["cold"][role]), peer=peer(),
            helper_history_originals=members)
        guest = {"configurationSha256": sha(canonical(f["cold"][role])),
            "deliverySha256": labelled("SYNTHETIC public guest only / " + role),
            "runtimeConfigurationSha256": sha(built[role]), "serviceRole": role,
            "uid": f["cold"][role]["uid"], "gid": f["cold"][role]["gid"], "issuedAtBoottimeNs": str(f["now"]),
            **{name: f["launch"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")}}
        contexts[role] = dict(configurationOriginal=canonical(f["cold"][role]), runtimeOriginal=built[role],
            historyOriginal=f["histories"][role], guest=guest)
    f["runtimes"] = built
    kw = dict(preparation_original=canonical(f["preparation"]), resources_original=canonical(f["resources"]),
        launch_original=canonical(f["launch"]), window=copy.deepcopy(f["window"]),
        boot=tuple(f["window"][name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")),
        now_boottime_ns=f["now"])
    return f, contexts, kw


def export(selection, kw):
    rows = {}
    for index, (service_role, endpoint_role, item) in enumerate(requests.iter_selection(selection)):
        raw = requests.request_original(item, entropy=bytes([index + 1]) * 32, issued_at_boottime_ns=1201)
        row = {name: item[name] for name in requests.ROW_FIELDS[:4]}
        row.update(requestOriginal=raw.decode("ascii"), requestSha256=framed(head.REQUEST_DOMAIN, (raw,)))
        if service_role == HELPER:
            rows.setdefault(service_role, {})[endpoint_role] = row
        else:
            rows[service_role] = row
    return {"apiVersion": "catchplate.nativePilotInitialTrustRequests/v2", "launchSha256": sha(kw["launch_original"]),
        "preparationSha256": sha(kw["preparation_original"]), "resourcesSha256": sha(kw["resources_original"]),
        "requestedAtBoottimeNanos": 1201, "startupDeadlineBoottimeNs": kw["window"]["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": kw["window"]["lifetimeDeadlineBoottimeNs"], "requests": rows}


def head_input(f, contexts, kw, endpoint_role):
    selected = export(requests.select(contexts, **kw), kw)["requests"][HELPER][endpoint_role]
    pending = json.loads(selected["requestOriginal"])
    config = json.loads(configuration_raw())
    window = copy.deepcopy(f["window"])
    window.update(configurationSha256=sha(configuration_raw()), signingKeyId=config["bootstrapAuthority"]["keyId"])
    signed_window = {"apiVersion": "catchplate.nativeShadowDriverBootstrapWindow/v1", "payload": window,
        "signatureBase64url": encoded(key_fixture("window")[0].sign(WINDOW_DOMAIN + canonical(window)))}
    root = f["initial_policy"]["services"][HELPER]["authorities"]["root"]
    return {"apiVersion": "catchplate.nativePilotCurrentHeadAuthorityInput/v2", "serviceRole": HELPER,
        "endpointRole": endpoint_role, "runtimeOriginal": f["runtimes"][HELPER].decode("ascii"),
        "driverConfigurationOriginal": configuration_raw().decode("ascii"),
        "driverWindowOriginal": canonical(signed_window).decode("ascii"),
        "launchOriginal": kw["launch_original"].decode("ascii"),
        "configurationOriginal": canonical(f["cold"][HELPER]).decode("ascii"),
        "preparationOriginal": kw["preparation_original"].decode("ascii"),
        "resourcesOriginal": kw["resources_original"].decode("ascii"),
        "initialHistoryOriginal": f["histories"][HELPER].decode("ascii"),
        "rootAuthority": {name: root[name] for name in ("keyId", "keySpkiSha256")},
        "requestOriginal": selected["requestOriginal"], "currentness": {
            "profile": "initial-checkpoint-current-for-exact-request-v1",
            "initialHistorySha256": selected["initialHistorySha256"], "checkpointSha256": selected["checkpointSha256"],
            "requestSha256": selected["requestSha256"], "requestNonceSha256": pending["requestNonceSha256"],
            "issuedAtBoottimeNanos": 1202}}


class HelperInitialControls(unittest.TestCase):
    def test_four_independent_signed_members_bind_one_real_shape_not_one_role_label(self):
        f, _, _ = fixture(); value = json.loads(f["runtimes"][HELPER])
        members = initial.helper_endpoint_histories(f["histories"][HELPER], runtime=value)
        self.assertEqual(tuple(members), HELPER_ROLES)
        self.assertEqual(len({row["identity"]["identitySha256"] for row in members.values()}), 4)
        self.assertEqual(len({row["checkpoint"]["checkpointSha256"] for row in members.values()}), 4)
        self.assertEqual(len({row["identity"]["endpointPid"] for row in members.values()}), 1)

    def test_missing_mixed_relabelled_or_unauthenticated_members_refuse(self):
        f, _, _ = fixture(); original = json.loads(f["runtimes"][HELPER])
        for change in ("missing", "null", "primary-copy", "signature", "root", "legacy"):
            value = copy.deepcopy(original)
            if change == "missing": del value["initialEndpointHistories"][HELPER_ROLES[0]]
            elif change == "null": value["initialEndpointHistories"] = None
            elif change == "primary-copy": value["initialEndpointHistories"][HELPER_ROLES[0]] = f["histories"][HELPER].decode("ascii")
            elif change == "root": value["runtime"]["authorityHistoryRootKeyId"] = labelled("wrong root")
            elif change == "legacy": value["runtime"]["apiVersion"] = "catchplate.policyCustodyServiceRuntimeConfig/v5"
            else:
                wrapper = json.loads(value["initialEndpointHistories"][HELPER_ROLES[0]])
                wrapper["initialCheckpoint"]["authoritySignatureBase64"] = encoded(bytes(64))
                value["initialEndpointHistories"][HELPER_ROLES[0]] = canonical(wrapper).decode("ascii")
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                runtime.validate_runtime(HELPER, canonical(value))

    def test_authentically_signed_different_kernel_identity_is_not_same_helper(self):
        f, _, _ = fixture(); value = json.loads(f["runtimes"][HELPER])
        wrapper = json.loads(value["initialEndpointHistories"][HELPER_ROLES[0]])
        wrapper["history"]["firstRetainedEpoch"]["retainedEpoch"]["endpointProcessIdentity"]["endpointPid"] += 1
        value["initialEndpointHistories"][HELPER_ROLES[0]] = canonical(refresh(wrapper)).decode("ascii")
        with self.assertRaises(ValueError):
            initial.helper_endpoint_histories(f["histories"][HELPER], runtime=value)

    def test_policy_successor_requires_explicit_full_roles_and_public_credentials(self):
        f, _, _ = fixture()
        def check(fragment):
            return runtime.validate_policy(fragment, ordinary_cold_originals={role: canonical(f["cold"][role]).decode("ascii")
                for role in ROLES}, initial_policy=f["initial_policy"])
        self.assertEqual(check(f["fragment"]), f["fragment"])
        for change in ("legacy", "subset", "secret-as-public"):
            value = copy.deepcopy(f["fragment"]); row = value["services"][HELPER]
            if change == "legacy": value["apiVersion"] = "catchplate.nativePilotOrdinaryRuntimePolicy/v1"
            elif change == "subset": row["service"]["initialEndpointRoles"].pop()
            else: row["service"]["initialEndpointPins"][HELPER_ROLES[0]]["endpointVerifyingKeyCredential"] = "signing-seed"
            with self.subTest(change=change), self.assertRaises(ValueError): check(value)

    def test_eight_requests_use_actual_role_pins_and_missing_cursor_refuses(self):
        f, contexts, kw = fixture(); selection = requests.select(contexts, **kw)
        rows = tuple(requests.iter_selection(selection))
        self.assertEqual(len(rows), 8)
        self.assertEqual(tuple(item[1] for item in rows[-4:]), HELPER_ROLES)
        value = json.loads(f["runtimes"][HELPER])
        for role in HELPER_ROLES:
            self.assertEqual(selection[HELPER][role]["floor"]["consumeCursor"], value["initialEndpointPins"][role]["consumeCursor"])
            self.assertEqual(selection[HELPER][role]["initialHistorySha256"], sha(f["helper_histories"][role]))
        del value["initialEndpointPins"][HELPER_ROLES[0]]
        contexts[HELPER]["runtimeOriginal"] = canonical(value)
        contexts[HELPER]["guest"]["runtimeConfigurationSha256"] = sha(canonical(value))
        with self.assertRaises(ValueError): requests.select(contexts, **kw)

    def test_successor_export_preserves_exact_member_and_native_request_hashes(self):
        _, contexts, kw = fixture(); value = export(requests.select(contexts, **kw), kw)
        self.assertEqual(len(requests.iter_requests(value)), 8)
        for _, _, row in requests.iter_requests(value):
            self.assertEqual(row["requestSha256"], framed(head.REQUEST_DOMAIN, (row["requestOriginal"].encode("ascii"),)))
        for change in ("legacy", "missing", "swapped"):
            bad = copy.deepcopy(value)
            if change == "legacy": bad["apiVersion"] = "catchplate.nativePilotInitialTrustRequests/v1"
            elif change == "missing": del bad["requests"][HELPER][HELPER_ROLES[0]]
            else: bad["requests"][HELPER][HELPER_ROLES[0]] = bad["requests"][HELPER][HELPER_ROLES[1]]
            with self.subTest(change=change), self.assertRaises(ValueError): requests.shape(canonical(bad))

    def test_four_separate_currentness_decisions_and_real_signatures_keep_original_window(self):
        f, contexts, kw = fixture()
        clocks = dict(boot=kw["boot"], now_boottime_ns=1202)
        public = f["initial_policy"]["services"][HELPER]["authorities"]["checkpoint"]
        for endpoint_role in HELPER_ROLES:
            value = head_input(f, contexts, kw, endpoint_role)
            prepared = head.prepare_input(canonical(value), **clocks)
            signed = signed_result(prepared["statement"], public, private(HELPER + "/checkpoint"))
            self.assertEqual(head.checked_result(canonical(value), signed, **clocks), signed["original"].encode("ascii"))
            self.assertEqual(prepared["statement"]["endpointRole"], endpoint_role)
            for change in ("primary-hash", "wrong-role", "expired", "wrong-cursor"):
                bad, checked_clocks = copy.deepcopy(value), dict(clocks)
                if change == "primary-hash":
                    bad["currentness"]["initialHistorySha256"] = labelled("not selected member")
                elif change == "wrong-role": bad["endpointRole"] = "signer-hsm"
                elif change == "expired": checked_clocks["now_boottime_ns"] = 5000
                else:
                    pending = json.loads(bad["requestOriginal"])
                    pending["operation"]["body"]["accepted_floor"]["consumeCursor"]["expectedPredecessorReceiptSha256"] = labelled("borrowed cursor")
                    from test_native_pilot_current_head import refresh_request, refresh_decision
                    refresh_request(pending); bad["requestOriginal"] = canonical(pending).decode("ascii"); refresh_decision(bad)
                with self.subTest(role=endpoint_role, change=change), self.assertRaises(ValueError):
                    head.prepare_input(canonical(bad), **checked_clocks)

    def test_real_root_signed_helper_grant_binds_public_credential_metadata(self):
        f, _, kw = fixture(); source = generation_context()
        delivery = json.loads(source["deliveries"][HELPER]); payload = delivery["payload"]
        payload.update(lifetimeDeadlineBoottimeNs="9000000")
        payload["runtimeConfig"]["sha256"] = sha(f["runtimes"][HELPER])
        payload["credentials"] = copy.deepcopy(f["fragment"]["services"][HELPER]["credentials"])
        payload["credentials"].append({"name": "authority-history", "original": {
            "path": initial.INITIAL_CREDENTIAL_PATHS[HELPER], "sha256": sha(f["histories"][HELPER])},
            "length": len(f["histories"][HELPER]), "signing": None})
        delivery["signatureBase64url"] = encoded(f["delivery_keys"][HELPER].sign(
            b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload)))
        raw = canonical(delivery)
        _, guest = grants._admit_delivery(signed_raw=raw, cold_raw=canonical(f["cold"][HELPER]),
            cold_sha=sha(canonical(f["cold"][HELPER])), role=HELPER, activation=payload["activation"], boot=kw["boot"],
            startup=5000, lifetime=9000000, now=1300, commitment=False)
        grant = {"apiVersion": "catchplate.custodyServiceGenerationGrant/v1", "purpose": "cold-service-generation-admission",
            "serviceRole": HELPER, "guest": guest, "runtimeConfigurationSha256": sha(f["runtimes"][HELPER]),
            "authorityHistoryManifestSha256": json.loads(f["histories"][HELPER])["history"]["manifestSha256"],
            "scope": scope_fixture(), "issuedAtBoottimeNanos": 1300, "expiresAtBoottimeNanos": 9000000}
        signed = grant_result(HELPER, grant)["original"].encode("ascii")
        args = dict(signed_raw=signed, guest=guest, runtime_raw=f["runtimes"][HELPER], history_raw=f["histories"][HELPER],
            delivery_raw=raw, now=1300, commitment=False)
        self.assertEqual(grants._admit_grant(**args)[0], signed)
        value = json.loads(f["runtimes"][HELPER])
        members = initial.helper_endpoint_histories(f["histories"][HELPER], runtime=value)
        bad = copy.deepcopy(payload["credentials"])
        next(row for row in bad if row["name"] == "helper-service-public")["signing"] = {"keyId": labelled("seed")}
        with self.assertRaises(ValueError): initial.helper_public_keys(value, members, bad)


if __name__ == "__main__":
    unittest.main()
