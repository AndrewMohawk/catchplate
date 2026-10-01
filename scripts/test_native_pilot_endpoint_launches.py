#!/usr/bin/env python3
"""Synthetic public launch controls; no files, KMS, owners or native startup.

Two roles exercise complete authenticated public composition using deterministic
test signatures. The other eight cover deterministic projection and refusals,
not a complete operational history transcript. Fixture grants/bootstrap/genesis
are not live state, provisioning, attestation or proof of an installed file.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_endpoint_launch_profile as profile
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_native_service_profile as services
from test_native_pilot_launch_authorizations import (fixture, policy_fragment as late_policy,
    pair, expected, signed, ROLES, clocks)
from test_native_pilot_native_services import fixture as service_policy
from test_native_pilot_generation_scope import NOW, key_fixture, encoded, signed_message
from test_native_pilot_closure_set import canonical, sha, synthetic

CLOCK_FIELDS = ("parentPort", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm")
COMPONENTS = {"trust": "trust", "timeBootstrap": "time-bootstrap", "assignment": "assignment",
    "closure": "closure", "keys": "keys", "encryptedKeys": "encrypted-keys", "admission": "admission",
    "verifierTransport": "verifier"}
SERVICE_MAP = {role: role for role in ROLES} | {
    "commitRequest": "ledger", "ingressAdmission": "ingress", "terminalAppend": "terminal"}


def policy_fragment():
    return {"apiVersion": "serverware.nativePilotEndpointLaunchPolicy/v1", "endpoints": {
        role: {"parentPort": 10444, "maximumBracketNanos": "1000000", "timestampErrorNanos": 1000,
            "maximumClockRateErrorPpm": 10} for role in ROLES}}


def peer_original(f):
    """Independently frame a labelled synthetic peer matching the fixture census."""
    observed = f["observed"]["externalDriver"]
    executable, process = observed["executable"], observed["driver"]
    value = {"uid": 61000, "gid": 61000, "pid": process["processId"], "startTimeTicks": process["startTimeTicks"],
        **{"executable" + name[0].upper() + name[1:]: executable[name] for name in ("device", "inode", "length", "sha256")},
        "cgroupPathSha256": synthetic("synthetic-driver-cgroup"), "cgroupMountId": 7, "cgroupInode": 11,
        "securityLabelSha256": synthetic("synthetic-driver-label"), "configurationGenerationSha256": synthetic("synthetic-driver-generation")}
    pieces = [value[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    pieces += [value[name].to_bytes(8, "big") for name in ("startTimeTicks", "executableDevice", "executableInode", "executableLength")]
    pieces += [bytes.fromhex(value["executableSha256"][7:]), value["cgroupPathSha256"].encode("ascii"),
        value["cgroupMountId"].to_bytes(8, "big"), value["cgroupInode"].to_bytes(8, "big"),
        value["securityLabelSha256"].encode("ascii"), value["configurationGenerationSha256"].encode("ascii")]
    value["processIdentitySha256"] = sha(b"serverware.policyCustodyPeerProcessIdentity/v4\0"
        + b"".join(len(part).to_bytes(8, "big") + part for part in pieces))
    return canonical(value)


def service_fixture(f, role, pair_context, settings, selected):
    """Complete public input for the two roles without ordinary-history inputs."""
    context = services._context(role, settings, pair_context, **clocks(f))
    peer_raw = peer_original(f)
    value = services._base(role, context, peer_raw)
    key = json.loads(pair_context["roleKeyOriginal"])["payload"]
    common = {name: key[name] for name in ("guest", "assignmentPayloadSha256", "trustCheckpointId",
        "revocationGeneration", "revocationRootSha256", "signingKeyId", "signingKeySpkiSha256")}
    common.update(keyAuthorizationSha256=sha(pair_context["roleKeyOriginal"].encode("ascii")),
        issuedAtUnixNanos=NOW - 500_000_000, expiresAtUnixNanos=NOW + 500_000_000,
        expectedPeer=json.loads(peer_raw))
    if role == "trustedTime":
        trust = json.loads(f["recipe_originals"]["trustOriginal"])
        bootstrap = canonical({"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1", "guest": key["guest"],
            "signingKeyId": trust["timeKey"]["keyId"], **selected["endpoints"][role]})
        value["bootstrapOriginal"] = bootstrap.decode("ascii")
        payload = {**common, "apiVersion": "serverware.nativeShadowTrustedTimeServiceAssignment/v1",
            "purpose": "native-shadow-trusted-time-response", "clockBootstrapSha256": sha(bootstrap)}
        domain = "serverware.nativeShadowTrustedTimeServiceAssignment.signature/v1"
    else:
        if role != "persistence":
            raise AssertionError("only two complete service fixtures are provided")
        proof_raw = f["measured"]["proofScopeOriginal"].encode("ascii")
        genesis = canonical({"apiVersion": "serverware.nativeShadowPersistenceGenesis/v1",
            "proofScopeSha256": json.loads(proof_raw)["binding_sha256"], "guest": key["guest"]})
        journal = {"genesisSha256": sha(genesis), "headSequence": 0, "headSha256": sha(genesis)}
        value.update(proofScopeOriginal=proof_raw.decode("ascii"), genesisOriginal=genesis.decode("ascii"),
            journalOriginal=canonical(journal).decode("ascii"), permissions=["store-dispatch-original", "verify-persistence"])
        payload = {**common, "apiVersion": "serverware.nativeShadowPersistenceServiceAssignment/v1",
            "purpose": "native-shadow-receipt-persistence", "proofScopeOriginalBase64url": encoded(proof_raw),
            "journal": journal, "permissions": list(value["permissions"])}
        domain = "serverware.nativeShadowPersistenceServiceAssignment.signature/v1"
    grant = canonical({"payload": payload, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
        signed_message(domain, payload)))})
    return {"inputOriginal": canonical(value), "grantOriginal": grant, "commitRequestOriginal": None}


class EndpointLaunchControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture(); cls.selected = policy_fragment(); cls.late_selected = late_policy()
        cls.settings = service_policy()
        cls.pairs = {role: pair(cls.f, role) for role in ROLES}
        cls.auth = {}; cls.service = {}; cls.bundles = {}

    def authorizations(self, role):
        if role not in self.auth:
            outputs, records = {}, {}
            for operation in (("closure", "request-commitment", "encrypted-delivery", "verifier-transport")
                    if role == "commitRequest" else ("closure", "encrypted-delivery", "verifier-transport")):
                prior = outputs.get("request-commitment") if operation == "encrypted-delivery" else None
                raw = profile.late.build(operation, role, fragment=self.late_selected, pair_context=self.pairs[role],
                    prior_authorization_originals={} if prior is None else {"request-commitment": prior}, **clocks(self.f))
                payload = expected(self.f, self.late_selected, self.pairs[role], operation, role)
                output, _ = signed(self.f, operation, role, payload, prior=prior)
                outputs[operation] = output
                records[operation] = {"inputOriginal": raw, "authorizationOriginal": output}
            self.auth[role] = records
        return self.auth[role]

    def arguments(self, role):
        if role not in self.service:
            self.service[role] = service_fixture(self.f, role, self.pairs[role], self.settings, self.selected)
        return dict(fragment=self.selected, pair_context=self.pairs[role], authorizations=self.authorizations(role),
            service_context=self.service[role], **clocks(self.f))

    def bundle(self, role):
        if role not in self.bundles:
            self.bundles[role] = profile.build(role, **self.arguments(role))
        return self.bundles[role]

    def options(self, role):
        return dict(delivery_input_original=self.f["delivery_inputs"][role], delivery_original=self.f["deliveries"][role],
            service_grant_original=self.service[role]["grantOriginal"], commit_request_original=None, **clocks(self.f))

    def test_exact_ten_role_policy_and_independent_four_settings(self):
        self.assertEqual(profile.ROLES, ROLES); self.assertEqual(profile.SERVICE_OPERATIONS, SERVICE_MAP)
        checked = profile.validate_policy(self.selected)
        self.assertEqual(checked, self.selected)
        self.assertTrue(all(set(row) == set(CLOCK_FIELDS) for row in checked["endpoints"].values()))
        checked["endpoints"]["retrieval"]["parentPort"] += 1
        self.assertNotEqual(checked, self.selected)

    def test_policy_unknown_missing_null_bool_and_bounds_reject(self):
        cases = []
        for field, value in (("parentPort", 1023), ("parentPort", True), ("maximumBracketNanos", "0"),
                ("maximumBracketNanos", "1000000001"), ("maximumBracketNanos", 1), ("timestampErrorNanos", -1),
                ("maximumClockRateErrorPpm", 10001), ("signingKeyId", synthetic("unapproved-key"))):
            row = copy.deepcopy(self.selected); row["endpoints"]["retrieval"][field] = value; cases.append(row)
        row = copy.deepcopy(self.selected); row["apiVersion"] += "-unknown"; cases.append(row)
        row = copy.deepcopy(self.selected); del row["endpoints"]["retrieval"]; cases.append(row)
        row = copy.deepcopy(self.selected); row["endpoints"]["bridge"] = row["endpoints"]["retrieval"]; cases.append(row)
        row = copy.deepcopy(self.selected); row["endpoints"]["retrieval"] = None; cases.append(row)
        for row in cases:
            with self.assertRaises(ValueError): profile.validate_policy(row)

    def test_two_complete_signed_launch_paths_and_exact_reported_pins(self):
        for role in ("persistence", "trustedTime"):
            with self.subTest(role=role):
                raw = self.bundle(role)
                context = launch.prepare_endpoint_bundle(raw, **self.options(role))
                self.assertEqual(len(context["prepared"]), 10)
                self.assertEqual(tuple(context["prepared"]), ("native-runtime-" + role,
                    *("native-" + role + "-" + suffix for suffix in COMPONENTS.values()), "native-launch-" + role))
                pins = {purpose: {"path": "/etc/serverware/native-pilot-inputs/" + purpose + ".json", "sha256": sha(value)}
                    for purpose, value in context["prepared"].items()}
                self.assertEqual(context["pins"], pins)
                result = {"apiVersion": "serverware.nativePilotLaunchInstallation/v1", "role": role,
                    "bundleSha256": sha(raw), "startupDeadlineBoottimeNs": self.f["window"]["startupDeadlineBoottimeNs"],
                    "lifetimeDeadlineBoottimeNs": self.f["window"]["lifetimeDeadlineBoottimeNs"],
                    "launch": pins["native-launch-" + role], "pins": pins}
                self.assertEqual(profile.checked_result(role, raw, result, pair_context=self.pairs[role],
                    service_context=self.service[role], **clocks(self.f)), result)
                for changed in (result | {"installed": True}, result | {"bundleSha256": synthetic("wrong-bundle")},
                        result | {"launch": {"path": "/etc/wrong.json", "sha256": result["launch"]["sha256"]}}):
                    with self.assertRaises(ValueError): launch.checked_endpoint_result(raw, changed, **self.options(role))

    def test_all_ten_projection_paths_do_not_claim_full_service_acceptance(self):
        for role in ROLES:
            context = profile._pair(role, self.pairs[role], clocks(self.f))
            outputs = {name: item["authorizationOriginal"] for name, item in self.authorizations(role).items()}
            service_input = {}; grant = canonical({"syntheticProjectionOnly": role})
            if role == "trustedTime":
                self.arguments(role); service_input = json.loads(self.service[role]["inputOriginal"])
            # Other roles deliberately use a labelled projection-only grant;
            # it never enters build(), preparation, or signature acceptance.
            raw = profile._bundle(role, self.selected["endpoints"][role], context, outputs,
                {"grantOriginal": grant}, service_input)
            value = json.loads(raw)
            self.assertEqual(len(value), 9)
            self.assertEqual(value["serviceGrant"], {"path": "/etc/serverware/native-pilot-inputs/"
                + ("native-generation-install-grant" if role == "generationInstall" else "native-service-" + SERVICE_MAP[role])
                + ".json", "sha256": sha(grant)})
            self.assertEqual(json.loads(value["originals"]["keys"]), {"apiVersion": "serverware.nativeShadowRoleKeys/v2",
                "authorization": json.loads(self.pairs[role]["roleKeyOriginal"])})
            for name, suffix in COMPONENTS.items():
                self.assertEqual(value["keyAdmission"][name], {"path": "/etc/serverware/native-pilot-inputs/native-"
                    + role + "-" + suffix + ".json", "sha256": sha(value["originals"][name].encode("ascii"))})

    def test_trusted_time_uses_original_grant_bound_bootstrap_without_replacement(self):
        raw = self.bundle("trustedTime")
        original = json.loads(self.service["trustedTime"]["inputOriginal"])["bootstrapOriginal"]
        self.assertEqual(json.loads(raw)["originals"]["timeBootstrap"], original)
        payload = json.loads(self.service["trustedTime"]["grantOriginal"])["payload"]
        self.assertEqual(payload["clockBootstrapSha256"], sha(original.encode("ascii")))
        args = self.arguments("trustedTime"); args["fragment"] = copy.deepcopy(args["fragment"])
        args["fragment"]["endpoints"]["trustedTime"]["parentPort"] += 1
        with self.assertRaises(ValueError): profile.build("trustedTime", **args)

    def test_actual_grant_and_authorization_signatures_and_context_are_required(self):
        base = self.arguments("trustedTime")
        for target in ("grant", "authorization", "different-role", "missing", "companion"):
            args = copy.deepcopy(base)
            if target == "grant":
                value = json.loads(args["service_context"]["grantOriginal"]); value["signature"] = encoded(bytes(64))
                args["service_context"]["grantOriginal"] = canonical(value)
            elif target == "authorization":
                row = args["authorizations"]["verifier-transport"]; value = json.loads(row["authorizationOriginal"])
                value["authorization"]["signature"] = encoded(bytes(64)); row["authorizationOriginal"] = canonical(value)
            elif target == "different-role": args["pair_context"] = self.pairs["persistence"]
            elif target == "missing": del args["authorizations"]["closure"]
            else: args["service_context"]["commitRequestOriginal"] = canonical({"unapproved": True})
            with self.subTest(target=target), self.assertRaises((ValueError, InvalidSignature)):
                profile.build("trustedTime", **args)

    def test_bundle_fixed_original_pins_runtime_and_boot_cannot_be_substituted(self):
        raw = self.bundle("trustedTime")
        for target in ("runtimeOriginal", "ownerConfigurationSha256", "windowSha256", "serviceGrant", "keys"):
            value = json.loads(raw)
            if target == "runtimeOriginal": value[target] = canonical({"apiVersion": "serverware.nativePilotEndpointRuntime/v1", "role": "persistence"}).decode("ascii")
            elif target == "serviceGrant": value[target]["path"] = "/etc/serverware/native-pilot-inputs/native-service-persistence.json"
            elif target == "keys": value["keyAdmission"][target]["sha256"] = synthetic("substituted-key-wrapper")
            else: value[target] = synthetic("different-" + target)
            with self.assertRaises(ValueError): launch.prepare_endpoint_bundle(canonical(value), **self.options("trustedTime"))
        for override in ({"now_boottime_ns": int(self.f["window"]["startupDeadlineBoottimeNs"])},
                {"now_unix_ns": NOW + 1_000_000_000}, {"boot": (encoded(b"different-boot16"), 4, 5)}):
            with self.assertRaises(ValueError): launch.prepare_endpoint_bundle(raw, **(self.options("trustedTime") | override))

    def test_bridge_or_incomplete_service_context_is_never_a_launch(self):
        with self.assertRaises(ValueError): profile.build("bridge", **self.arguments("trustedTime"))
        for role in ROLES:
            with self.subTest(role=role), self.assertRaises(ValueError):
                profile.build(role, fragment=self.selected, pair_context=self.pairs[role], authorizations={},
                    service_context={"inputOriginal": b"{}", "grantOriginal": b"{}", "commitRequestOriginal": None}, **clocks(self.f))


if __name__ == "__main__":
    unittest.main(verbosity=2)
