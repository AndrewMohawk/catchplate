#!/usr/bin/env python3
"""Pure adopted endpoint controls with real deterministic TEST signatures.

The complete trusted-time public chain is synthetic: no observed owner, actual
ciphertext, Nitro verdict, native provisioning, signer process or installation
is claimed. Other seven issuers get closed-profile controls, not invented
ordinary histories, generation receipts or authenticated positive transcripts.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from serverware import native_pilot_adopted_commands as commands
from serverware import native_pilot_adopted_launch_profile as launch
from serverware import native_pilot_encrypted_authority as encrypted
from serverware import native_pilot_generation_install_authority as generation
from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_launch_publication as publication
from serverware import native_pilot_native_service_authority as authority
from serverware import native_pilot_native_service_profile as profile
from serverware import native_pilot_verifier_authority as verifier
from test_native_pilot_adopted_closure import fixture, input_for as closure_input, signed as signed_closure
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import NOW, encoded, key_fixture, signed_message
from test_native_pilot_key_authorizations import build, clocks, expected_payload, signed_result
from test_native_pilot_launch_authorizations import set_credentials, transport
from test_native_pilot_native_services import fixture as service_policy

ROLE = "trustedTime"


def signed(payload, domain):
    return canonical({"payload": payload, "signature": encoded(key_fixture("custody-supervisor-capability")[0].sign(
        signed_message(domain, payload)))})


def peer(f):
    held = f["observed"]["externalDriver"]
    result = {"uid": 64000, "gid": 64000, "pid": held["driver"]["processId"],
        "startTimeTicks": held["driver"]["startTimeTicks"], "cgroupMountId": 20, "cgroupInode": 30,
        **{target: held["executable"][source] for target, source in (("executableDevice", "device"),
            ("executableInode", "inode"), ("executableLength", "length"), ("executableSha256", "sha256"))},
        **{name: synthetic("unobserved-test-peer/" + name) for name in
            ("cgroupPathSha256", "securityLabelSha256", "configurationGenerationSha256")}}
    parts = [result[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    parts += [result[name].to_bytes(8, "big") for name in
        ("startTimeTicks", "executableDevice", "executableInode", "executableLength")]
    parts += [bytes.fromhex(result["executableSha256"][7:]), result["cgroupPathSha256"].encode("ascii"),
        result["cgroupMountId"].to_bytes(8, "big"), result["cgroupInode"].to_bytes(8, "big"),
        result["securityLabelSha256"].encode("ascii"), result["configurationGenerationSha256"].encode("ascii")]
    result["processIdentitySha256"] = "sha256:" + hashlib.sha256(
        b"serverware.policyCustodyPeerProcessIdentity/v4\0" + b"".join(len(part).to_bytes(8, "big") + part for part in parts)).hexdigest()
    return result


def chain():
    f = fixture()
    credentials = copy.deepcopy(json.loads(f["deliveries"][ROLE])["payload"]["credentials"])
    credentials.append({"name": "shadow-encrypted-role-inventory", "original": {
        "path": "/etc/serverware/synthetic-trusted-time-ciphertext.json", "sha256": transport(ROLE)["encryptedInventorySha256"]},
        "length": 256, "signing": None})
    set_credentials(f, ROLE, credentials)
    first = build(f, "role-keys", ROLE, adopted=True)
    first_raw, _ = signed_result(expected_payload(f, "role-keys", ROLE), "role-keys")
    second = build(f, "admission", ROLE, role_key_raw=first_raw, adopted=True)
    second_raw, _ = signed_result(expected_payload(f, "admission", ROLE, role_key_raw=first_raw), "admission")
    raw_pair = (first, first_raw, second, second_raw)
    pair = dict(zip(profile.PAIR_FIELDS, (raw.decode("ascii") for raw in raw_pair), strict=True))
    admitted = keys.admitted_adopted_pair(ROLE, *raw_pair, **clocks(f))
    settings = service_policy()
    guest = admitted["expectedScope"]["guest"]
    operation = {name: guest[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs")}
    operation["deadlineBoottimeNs"] = guest["startupDeadlineBoottimeNs"]
    config = {"apiVersion": "serverware.nativeShadowNitroVerifierConfiguration/v2", "operation": operation,
        **settings["verifierSettings"][ROLE], **admitted}
    trust = json.loads(f["recipe_originals"]["trustOriginal"])
    timing = settings["trustedTime"]
    bootstrap = {"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1", "guest": guest,
        "signingKeyId": trust["timeKey"]["keyId"], **timing}
    delivery = json.loads(f["delivery_inputs"][ROLE])
    peer_raw = canonical(peer(f))
    source = {"apiVersion": authority.ADOPTED_INPUT_API, "operation": ROLE, "configurationOriginal": canonical(config).decode("ascii"),
        "configurationSha256": sha(canonical(config)),
        "assignmentPayloadOriginal": canonical(json.loads(f["recipe_originals"]["assignmentOriginal"])["payload"]).decode("ascii"),
        "cohortConfigurationOriginal": delivery["ownerConfigurationOriginal"], "precreationOriginal": delivery["windowOriginal"],
        "observationOriginal": delivery["observationOriginal"], "coldConfigurationOriginal": delivery["configurationOriginal"],
        "deliveryOriginal": f["deliveries"][ROLE].decode("ascii"), "deliveryInputOriginal": f["delivery_inputs"][ROLE].decode("ascii"),
        "runtimeOriginal": delivery["runtimeOriginal"], "peerOriginal": peer_raw.decode("ascii"), "peerSha256": sha(peer_raw),
        "issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000,
        "bootstrapOriginal": canonical(bootstrap).decode("ascii"), "pair": pair}
    raw = canonical(source)
    prepared = profile.prepare_adopted_input(ROLE, raw, **clocks(f))
    grant = signed(prepared["payload"], prepared["domain"])
    authorizations = {}
    closure = closure_input(f, ROLE); closure_raw, _ = signed_closure(closure)
    authorizations["closure"] = {"inputOriginal": canonical(closure).decode("ascii"), "original": closure_raw.decode("ascii")}
    interval = {"issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}
    encrypted_input = {"apiVersion": encrypted.ADOPTED_API, "operation": "delivery", "role": ROLE, **pair,
        **interval, "transportOriginal": canonical(transport(ROLE)).decode("ascii")}
    encrypted_context = encrypted.prepare_input("delivery", ROLE, canonical(encrypted_input), **clocks(f))
    encrypted_raw = canonical({"apiVersion": encrypted_context["apiVersion"],
        "authorization": json.loads(signed(encrypted_context["payload"], encrypted_context["domain"]))})
    authorizations["encrypted-delivery"] = {"inputOriginal": canonical(encrypted_input).decode("ascii"), "original": encrypted_raw.decode("ascii")}
    verifier_input = {"apiVersion": verifier.ADOPTED_API, "role": ROLE, **pair, **interval, "parentPort": 11443}
    verifier_context = verifier.prepare_input(ROLE, canonical(verifier_input), **clocks(f))
    verifier_raw = canonical({"apiVersion": "serverware.nativeShadowVerifierTransport/v1",
        "authorization": json.loads(signed(verifier_context["payload"], verifier_context["domain"]))})
    authorizations["verifier-transport"] = {"inputOriginal": canonical(verifier_input).decode("ascii"), "original": verifier_raw.decode("ascii")}
    launch_input = {"apiVersion": launch.ALL_API, "role": ROLE, "pair": pair, "authorizations": authorizations,
        "serviceInputOriginal": raw.decode("ascii"), "serviceGrantOriginal": grant.decode("ascii"), "timeBootstrap": timing}
    return f, source, prepared, grant, launch_input


class AdoptedEndpointControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.chain = chain()

    def test_trusted_time_complete_signed_public_chain_keeps_native_domain(self):
        f, source, context, grant, _ = self.chain
        self.assertEqual(context["payload"]["apiVersion"], "serverware.nativeShadowTrustedTimeServiceAssignment/v1")
        self.assertEqual(context["domain"], authority.PROFILES[ROLE][2])
        self.assertEqual(profile.checked_adopted_result(ROLE, canonical(source),
            {"original": grant.decode("ascii"), "sha256": sha(grant)}, **clocks(f)), grant)
        self.assertEqual(commands.prepare_input(ROLE, "grant", canonical(source), **clocks(f))["payload"], context["payload"])

    def test_complete_trusted_time_launch_uses_adopted_closure_and_fixed_paths(self):
        f, _, _, grant, value = self.chain
        result = launch.prepare_input(ROLE, canonical(value), **clocks(f))
        bundle = json.loads(result["bundleOriginal"])
        self.assertEqual(bundle["apiVersion"], launch.BUNDLE_API)
        self.assertEqual(bundle["serviceGrant"]["sha256"], sha(grant))
        self.assertEqual(json.loads(bundle["originals"]["closure"])["apiVersion"], "serverware.nativeCustodyClosure/v5")
        self.assertEqual(json.loads(result["prepared"]["native-launch-trustedTime"])["apiVersion"],
            "serverware.nativeShadowTrustedTimeGuestLaunch/v1")
        self.assertEqual(len(result["prepared"]), 10)

    def test_legacy_and_mixed_source_versions_refuse_before_key_loading(self):
        f, source, _, _, value = self.chain
        for version in ("serverware.nativePilotNativeServiceAuthorityInput/v1", authority.HISTORY_INPUT_API,
                "serverware.nativePilotNativeServiceAuthorityInput/v6"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                commands.prepare_input(ROLE, "grant", canonical({**source, "apiVersion": version}), **clocks(f))
        with self.assertRaises(ValueError): launch.input_document(ROLE, canonical({**value, "apiVersion": launch.API}))
        broken = copy.deepcopy(source); first = json.loads(broken["pair"]["roleKeyInputOriginal"])
        first["apiVersion"] = keys.API; broken["pair"]["roleKeyInputOriginal"] = canonical(first).decode("ascii")
        with self.assertRaises(ValueError): commands.prepare_input(ROLE, "grant", canonical(broken), **clocks(f))

    def test_source_duplicates_current_time_key_and_peer_are_not_replaceable(self):
        f, source, _, _, _ = self.chain
        for name in ("cohortConfigurationOriginal", "precreationOriginal", "observationOriginal", "coldConfigurationOriginal", "runtimeOriginal"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                profile.prepare_adopted_input(ROLE, canonical({**source, name: "{}"}), **clocks(f))
        changed = copy.deepcopy(source); bootstrap = json.loads(changed["bootstrapOriginal"])
        bootstrap["signingKeyId"] = synthetic("other-time-key")
        changed["bootstrapOriginal"] = canonical(bootstrap).decode("ascii")
        with self.assertRaises(ValueError): profile.prepare_adopted_input(ROLE, canonical(changed), **clocks(f))
        changed = copy.deepcopy(source); changed["peerSha256"] = synthetic("different-peer")
        with self.assertRaises(ValueError): profile.prepare_adopted_input(ROLE, canonical(changed), **clocks(f))

    def test_original_signature_and_ceiling_remain_required(self):
        f, source, context, grant, _ = self.chain
        bad = json.loads(grant); bad["signature"] = encoded(bytes(64)); raw = canonical(bad)
        with self.assertRaises(InvalidSignature): profile.checked_adopted_result(ROLE, canonical(source),
            {"original": raw.decode("ascii"), "sha256": sha(raw)}, **clocks(f))
        for replacement in ({"now_boottime_ns": context["deadline"]}, {"now_unix_ns": context["epochLimit"]}):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                profile.prepare_adopted_input(ROLE, canonical(source), **(clocks(f) | replacement))
        changed = {**source, "expiresAtUnixNanos": NOW + 2_000_000_000}
        with self.assertRaises(ValueError): profile.prepare_adopted_input(ROLE, canonical(changed), **clocks(f))

    def test_eleven_explicit_launch_rows_keep_legacy_map_closed(self):
        self.assertEqual(len(launch.ALL_ROLES), 11)
        self.assertEqual(launch.ROLES, ("retrieval", "persistence", "publicationReconciliation"))
        for role in launch.ALL_ROLES:
            api, field, operation = publication.ADOPTED_LAUNCHES[role]
            inner = {"apiVersion": "serverware.nativeShadowGuestLaunch/v1"}
            paths = publication.ADOPTED_DESTINATIONS
            for name, purpose in (("deliveryConfiguration", "native-cold-" + role), ("delivery", "native-delivery-" + role)):
                inner[name] = {"path": paths[purpose], "sha256": synthetic(purpose)}
            for name, (suffix, _) in publication.COMPONENTS.items():
                purpose = "native-" + role + "-" + suffix
                inner[name] = {"path": paths[purpose], "sha256": synthetic(purpose)}
            purpose = "native-generation-install-grant" if operation is None else "native-service-" + operation
            value = {"apiVersion": "serverware." + api, "keyAdmission": inner,
                field: {"path": paths[purpose], "sha256": synthetic(purpose)}}
            self.assertEqual(publication.shape_adopted("native-launch-" + role, canonical(value)), value)
        self.assertNotIn("publicationReconciliation", publication.LAUNCHES)

    def test_companion_and_request_authorization_are_three_distinct_purposes(self):
        self.assertEqual(commands.grant_operation("commitRequest", "grant"), "ledger")
        self.assertEqual(commands.grant_operation("commitRequest", "companion-grant"), "commitRequest")
        for role in launch.ALL_ROLES:
            if role == "commitRequest": continue
            with self.subTest(role=role), self.assertRaises(ValueError): commands.grant_operation(role, "companion-grant")
        _, _, _, _, value = self.chain
        candidate = copy.deepcopy(value); candidate.update(role="commitRequest", companionInputOriginal="{}", companionGrantOriginal="{}")
        with self.assertRaises(ValueError): launch.input_document("commitRequest", canonical(candidate))
        candidate["authorizations"]["request-commitment"] = {"inputOriginal": "{}", "original": "{}"}
        self.assertEqual(launch.input_document("commitRequest", canonical(candidate)), candidate)
        del candidate["companionGrantOriginal"]
        with self.assertRaises(ValueError): launch.input_document("commitRequest", canonical(candidate))

    def test_other_seven_issuers_refuse_missing_history_generation_and_runtime_evidence(self):
        f, source, _, _, _ = self.chain
        for operation in authority.HISTORY_OPERATIONS:
            changed = {**source, "operation": operation}; del changed["bootstrapOriginal"]
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                profile.prepare_adopted_input(operation, canonical(changed), **clocks(f))
        with self.assertRaises(ValueError): profile.prepare_adopted_input("generationInstall",
            canonical({"apiVersion": generation.ADOPTED_INPUT_API}), **clocks(f))

    def test_launch_rejects_different_grant_timing_pair_and_unpinned_authorization(self):
        f, _, _, _, source = self.chain
        changed = copy.deepcopy(source); changed["timeBootstrap"]["parentPort"] += 1
        with self.assertRaises(ValueError): launch.prepare_input(ROLE, canonical(changed), **clocks(f))
        changed = copy.deepcopy(source); signed_grant = json.loads(changed["serviceGrantOriginal"])
        signed_grant["payload"]["clockBootstrapSha256"] = synthetic("different-clock")
        changed["serviceGrantOriginal"] = signed(signed_grant["payload"], authority.PROFILES[ROLE][2]).decode("ascii")
        with self.assertRaises(ValueError): launch.prepare_input(ROLE, canonical(changed), **clocks(f))
        changed = copy.deepcopy(source); del changed["authorizations"]["closure"]
        with self.assertRaises(ValueError): launch.prepare_input(ROLE, canonical(changed), **clocks(f))


if __name__ == "__main__": unittest.main()
