#!/usr/bin/env python3
"""Bounded synthetic bridge commissioning, not protected-owner acceptance.

C9 and five authorization signatures use deterministic in-memory test keys,
not issuer entrypoints. Runtime peers, histories and installation observations
are labelled public projection fixtures, not native admission or provisioning.
Launch projection uses a signed TrustedTime grant but has no complete positive
TrustedTime authority-input transcript; the full launch builder remains strict.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
import os
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_bridge_authorization_profile as authorizations
from serverware import native_pilot_bridge_commissioning_policy as policy
from serverware import native_pilot_bridge_delivery_profile as delivery
from serverware import native_pilot_bridge_launch_profile as launch_profile
from serverware import native_pilot_launch_publication as publication
from serverware import native_pilot_phase_execution as execution
from serverware import native_pilot_supervisor as supervisor
from serverware import native_pilot_supervisor_policy as outer_policy
from test_native_pilot_bridge_authorizations import clocks, public_keys, SERVICES
from test_native_pilot_bridge_launches import fixture as launch_fixture, CLOCK
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import key_fixture, signed_message, encoded, NOW

PROOF_KEYS = {"retrieval": "custody-retrieval-response", "persistence": "custody-store-response",
    "trusted-time": "custody-trusted-time-response", "generation-install-envelope": "custody-result-envelope"}


def result(raw):
    return {"original": raw.decode("ascii"), "sha256": sha(raw)}


@lru_cache(maxsize=1)
def _fixture():
    _, old_pair, grant_raw = launch_fixture(version=11)
    first = json.loads(old_pair["roleKeyInputOriginal"])
    source = json.loads(first["deliveryInputOriginal"])
    operational = json.loads(source["runtimeOriginal"])
    signed_delivery = json.loads(first["deliveryOriginal"])
    credentials = copy.deepcopy(signed_delivery["payload"]["credentials"])
    histories = {role: canonical({"syntheticPrecheckedHistory": role}) for role in SERVICES}
    operational["histories"] = [{"serviceRole": role, "manifestCredential": "history-" + role,
        "manifestSha256": synthetic("semantic-history/" + role), "rootKeyId": synthetic("history-root/" + role),
        "rootKeySpkiSha256": synthetic("history-spki/" + role)} for role in SERVICES]
    for row in operational["histories"]:
        raw = histories[row["serviceRole"]]
        credentials.append({"name": row["manifestCredential"], "original": {
            "path": "/etc/serverware/synthetic-" + row["manifestCredential"], "sha256": sha(raw)},
            "length": len(raw), "signing": None})
    keys = {row["role"]: row for row in public_keys()}
    for field, discriminator in (("parentSignerEndpoints", "signerRole"), ("proofEndpoints", "endpointKind")):
        for row in operational[field]:
            key = keys["custody-" + row[discriminator] if field == "parentSignerEndpoints" else PROOF_KEYS[row[discriminator]]]
            row.update(authorityKeyId=key["keyId"], authorityKeySpkiSha256=key["keySpkiSha256"])
            raw = authorizations.p.decoded(key["publicKeyBase64url"], size=32)
            credentials.append({"name": row["authorityBindingCredential"], "original": {
                "path": "/etc/serverware/synthetic-" + row["authorityBindingCredential"], "sha256": sha(raw)},
                "length": 32, "signing": None})
    journal = next(row for row in json.loads(source["activationOriginal"]) if row["name"] == "production-journal")
    operational["journalDirectoryIdentity"] = {"mountId": 17, "deviceMajor": os.major(journal["device"]),
        "deviceMinor": os.minor(journal["device"]), **{name: journal[name] for name in ("inode", "uid", "gid", "mode")}}
    runtime_raw = canonical(operational)
    source["runtimeOriginal"] = runtime_raw.decode("ascii")
    payload = signed_delivery["payload"]
    payload.update(credentials=credentials, runtimeConfig={"path": "/etc/serverware/native-pilot-inputs/bridge-runtime.json",
        "sha256": sha(runtime_raw)})
    signed_delivery["signatureBase64url"] = encoded(key_fixture("bridge-c9")[0].sign(
        b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(payload)))
    delivery_raw = canonical(signed_delivery)
    source["payloadOriginal"] = canonical(payload).decode("ascii")
    interval = {"issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}
    fragment = {"apiVersion": policy.API, "deliveryCredentials": credentials,
        "keyAuthorization": copy.deepcopy(first["policy"]), "launchAuthorizations": {
            "closure": copy.deepcopy(interval), "encryptedDelivery": copy.deepcopy(interval),
            "verifierTransport": dict(interval, parentPort=11443)}, "timeBootstrap": copy.deepcopy(CLOCK)}
    common = dict(fragment=fragment, control_original=first["controlOriginal"].encode("ascii"),
        delivery_input_raw=canonical(source), delivery_raw=delivery_raw, recipe_originals=first["recipeOriginals"],
        measured=first["measured"], **clocks())
    records = {}
    for operation in authorizations.OPERATIONS:
        raw = authorizations.build(operation, prior_authorizations=records, **common)
        prepared = authorizations.prepare_input(operation, raw, **clocks())
        output = copy.deepcopy(prepared["result"])
        envelope = output["authorization"] if "authorization" in output else output
        envelope["signature"] = encoded(key_fixture("custody-supervisor-capability")[0].sign(
            signed_message(prepared["domain"], prepared["payload"])))
        records[operation] = {"inputOriginal": raw, "authorizationOriginal": canonical(output)}
    pair_context = authorizations._pair_context(records)
    pair = authorizations.keys.admitted_pair(*(pair_context[name].encode("ascii")
        for name in authorizations.PAIR_FIELDS), **clocks())
    return dict(common=common, source=source, runtime=operational, records=records, pair=pair,
        pair_context=pair_context, service_grant_raw=grant_raw, history_originals=histories)


def fixture():
    return copy.deepcopy(_fixture())


def delivery_options(f):
    """Synthetic reported install data, not a genuine retained installer."""
    common, source = f["common"], f["source"]
    configuration = json.loads(source["ownerConfigurationOriginal"])
    window = json.loads(source["windowOriginal"])["payload"]
    runtime_raw = source["runtimeOriginal"].encode("ascii")
    outgoing = {"apiVersion": "serverware.nativeShadowDriverOutgoingInputs/v1",
        "driverConfigurationSha256": sha(source["ownerConfigurationOriginal"].encode("ascii")),
        "driverWindowSha256": sha(source["windowOriginal"].encode("ascii")),
        "driverObservationSha256": sha(source["observationOriginal"].encode("ascii")),
        "invocationId": window["invocationId"], "deliveryConfiguration": configuration["deliveryConfiguration"],
        "runtime": {"path": "/etc/serverware/native-pilot-inputs/bridge-runtime.json", "sha256": sha(runtime_raw)},
        "bridgeLaunchVersion": "serverware.nativeProofBridgeLaunch/v7"}
    outgoing_raw = canonical(outgoing)
    bundle = canonical({"apiVersion": "serverware.nativePilotBridgeRuntimeBundle/v1",
        "driverControlSha256": sha(common["control_original"]), "driverObservationOriginal": source["observationOriginal"],
        "runtimeOriginal": source["runtimeOriginal"], "outgoingOriginal": outgoing_raw.decode("ascii")})
    installed = {"apiVersion": "serverware.nativePilotBridgeRuntimeInstallation/v1", "bundleSha256": sha(bundle),
        "configurationSha256": outgoing["driverConfigurationSha256"], "windowSha256": outgoing["driverWindowSha256"],
        "observationSha256": outgoing["driverObservationSha256"], "invocationId": window["invocationId"],
        "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"], "pins": {
            name: {"path": delivery.publication.DESTINATIONS[name], "sha256": sha(raw)}
            for name, raw in (("bridge-runtime", runtime_raw), ("bridge-outgoing", outgoing_raw))}}
    return dict(fragment=common["fragment"], runtime_bundle_raw=bundle, runtime_result=installed,
        bootstrap_originals={"control": common["control_original"], "configuration": source["ownerConfigurationOriginal"].encode("ascii"),
            "window": source["windowOriginal"].encode("ascii"), "deliveryConfiguration": source["configurationOriginal"].encode("ascii")},
        activation=json.loads(source["activationOriginal"]), recipe_originals=common["recipe_originals"],
        measured=common["measured"], history_originals=f["history_originals"], **clocks())


class BridgeCommissioningControls(unittest.TestCase):
    def test_fixed_seven_bridge_jobs_add_five_selectors_without_legacy_or_release_authority(self):
        names = ("native-delivery-bridge", "native-role-keys-bridge", "native-key-admission-bridge",
            "native-closure-bridge", "native-encrypted-delivery-bridge", "native-verifier-transport-bridge",
            "install-launch-bridge")
        jobs = execution.JOBS["bridge-delivery"]
        self.assertEqual(tuple(job.name for job in jobs), names)
        self.assertEqual(tuple(execution.BRIDGE_AUTHORIZATION_JOBS), jobs[1:-1])
        for index, job in enumerate(jobs, 1):
            self.assertEqual(execution.job_index("bridge-delivery", job.name), index)
            self.assertIn(("bridge-delivery", job.name), supervisor.SUPPORTED_JOBS)
            self.assertIn(("bridge-delivery", job.name), supervisor._COMPOSERS)
        for job, operation in zip(jobs[1:-1], authorizations.OPERATIONS, strict=True):
            self.assertEqual((job.key, job.role, job.purpose, job.family), (job.name, "bridge", None, "bridge-authorization"))
            self.assertEqual(execution.BRIDGE_AUTHORIZATION_JOB_INFO[job.name], operation)
        added = set(execution.KEY_PURPOSES) - set(outer_policy.LAUNCH_KEY_PURPOSES)
        self.assertEqual(added, set(names[1:-1]))
        self.assertEqual((len(outer_policy.LAUNCH_KEY_PURPOSES), len(execution.KEY_PURPOSES)), (108, 113))
        # This is the actual closed key-name parser, not a claim of Policy.open.
        legacy = {name: "synthetic-unvalidated-key-pin" for name in outer_policy.LAUNCH_KEY_PURPOSES}
        self.assertEqual(outer_policy.p.fields(legacy, outer_policy.LAUNCH_KEY_PURPOSES), legacy)
        with self.assertRaises(ValueError):
            outer_policy.p.fields(legacy | {names[1]: "not-legacy-authority"}, outer_policy.LAUNCH_KEY_PURPOSES)
        self.assertEqual((len(supervisor.SUPPORTED_JOBS), len(supervisor._ORDER), len(supervisor.missing_jobs())), (158, 164, 6))
        self.assertEqual(supervisor.missing_jobs()[0], ("release", "cohort-release"))
        with self.assertRaises(ValueError): supervisor.require_complete_coverage()

    def test_policy_is_closed_and_preserves_twenty_non_signing_credential_selections(self):
        f = fixture(); fragment = f["common"]["fragment"]
        options = dict(bootstrap_configuration=json.loads(f["source"]["ownerConfigurationOriginal"]),
            cold_original=f["source"]["configurationOriginal"].encode("ascii"))
        checked = policy.validate_policy(fragment, **options)
        self.assertEqual(checked, fragment)
        self.assertEqual(set(checked), {"apiVersion", "deliveryCredentials", "keyAuthorization", "launchAuthorizations", "timeBootstrap"})
        names = [row["name"] for row in checked["deliveryCredentials"]]
        self.assertEqual((len(names), len(set(names))), (20, 20))
        self.assertTrue(all(row["signing"] is None for row in checked["deliveryCredentials"]))
        for change in ("missing", "duplicate", "private-key", "ciphertext", "transport-override", "unknown"):
            bad = copy.deepcopy(fragment)
            if change == "missing": bad["deliveryCredentials"].pop()
            elif change == "duplicate": bad["deliveryCredentials"][-1] = copy.deepcopy(bad["deliveryCredentials"][0])
            elif change == "private-key": bad["deliveryCredentials"][-1]["name"] = "shadow-key-custody-result-envelope"
            elif change == "ciphertext": bad["deliveryCredentials"][0]["original"]["sha256"] = synthetic("unapproved-ciphertext")
            elif change == "transport-override": bad["launchAuthorizations"]["encryptedDelivery"]["transportOriginal"] = "{}"
            else: bad["currentnessApproved"] = True
            with self.subTest(change=change), self.assertRaises(ValueError): policy.validate_policy(bad, **options)

    def test_c9_binds_exact_public_metadata_bytes_and_signed_result_not_semantic_hashes(self):
        f = fixture(); options = delivery_options(f)
        self.assertEqual(options["runtime_result"]["pins"]["bridge-outgoing"]["path"],
            "/etc/serverware/native-shadow-driver-outgoing.json")
        raw = delivery.build(**options)
        self.assertEqual(raw, f["common"]["delivery_input_raw"])
        reported = result(f["common"]["delivery_raw"])
        reported["pin"] = {"path": "/etc/serverware/native-pilot-inputs/native-delivery-bridge.json", "sha256": reported["sha256"]}
        self.assertEqual(delivery.checked_result(raw, reported, **options), f["common"]["delivery_raw"])
        payload = json.loads(json.loads(raw)["payloadOriginal"])
        self.assertEqual(payload["credentials"], f["common"]["fragment"]["deliveryCredentials"])
        self.assertEqual(len(payload["activation"]), 41)
        for change in ("history-semantic", "public-spki", "journal", "result-pin"):
            bad = copy.deepcopy(options)
            if change == "history-semantic":
                history = f["runtime"]["histories"][0]
                row = next(row for row in bad["fragment"]["deliveryCredentials"] if row["name"] == history["manifestCredential"])
                row["original"]["sha256"] = history["manifestSha256"]
            elif change == "public-spki":
                endpoint = f["runtime"]["proofEndpoints"][0]
                row = next(row for row in bad["fragment"]["deliveryCredentials"] if row["name"] == endpoint["authorityBindingCredential"])
                row["original"]["sha256"] = endpoint["authorityKeySpkiSha256"]
            elif change == "journal":
                next(row for row in bad["activation"] if row["name"] == "production-journal")["inode"] += 1
            else:
                changed = copy.deepcopy(reported); changed["pin"]["sha256"] = synthetic("different-result")
                with self.assertRaises(ValueError): delivery.checked_result(raw, changed, **bad)
                continue
            with self.subTest(change=change), self.assertRaises(ValueError): delivery.build(**bad)

    def test_five_real_synthetic_authorizations_bind_exact_predecessors_and_original_transport(self):
        f = fixture()
        self.assertEqual(authorizations.OPERATIONS, ("role-keys", "admission", "closure", "encrypted-delivery", "verifier-transport"))
        for operation, row in f["records"].items():
            self.assertEqual(authorizations.checked_result(operation, row["inputOriginal"],
                result(row["authorizationOriginal"]), **clocks()), row["authorizationOriginal"])
        admitted = json.loads(f["records"]["admission"]["authorizationOriginal"])["payload"]
        self.assertEqual(admitted["productionConfigurationBindingSha256"], f["common"]["measured"]["configurationBindingSha256"])
        encrypted = json.loads(f["records"]["encrypted-delivery"]["authorizationOriginal"])["authorization"]["payload"]
        config = json.loads(f["source"]["ownerConfigurationOriginal"])
        self.assertEqual(encrypted["transport"], config["continuation"]["keyTransport"])
        self.assertEqual(encrypted["keyAuthorizationSha256"], sha(f["records"]["role-keys"]["authorizationOriginal"]))
        closure = json.loads(f["records"]["closure"]["authorizationOriginal"])
        self.assertEqual(closure["authorization"]["payload"]["guestRole"], "bridge")
        self.assertEqual(canonical(closure["closureSet"]).decode("ascii"), f["common"]["recipe_originals"]["closureSetOriginal"])

    def test_reordered_missing_changed_prior_and_signature_refuse_without_new_approval(self):
        f = fixture(); operation = authorizations.OPERATIONS[-1]
        prior = {name: row for name, row in f["records"].items() if name != operation}
        for change in ("missing", "future", "input", "signature", "policy-order"):
            bad, common = copy.deepcopy(prior), copy.deepcopy(f["common"])
            if change == "missing": bad.pop("closure")
            elif change == "future": bad[operation] = f["records"][operation]
            elif change == "input": bad["role-keys"]["inputOriginal"] += b"\n"
            elif change == "signature":
                value = json.loads(bad["closure"]["authorizationOriginal"])
                value["authorization"]["signature"] = encoded(b"X" * 64)
                bad["closure"]["authorizationOriginal"] = canonical(value)
            else: common["fragment"]["deliveryCredentials"].reverse()
            with self.subTest(change=change), self.assertRaises((ValueError, InvalidSignature)):
                authorizations.build(operation, prior_authorizations=bad, **common)

    def test_original_clock_bounds_and_result_hash_cannot_be_renewed(self):
        f = fixture(); row = f["records"]["closure"]
        prepared = authorizations.prepare_input("closure", row["inputOriginal"], **clocks())
        self.assertEqual(prepared["deadline"], 2_000_000_000)
        self.assertEqual(prepared["epochLimit"], NOW + 100_000_000)
        for field, value in (("now_boottime_ns", 2_000_000_000), ("now_unix_ns", NOW + 100_000_000),
                ("boot", (encoded(b"X" * 16), 4, 5))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                authorizations.checked_result("closure", row["inputOriginal"], result(row["authorizationOriginal"]),
                    **(clocks() | {field: value}))
        for change in ("hash", "extra"):
            reported = result(row["authorizationOriginal"])
            if change == "hash": reported["sha256"] = synthetic("unrelated-authorization")
            else: reported["approved"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                authorizations.checked_result("closure", row["inputOriginal"], reported, **clocks())

    def test_launch_projection_keeps_v2_keys_exact_nine_pins_and_actual_signed_time_grant(self):
        f = fixture()
        raw = launch_profile._bundle(f["common"]["fragment"], source=f["source"],
            recipe_originals=f["common"]["recipe_originals"], pair=f["pair"],
            authorization_originals={name: row["authorizationOriginal"] for name, row in f["records"].items()},
            service_grant_raw=f["service_grant_raw"])
        options = dict(pair_context=f["pair_context"], service_grant_original=f["service_grant_raw"], **clocks())
        checked = publication.prepare_bridge_bundle(raw, **options)
        self.assertEqual(len(checked["pins"]), 9)
        self.assertNotIn("bridge-runtime", checked["prepared"])
        self.assertEqual(json.loads(checked["prepared"]["native-bridge-keys"])["apiVersion"], "serverware.nativeShadowRoleKeys/v2")
        self.assertEqual(json.loads(checked["prepared"]["native-launch-bridge"])["apiVersion"], "serverware.nativeProofBridgeLaunch/v7")
        value = json.loads(raw)
        self.assertEqual(value["serviceGrant"]["sha256"], sha(f["service_grant_raw"]))
        reported = {"apiVersion": "serverware.nativePilotLaunchInstallation/v1", "role": "bridge", "bundleSha256": sha(raw),
            "startupDeadlineBoottimeNs": checked["window"]["startupDeadlineBoottimeNs"],
            "lifetimeDeadlineBoottimeNs": checked["window"]["lifetimeDeadlineBoottimeNs"],
            "launch": checked["launch"], "pins": checked["pins"]}
        self.assertEqual(publication.checked_bridge_result(raw, reported, **options), reported)
        changed = copy.deepcopy(reported); changed["launch"]["sha256"] = synthetic("different-installation")
        with self.assertRaises(ValueError): publication.checked_bridge_result(raw, changed, **options)
        with self.assertRaises(ValueError): launch_profile.prepare(**f["common"], authorizations=f["records"],
            service_context={"inputOriginal": b"{}", "grantOriginal": f["service_grant_raw"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
