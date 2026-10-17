#!/usr/bin/env python3
"""Read-only actual-container proof for the private managed app/gate fixture.

Retains the existing curated probe's lock, original leaf inodes, executable,
policy and private-file checks. Adds exactly the public managed manifest and
an app-only custody directory. Never starts a container or reads key bytes.
Root invokes unconfigured, before-clients and after-clients phases separately.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import time

from scripts import check_operator_curated_gate as curated
from scripts import prepare_operator_managed_google_gate_fixture as fixture

base, basic = fixture.base, fixture.basic
SCHEMA = "catchplate.privateManagedGoogleGateMountObservation/v1"

# These are checked, exact additions to the pinned existing probe, not a
# replacement mount oracle. A changed upstream anchor refuses source assembly.
MANAGED_PROBE = r'''
def managed_configuration(root):
    need(os.environ.get("CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED") == "1")
    path = root / "operator-google-configuration.json"
    prior = identity(path)
    need(prior["mode"] == 0o600 and 0 < prior["size"] <= 32768)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        need((opened.st_dev, opened.st_ino) == (prior["device"], prior["inode"]))
        raw = os.read(descriptor, 32769)
    finally: os.close(descriptor)
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result); result[key] = value
        return result
    need(len(raw) == prior["size"] and identity(path) == prior)
    manifest = json.loads(raw, object_pairs_hook=pairs)
    need(manifest == expected_manifest)
    identity_value = {key: manifest[key] for key in ("operation", "profile_binding_digest", "effective_settings_digest")}
    provider = None
    if mode == "app":
        need(os.environ.get("CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR") == "/provider-custody")
        provider = {"directory": directory("/provider-custody"), "key_present": manifest["operation"] is not None}
        need(provider["directory"] != directory("/data") and provider["directory"] != directory(root))
        need(set(os.listdir("/provider-custody")) == ({"provider-key.json"} if provider["key_present"] else set()))
        if provider["key_present"]:
            key = identity("/provider-custody/provider-key.json")
            need(key["mode"] == 0o600 and 0 < key["size"] <= 4096)
            provider["key_metadata"] = key  # Stat only; never read or hash key bytes.
    else:
        need("CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR" not in os.environ)
        for path in ("/provider-custody", "/managed-work", "/data/provider-custody", "/data/provider-key.json"):
            try: os.lstat(path)
            except FileNotFoundError: pass
            else: raise ValueError("provider custody exposed")
    return {"identity": identity_value, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_metadata": prior, "provider_custody": provider}
'''


def probe_source():
    source = curated.PROBE
    edits = (
        ("mode, expected_binary = sys.argv[1:]", "mode, expected_binary, expected_manifest_json = sys.argv[1:]\nexpected_manifest = json.loads(expected_manifest_json)"),
        ('"response-signing-ed25519.pem", "dev-tee-quote-ed25519.pem", "webauthn-trust-signing-ed25519.pem")',
         '"response-signing-ed25519.pem", "dev-tee-quote-ed25519.pem", "webauthn-trust-signing-ed25519.pem", "provider-key.json")'),
        ('try:\n    directory("/data")', MANAGED_PROBE + '\ntry:\n    directory("/data")'),
        ('{"policy-bundle.json", leaves[0], leaves[1], "mitmproxy"}',
         '{"policy-bundle.json", "operator-google-configuration.json", leaves[0], leaves[1], "mitmproxy"}'),
        ('        current = policy(root / "policy-bundle.json")',
         '        current = policy(root / "policy-bundle.json")\n        managed = managed_configuration(root)'),
        ('"private_files": visible, "mountinfo": mounts, "actual_executable": executable}',
         '"private_files": visible, "mountinfo": mounts, "actual_executable": executable, "managed": managed}'),
    )
    for old, new in edits:
        base.require(source.count(old) == 1, "pinned curated probe anchor differs")
        source = source.replace(old, new)
    return source


def observation_receipt(receipt, expected, policy, revision, binary_sha, phase):
    base.require(receipt.get("schema") == "catchplate.managedGoogleFixtureObservation/v1"
        and receipt.get("ok") is True and receipt.get("syntheticOnly") is True and receipt.get("readOnly") is True
        and receipt.get("phase") == phase and receipt.get("managedGoogle") == fixture.identity(expected)
        and receipt.get("catalogRevision") == revision and receipt.get("policyHash") == policy["policy_hash"]
        and receipt.get("policySequence") == policy["sequence"] and receipt.get("actualAppGateReady") is True
        and receipt.get("dataPlaneBinaryDigest") == "sha256:" + binary_sha
        and receipt.get("catalogResources") == {"credentials": 0, "applications": 0, "access_rules": 0}
        and receipt.get("googleConsentStarted") is False and receipt.get("realProviderVerified") is False,
        "actual read-only app/gate readiness receipt differs")


def verify_transition(before, after, client):
    base.require(before.get("schema") == SCHEMA and before.get("phase") == "before"
        and before.get("managed_google") == after["managed_google"] == client.get("managedGoogle")
        and before.get("manifest_sha256") == after["manifest_sha256"]
        and before.get("manifest_metadata") == after["manifest_metadata"]
        and before.get("provider_custody") == after["provider_custody"]
        and client.get("managedInitialRevision") == 3 and client.get("googleConsentStarted") is False,
        "managed activation changed during ordinary policy reloads")
    # Reuse the entire original two-reload/actual-client transition oracle.
    # Only its schema/phase wrapper is translated; no measured field is changed.
    legacy_before = {**before, "schema": "catchplate.privateCuratedGateObservation/v1"}
    return curated.verify_transition(legacy_before, after, client)


def run(args):
    root = args.job_root
    base.require(root.resolve() == root and root.parent == base.SCRATCH and re.fullmatch(
        r"catchplate-managed-google-gate-private\.[A-Za-z0-9]{6,32}", root.name), "exact managed fixture root required")
    base.require((args.phase == "after") == bool(args.before_receipt and args.client_receipt)
        and (args.phase == "after" or not (args.before_receipt or args.client_receipt))
        and bool(args.observation_receipt) == (args.phase != "after")
        and bool(args.prepare_receipt) == (args.phase != "unconfigured"), "exact observation phase receipts required")
    prep = basic.pinned_json(root / "preparation.json", args.expected_preparation_sha256)
    base.require(prep.get("schema") == "catchplate.privateManagedGoogleGatePreparation/v1"
        and prep["jobRoot"] == str(root), "managed preparation differs")
    source, binary, initializer = (Path(prep[name]) for name in ("source", "binary", "initializer"))
    sources = basic.source_inventory(source, Path(prep["sourceManifest"]), prep["sourceManifestSha256"], prep["sourceCommit"])
    base.require(base.digest(binary) == prep["binarySha256"] and base.digest(initializer) == base.INITIALIZER_SHA256
        and sources[fixture.CHECKER] == prep["clientCheckerSha256"]
        and sources[fixture.OBSERVER] == prep["mountObserverSha256"]
        and base.digest(root / "compose.json") == prep["composeSha256"], "fixture source/executables differ")
    config = curated.document(root / "compose.json")
    fixture.validate(config, source, binary, initializer, root, prep["subnet"], expected_binary_sha256=prep["binarySha256"])
    fixture_cidr = str(ipaddress.ip_network(prep["subnet"]).network_address + 2) + "/32"
    # The orchestrator cannot traverse the app-owned0700 work directory. Use
    # only the original public stdout receipt retained in its evidence tree;
    # never relax custody/work permissions or grant the host a private mount.
    receipt = None if args.phase == "unconfigured" else curated.document(args.prepare_receipt, 32768)
    manifest = fixture.expected_manifest(fixture_cidr, receipt)
    identities, observations = {}, {}
    for mode, identifier, service in (("app", args.app_container_id, "catchplate"), ("gate", args.gate_container_id, "decision-gate-rs")):
        identities[mode] = curated.inspect(identifier, service, config)
        observations[mode] = curated.command(["/usr/bin/docker", "exec", "-i", "--user", "10001:10001", identifier,
            "python", "-I", "-B", "-", mode, prep["binarySha256"], json.dumps(manifest, sort_keys=True)], probe_source())
        base.require(observations[mode].get("ok") is True, "managed runtime filesystem observation refused")
    app, gate = observations["app"], observations["gate"]
    base.require(app["leaves"] == gate["leaves"] and app["policy"] == gate["policy"]
        and app["export_directory"] == gate["export_directory"]
        and app["managed"]["identity"] == gate["managed"]["identity"] == fixture.identity(manifest)
        and app["managed"]["manifest_sha256"] == gate["managed"]["manifest_sha256"]
        and app["managed"]["manifest_metadata"] == gate["managed"]["manifest_metadata"]
        and gate["managed"]["provider_custody"] is None, "original leaves/manifest/policy/private mount relation differs")
    for mode, identifier, service in (("app", args.app_container_id, "catchplate"), ("gate", args.gate_container_id, "decision-gate-rs")):
        base.require(curated.inspect(identifier, service, config) == identities[mode], "runtime changed while observed")
    result = {"ok": True, "schema": SCHEMA, "phase": args.phase,
        "preparation_sha256": args.expected_preparation_sha256, "binary_sha256": prep["binarySha256"],
        "containers": identities, "shared_leaves": gate["leaves"], "policy": gate["policy"],
        "gate_executable": gate["actual_executable"], "export_directory": gate["export_directory"],
        "gate_mountinfo": gate["mountinfo"], "app_private_files_present": sorted(app["private_files"]),
        "gate_private_files_absent": sorted(gate["private_files"]), "source_files_verified": len(sources),
        "managed_google": gate["managed"]["identity"], "manifest_sha256": gate["managed"]["manifest_sha256"],
        "manifest_metadata": gate["managed"]["manifest_metadata"], "provider_custody": app["managed"]["provider_custody"],
        "productionReady": False, "realProviderVerified": False, "isolatedFixtureOnly": True}
    if args.phase == "after":
        result.update(verify_transition(curated.document(args.before_receipt), result, curated.document(args.client_receipt)))
        result["before_receipt_sha256"] = base.digest(args.before_receipt)
        result["client_receipt_sha256"] = base.digest(args.client_receipt)
    else:
        observation_receipt(curated.document(args.observation_receipt), manifest, result["policy"],
            1 if receipt is None else 3, prep["binarySha256"], "unconfigured" if receipt is None else "activated")
        result["readiness_receipt_sha256"] = base.digest(args.observation_receipt)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("job-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("app-container-id", "gate-container-id", "expected-preparation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("before-receipt", "client-receipt", "observation-receipt", "prepare-receipt"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--phase", choices=("unconfigured", "before", "after"), required=True)
    args = parser.parse_args()
    curated.DEADLINE = time.monotonic() + 90
    def expired(*_):
        raise TimeoutError("bounded managed observation")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(90)
    try:
        base.require(args.output.is_absolute() and args.output.parent.resolve() == args.output.parent
            and not args.output.exists(), "fresh evidence output required")
        result = run(args)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps(result, sort_keys=True))
    except Exception:
        raise SystemExit("Managed mount observation refused; no private data or raw errors emitted") from None
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
