#!/usr/bin/env python3
"""Prepare only: isolated managed Google app/gate plus ordinary Basic clients.

The existing initializer and TLS setup are unchanged. Root separately creates
the two app-role-only 0700 UID/GID10001 directories outside runtime/app-data,
verifies isolation, executes each phase once, and tears down on every exit.
No Docker, provider, live configuration or secret operation occurs here.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import uuid

from scripts import prepare_operator_curated_gate_fixture as curated

base, basic = curated.base, curated.basic
PREPARER = "scripts/prepare_operator_managed_google_gate_fixture.py"
PREPARE = "scripts/operator_managed_google_gate_prepare.py"
CHECKER = "scripts/check_operator_managed_google_gate.py"
OBSERVER = "scripts/check_operator_managed_google_gate_mounts.py"
CLIENT_ID = "123-managed-gate-fixture.apps.googleusercontent.com"
GMAIL = "https://gmail.googleapis.com"


def canonical_digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def public_profile():
    """Independent, fixed synthetic profile oracle; imports no application code."""
    return {"schema": "serverware.operatorGoogleProfile/v1", "profile": "operator-google-v1",
        "provider_id": "google", "client_id": CLIENT_ID,
        "redirect_uri": base.ORIGIN + "/api/oauth/callback/google", "permission_preset": "gmail_readonly",
        "scopes": ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"], "api_origins": [GMAIL],
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token", "revocation_url": "https://oauth2.googleapis.com/revoke",
        "identity_url": "https://openidconnect.googleapis.com/v1/userinfo"}


def expected_manifest(fixture_cidr, receipt=None):
    network = ipaddress.ip_network(fixture_cidr, strict=True)
    base.require(network.version == 4 and network.prefixlen == 32 and network.network_address.is_private
        and not network.network_address.is_loopback and not network.network_address.is_link_local,
        "exact private fixture receiver required")
    old = {"allowed_upstreams": ["https://demo-upstream:8443"], "fixture_cidrs": [fixture_cidr]}
    target = {**old, "allowed_upstreams": [*old["allowed_upstreams"], GMAIL]}
    operation, profile = None, None
    if receipt is not None:
        base.require(type(receipt) is dict and set(receipt) == {"ok", "schema", "syntheticOnly",
            "readOnlyRecovery", "operation", "providerCalls"} and receipt["ok"] is True
            and receipt["syntheticOnly"] is True and receipt["readOnlyRecovery"] is False
            and type(receipt["providerCalls"]) is int and receipt["providerCalls"] == 0
            and receipt["schema"] == "serverware.managedGoogleFixturePrepare/v1", "original synthetic Prepare receipt required")
        item = receipt["operation"]
        keys = {"schema", "operation_id", "client_id", "old_settings", "target_settings", "expected_settings_digest",
            "public_url", "redirect_uri", "profile_binding", "profile_binding_digest", "reviewed_revision",
            "staged_revision", "policy_hash", "created_at", "setup_contract", "custody_ref", "secret_present",
            "status", "revision", "completed_at", "activation_receipt"}
        base.require(type(item) is dict and set(item) == keys and item["schema"] == "serverware.operatorGoogleManagedSetup/v2"
            and item["setup_contract"] == "serverware.operatorGoogleManagedSetupBinding/v2"
            and item["old_settings"] == old and item["target_settings"] == target
            and item["expected_settings_digest"] == canonical_digest(old)
            and item["client_id"] == CLIENT_ID and item["public_url"] == base.ORIGIN
            and item["profile_binding"] == public_profile() and item["redirect_uri"] == public_profile()["redirect_uri"]
            and item["profile_binding_digest"] == canonical_digest(public_profile())
            and item["secret_present"] is True and item["status"] == "pending"
            and type(item["reviewed_revision"]) is int and item["reviewed_revision"] == 1
            and type(item["staged_revision"]) is int and item["staged_revision"] == 2
            and type(item["revision"]) is int and item["revision"] == 2
            and item["completed_at"] is None and item["activation_receipt"] is None
            and isinstance(item["policy_hash"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item["policy_hash"])
            and isinstance(item["created_at"], str) and 1 <= len(item["created_at"]) <= 64,
            "synthetic pending binding differs")
        reference = item["custody_ref"]
        base.require(type(reference) is dict and set(reference) == {"owner_id", "config_version", "key_source"}
            and reference["key_source"] == "operator-provider-key-v1"
            and type(reference["config_version"]) is int and reference["config_version"] == 1,
            "synthetic custody reference differs")
        for identifier in (item["operation_id"], reference["owner_id"]):
            base.require(type(identifier) is str and str(uuid.UUID(identifier)) == identifier, "canonical fixture UUID required")
        operation = {"operation_id": item["operation_id"], "owner_id": reference["owner_id"], "config_version": 1}
        profile = public_profile()
    settings = old if receipt is None else target
    return {"schema": "serverware.operatorGoogleGateConfiguration/v1", "operation": operation,
        "profile_binding": profile, "profile_binding_digest": None if profile is None else canonical_digest(profile),
        "effective_settings": settings, "effective_settings_digest": canonical_digest(settings)}


def identity(manifest):
    return {key: manifest[key] for key in ("operation", "profile_binding_digest", "effective_settings_digest")}


def build(source, binary, initializer, root, subnet, *, expected_binary_sha256):
    base.require(root.parent == base.SCRATCH and re.fullmatch(
        r"serverware-managed-google-gate-private\.[A-Za-z0-9]{6,32}", root.name), "fresh managed fixture root required")
    template = root.with_name("serverware-curated-gate-private." + root.name.split(".", 1)[1])
    config = curated.build(source, binary, initializer, template, subnet,
        expected_binary_sha256=expected_binary_sha256)
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
    config["name"] = "serverware-managed-google-gate-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services = config["services"]
    app = services["serverware"]
    app["environment"].update({
        "SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1",
        "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR": "/provider-custody",
        "SERVERWARE_PROCESS_MODE": "serverware-control-plane", "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite", "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0", "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_DEV_AUTHENTICATOR": "0", "SERVERWARE_DEV_DEMO_SEED": "0"})
    app["volumes"].append(base.bind(root / "provider-custody", "/provider-custody", False))
    services["decision-gate-rs"]["environment"]["SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED"] = "1"

    prepare = deepcopy(app)
    for key in ("networks", "dns", "healthcheck", "depends_on", "command"):
        prepare.pop(key, None)
    prepare.update(profiles=["managed-prepare"], network_mode="none", cpus=1,
        entrypoint=["python", "-B"], command=["/app/" + PREPARE])
    prepare["volumes"].append(base.bind(root / "managed-work", "/managed-work", False))
    services["managed-prepare"] = prepare

    check = services["check"]
    check["command"][0] = "/app/" + CHECKER
    check["command"].extend(["--fixture-cidr", str(ipaddress.ip_network(subnet).network_address + 2) + "/32",
        "--prepare-receipt-file", "/managed-work/prepare-result.json", "--phase", "clients"])
    check["volumes"].append(base.bind(root / "managed-work", "/managed-work"))
    for phase in ("unconfigured", "activated"):
        inspect = deepcopy(check)
        inspect["profiles"] = ["managed-" + phase]
        inspect["command"][-1] = phase
        services["managed-" + phase] = inspect
    return config


def validate(config, source, binary, initializer, root, subnet, *, expected_binary_sha256):
    base.require(config == build(source, binary, initializer, root, subnet,
        expected_binary_sha256=expected_binary_sha256), "managed fixture recipe differs")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.subnet,
        expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    sources = basic.source_inventory(args.source, args.source_manifest, args.expected_source_manifest_sha256,
        args.expected_source_commit)
    base.require({PREPARER, PREPARE, CHECKER, OBSERVER, "serverware/operator_google_managed_config.py",
        "serverware/operator_google_gate_configuration.py", "serverware/operator_google_managed_readiness.py"}
        <= sources.keys(), "managed fixture source missing")
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.initializer, base.INITIALIZER_SHA256)):
        base.require(path.resolve() == path and path.is_file() and not path.is_symlink()
            and base.digest(path) == expected, "actual executable or unchanged initializer differs")
    basic.dependency_inventory()
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "serverware.privateManagedGoogleGatePreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifest": str(args.source_manifest), "sourceManifestSha256": args.expected_source_manifest_sha256,
        "sourceFiles": len(sources), "binary": str(args.binary), "binarySha256": args.expected_binary_sha256,
        "initializer": str(args.initializer), "initializerSha256": base.INITIALIZER_SHA256,
        "subnet": args.subnet, "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "clientChecker": CHECKER, "clientCheckerSha256": sources[CHECKER],
        "mountObserver": OBSERVER, "mountObserverSha256": sources[OBSERVER],
        "clientImage": basic.CLIENT_IMAGE, "clientDependencyManifestSha256": basic.DEPENDENCY_MANIFEST_SHA256,
        "rootCreateBeforeApp": [{"path": str(args.job_root / name), "uid": 10001, "gid": 10001,
            "mode": "0700", "empty": True} for name in ("provider-custody", "managed-work")],
        "phaseOrder": ["initialize", "root-create-app-only-directories", "start-upstream-and-app-only",
            "wait-app-healthy-and-export-tree", "basic-pki", "start-gate", "managed-unconfigured-read-only",
            "managed-unconfigured-actual-mount-observation",
            "root-stop-app-and-gate", "managed-prepare-network-none-once", "start-app-first-and-wait-healthy",
            "start-gate-second-and-wait-healthy", "managed-activated-read-only", "managed-mount-observation-before",
            "edge-startup", "check-stock-basic-bearer-and-policy-reloads", "managed-mount-observation-after", "root-teardown"],
        "uncertainPrepareRecovery": "Never repeat Prepare. Retain managed-work claim; same service command with --status-only performs SH-only exact UUID/actor lookup.",
        "rootPreflightRequired": ["capacity", "cached-images", "subnet-conflicts", "actual-container-isolation",
            "source-binary-client-provenance", "original-publication-lock-shared",
            "gate-has-no-provider-directory-key-SQLite-or-client-secret", "app-and-gate-stopped-before-one-shot"],
        "automaticExecution": False, "launched": False, "productionReady": False, "realProviderVerified": False}
    if args.write:
        base.fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, value in (("compose.json", compose), ("preparation.json", json.dumps(receipt, indent=2, sort_keys=True) + "\n")):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
    return {"preparation": receipt, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-manifest", "binary", "initializer", "job-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-source-manifest-sha256", "expected-binary-sha256"):
        parser.add_argument("--" + name, type=base.validated_binary_sha256, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except Exception:
        raise SystemExit("Managed fixture preparation refused; no input details emitted") from None


if __name__ == "__main__":
    main()
