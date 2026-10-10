#!/usr/bin/env python3
"""Dormant three-service rehearsal for an explicitly copied retained demo.

--write creates only public recipe files in an empty private job. Root then
extracts the pinned stopped archives into runtime/ and notification-custody/
and creates provider-custody/. --preflight recovers a further disposable SQLite
copy, never the mounted database. No initialization, Docker or Git execution.
Root captures working-tree identity before startup and after each cold stop;
archive/clone inode numbers must never substitute for those live-copy receipts.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import tempfile

from scripts import prepare_operator_catalog_fixture as base
from scripts import prepare_operator_proxy_basic_fixture as basic
from scripts import operator_rollout_snapshot as snapshots

CHECKER = "scripts/check_operator_managed_retained_fixture.py"
PREPARER = "scripts/prepare_operator_managed_retained_fixture.py"
ADDRESSES = ("172.16.249.18", "172.16.249.19", "172.16.249.20")
HOSTS = ("127.0.0.1 localhost\n172.16.249.18 demo-upstream\n"
         "172.16.249.19 serverware\n172.16.249.20 decision-gate-rs\n").encode("ascii")
RESOLV = b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"
KEEPER_SECONDS = 600
LEAVES = (".operator-publication.lock", ".serverware-operator-demo.json",
          "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")
SETTINGS = {"allowed_upstreams": ["https://demo-upstream:8443"], "fixture_cidrs": [ADDRESSES[0] + "/32"]}


def manifest():
    return {"schema": "serverware.operatorGoogleGateConfiguration/v1", "operation": None,
        "profile_binding": None, "profile_binding_digest": None, "effective_settings": SETTINGS,
        "effective_settings_digest": "sha256:" + snapshots.digest(SETTINGS)}


def job_path(root):
    base.require(root.is_absolute() and root.parent == base.SCRATCH and re.fullmatch(
        r"serverware-managed-retained-private\.[A-Za-z0-9]{6,32}", root.name), "private rehearsal job required")


def build(source, binary, root, *, expected_binary_sha256):
    job_path(root)
    template = root.with_name("serverware-catalog-private." + root.name.split(".", 1)[1])
    # The inherited initializer is discarded before the recipe is returned.
    # No initializer file, token creation or synthetic state is used here.
    config = base.build(source, binary, source / PREPARER, template, "172.16.249.16/28",
        expected_binary_sha256=expected_binary_sha256)
    config.pop("networks")
    config["name"] = "serverware-managed-retained-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services = config["services"]
    services.pop("initialize")
    common = services.pop("demo-upstream")
    for key in ("command", "environment", "volumes", "healthcheck", "depends_on", "networks", "dns"):
        common.pop(key, None)
    hosts = [base.bind(root / "hosts", "/etc/hosts"), base.bind(root / "resolv.conf", "/etc/resolv.conf")]
    for service in services.values():
        service.pop("networks"); service.pop("dns")
        service["network_mode"] = "service:network"
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
        service["volumes"].extend(deepcopy(hosts))
        service["environment"]["SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED"] = "1"
        service["environment"]["SERVERWARE_OPERATOR_DEMO_PROXY_URL"] = "https://serverware-proxy.example.com:443"
    app = services["serverware"]
    app["depends_on"] = {"network": {"condition": "service_healthy"}}
    app["environment"].update({
        "SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED": "1",
        "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR": "/provider-custody",
        "SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED": "1",
        "SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR": "/notification-custody",
        "SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON": '{"bindings":[]}',
        "SERVERWARE_PROCESS_MODE": "serverware-control-plane", "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite", "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0", "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_DEV_AUTHENTICATOR": "0", "SERVERWARE_DEV_DEMO_SEED": "0"})
    app["volumes"] = [row for row in app["volumes"] if row["target"] != "/private-audit-fixture.json"]
    app["volumes"].extend([base.bind(root / "provider-custody", "/provider-custody", False),
        base.bind(root / "notification-custody", "/notification-custody", False)])
    gate = services["decision-gate-rs"]
    gate["environment"]["SERVERWARE_DATA_PLANE_AUDIT_BATCH_MAX"] = "1"
    gate["environment"].pop("SERVERWARE_DATA_PLANE_AUDIT_QUEUE_MAX")
    gate["environment"].pop("SERVERWARE_DATA_PLANE_AUDIT_FLUSH_MS")
    for mount in gate["volumes"]:
        if mount["target"] == "/data":
            mount["source"] = str(root / "runtime/app-data/gate-runtime")
    gate["volumes"].extend(base.bind(root / "runtime/app-data" / name, "/data/" + name) for name in LEAVES)
    services["network"] = {**common, "image": base.GATE_IMAGE, "user": "0:0", "init": False, "network_mode": "none",
        "cap_add": ["NET_ADMIN", "SETUID", "SETGID"], "cpus": 0.25, "pids_limit": 16,
        "environment": {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"},
        "command": ["python", "-B", "-m", "scripts.check_operator_managed_retained_fixture", "network"],
        "sysctls": {"net.ipv4.ip_nonlocal_bind": "0"},
        "volumes": [base.bind(source, "/app"), *hosts],
        "healthcheck": {"test": ["CMD", "python", "-c", "import os,stat; "
            "os.setgroups([]); os.setgid(10001); os.setuid(10001); "
            "s=os.stat('/tmp/retained-network-ready',follow_symlinks=False); "
            "raise SystemExit(0 if stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o400 "
            "and s.st_uid==s.st_gid==10001 and s.st_nlink==1 and s.st_size==1 else 1)"],
            "interval": "2s", "timeout": "3s", "retries": 10, "start_period": "3s"}}
    return config


def preflight(root, historical):
    """Stopped PRIVATE copy only. Read no live DB and emit no row contents."""
    observed = snapshots.inventory(root / "runtime", root / "notification-custody",
        managed_unconfigured=True, provider_custody_root=root / "provider-custody")
    base.require(historical.get("schema") == snapshots.SCHEMA and historical.get("live_sqlite_opened") is False,
        "historical inventory contract differs")
    for area in ("persistent", "custody"):
        base.require({name: snapshots.content(row) for name, row in observed[area].items()} ==
            {name: snapshots.content(row) for name, row in historical[area].items()}, "archive copy content differs")
    base.require(not snapshots.gate_members(observed) and set(observed["custody"]) == {"."},
        "rehearsal must start unconfigured without a gate export")
    with tempfile.TemporaryDirectory(prefix="retained-preflight-", dir=root) as temporary:
        connection = snapshots.private_database(root / "runtime", observed, Path(temporary))
        try:
            connection.create_function("regexp", 2, lambda pattern, value: None if value is None else
                int(isinstance(value, str) and isinstance(pattern, str) and re.fullmatch(pattern, value) is not None), deterministic=True)
            connection.execute("PRAGMA query_only=ON"); connection.execute("BEGIN")
            base.require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "copied SQLite integrity refused")
            rows = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name LIMIT 4097").fetchall()
            base.require(0 < len(rows) <= 4096, "schema bound")
            base.require(not any(str(row[1]).lower().startswith("operator_notification_") or
                str(row[2]).lower().startswith("operator_notification_") for row in rows), "retained notification schema refused")
            base.require(connection.execute("SELECT 1 FROM audit_events WHERE event_type LIKE 'notification.%' "
                "OR event_type LIKE 'operator_notification%' OR event_type LIKE 'operator.notification%' LIMIT 1").fetchone() is None,
                "notification history refused")
            managed = snapshots.managed_database_identity(connection, observed)
            settings = connection.execute("SELECT settings_json FROM operator_demo_settings WHERE singleton=1").fetchone()
            base.require(settings is not None and json.loads(settings[0]) == SETTINGS, "retained origin settings differ")
            result = {"ok": True, "schema": "serverware.managedRetainedPreflight/v1",
                "schema_object_count": len(rows), "schema_sha256": snapshots.digest(rows),
                "historical_content_bound": True, "notification_schema_absent": True,
                "notification_custody_empty": True, "provider_custody_empty": True,
                "google_state_empty": True, "effective_settings_digest": manifest()["effective_settings_digest"],
                "managed_identity": managed,
                "original_database_opened": False, "private_copies_only": True}
        finally:
            connection.close()
    base.require(snapshots.inventory(root / "runtime", root / "notification-custody",
        managed_unconfigured=True, provider_custody_root=root / "provider-custody") == observed, "copied state changed during preflight")
    return result


def prepare(args):
    job_path(args.job_root)
    base.require(args.job_root.resolve() == args.job_root and args.job_root.is_dir()
        and stat.S_IMODE(args.job_root.stat().st_mode) == 0o700, "owned private job required")
    source_files = basic.source_inventory(args.source, args.source_manifest,
        args.expected_source_manifest_sha256, args.expected_source_commit)
    base.require({CHECKER, PREPARER, "scripts/operator_rollout_snapshot.py"} <= source_files.keys(), "rehearsal sources absent")
    base.require(args.binary.is_absolute() and args.binary.resolve() == args.binary
        and args.binary.is_file() and args.binary.stat().st_nlink == 1 and args.binary.stat().st_mode & 4
        and base.digest(args.binary) == args.expected_binary_sha256, "normal binary pin differs")
    historical = basic.pinned_json(args.retained_inventory, args.expected_retained_inventory_sha256)
    config = build(args.source, args.binary, args.job_root, expected_binary_sha256=args.expected_binary_sha256)
    raw = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "serverware.managedRetainedPreparation/v1", "project": config["name"],
        "job_root": str(args.job_root), "source": str(args.source), "source_commit": args.expected_source_commit,
        "source_manifest_sha256": args.expected_source_manifest_sha256, "source_files": len(source_files),
        "binary_sha256": args.expected_binary_sha256, "compose_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "historical_inventory_sha256": args.expected_retained_inventory_sha256,
        "managed_manifest": manifest(), "network": "none", "keeper_seconds": KEEPER_SECONDS,
        "automatic_execution": False, "initializer": False, "provider_service": False, "notifications_enabled": True,
        "cold_phases": ["first", "retained"], "root_preflight_and_cleanup_required": True}
    outputs = {"compose.json": raw.encode(), "preparation.json": (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
        "hosts": HOSTS, "resolv.conf": RESOLV}
    if args.write:
        base.require(args.job_root.stat().st_uid == os.geteuid() and not list(args.job_root.iterdir()),
            "owned empty job required before public recipe creation")
        for name, content in outputs.items():
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o444 if name in {"hosts", "resolv.conf"} else 0o600)
    elif args.verify_prepared or args.preflight:
        for name, content in outputs.items():
            path = args.job_root / name
            base.require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1
                and path.stat().st_size == len(content)
                and stat.S_IMODE(path.stat().st_mode) == (0o444 if name in {"hosts", "resolv.conf"} else 0o600)
                and path.read_bytes() == content, "prepared recipe changed")
    if args.preflight:
        base.require(args.private_copies_acknowledged, "explicit stopped-private-copy acknowledgement required")
        return preflight(args.job_root, historical)
    return {"ok": True, **receipt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-manifest", "binary", "job-root", "retained-inventory"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-source-manifest-sha256", "expected-binary-sha256", "expected-retained-inventory-sha256"):
        parser.add_argument("--" + name, type=base.validated_binary_sha256, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    phases = parser.add_mutually_exclusive_group()
    for name in ("write", "preflight", "verify-prepared"):
        phases.add_argument("--" + name, action="store_true")
    parser.add_argument("--private-copies-acknowledged", action="store_true")
    signal.alarm(120); os.umask(0o077)
    try:
        print(json.dumps(prepare(parser.parse_args()), sort_keys=True))
    except Exception:
        raise SystemExit("Managed retained rehearsal preparation refused; no private values emitted") from None
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
