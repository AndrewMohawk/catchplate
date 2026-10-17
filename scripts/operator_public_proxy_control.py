#!/usr/bin/env python3
"""One-shot LOCAL owner for the fixed public-proxy check; never a WAN client.

Stream into the exact reviewed app container as UID10001. The caller creates
an owned0700 /data/.public-proxy-check/public-proxy-<32hex> directory first.
No bootstrap, token renewal, provider contact, direct SQL mutation or retry.
An uncertain POST leaves its exclusive claim: inspect with status, never replay.
Private client.json is the only export; stdout contains authored public fields.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import time
import traceback
from types import SimpleNamespace

from scripts import check_operator_live_smoke as smoke
from scripts.check_operator_catalog import OperatorCatalogCheck, PREFIX, COLLECTIONS, features
from scripts.check_operator_demo import Endpoint, require, token_file


CREDENTIAL = "50124150-373d-4665-bcf2-225e9ea03a20"  # Public catalog ID, not a secret. gitleaks:allow
CREDENTIAL_NAME = "catchplate-live-smoke-757edf125b7444028059274a46ec7fd9-credential"
BINARY = "sha256:811082ac5e87f9ec05b9252cc53c180e965e563799b07235976c1654e6672d6e"
ORIGIN = "https://catchplate.example.com"
ORIGINS = ["https://demo-upstream:8443", "https://api.github.com", "https://registry.npmjs.org", "https://gmail.googleapis.com"]
ROOT = Path("/data/.public-proxy-check")
CA = Path("/data/mitmproxy/mitmproxy-ca-cert.pem")
BODY = b'{"public_proxy_smoke":true}'
DUMMY = "Bearer CATCHPLATE_PUBLIC_PROXY_DUMMY"
RESULT_FIELDS = set("schema ok mode run_id application_id credential_id rule_id policy_hash ca_sha256 peer connect_status http_status proxy_tls_verify_result response_body_sha256 response_body_bytes request_digest operation_digest".split())


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def identity(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def read(path, *, private=True, maximum=4 * 1024 * 1024):
    require(path.is_absolute() and path.resolve(strict=True) == path, "file path refused")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
                "file identity refused")
        if private:
            require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600, "private file refused")
        value = source.read(maximum + 1)
        require(len(value) <= maximum and identity(before) == identity(os.fstat(source.fileno())) == identity(path.lstat()),
                "file changed during read")
    return value


def document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, "nonfinite JSON"))


def preserve(before, after, app_id=None, rule_id=None):
    """Only the exact reused credential's derived active_rule_count may change."""
    for collection in COLLECTIONS:
        old = {row["id"]: row for row in before[collection]}
        new = {row["id"]: row for row in after[collection]}
        added = {"credentials": None, "applications": app_id, "access_rules": rule_id}[collection]
        require(len(new) == len(after[collection]) and set(new) == set(old) | ({added} if added else set()), "resource roster drift")
        for key, row in old.items():
            expected = dict(row)
            if collection == "credentials" and key == CREDENTIAL:
                delta = int(bool(rule_id) and new_rule(after, rule_id)["status"] == "active")
                expected["active_rule_count"] = row["active_rule_count"] + delta
            require(new[key] == expected, "preexisting resource changed")
    require(after["allowed_upstreams"] == before["allowed_upstreams"] == ORIGINS
            and after["proxy_url"] == before["proxy_url"] == smoke.PROXY, "deployment selection drift")


def new_rule(catalog, identifier):
    return OperatorCatalogCheck.resource(catalog, "access_rules", identifier)


class Control(smoke.LiveSmoke):
    def __init__(self, job):
        # Deliberately initialize only LOCAL endpoints. Never instantiate or
        # relax the shared fixture's public-proxy Endpoint admission.
        self.job, self.run_id, self.deadline = job, job.name, time.monotonic() + 85
        self.args = SimpleNamespace(operator_origin=ORIGIN, expected_binary_sha256=BINARY)
        self.control, self.management = Endpoint("http://127.0.0.1:3000"), Endpoint("http://decision-gate-rs:9091")
        self.upstream = Endpoint("https://demo-upstream:8443")
        self.control_ca = self.management_ca = None
        self.upstream_ca = ssl.create_default_context(cafile="/demo-upstream/ca.pem")
        self.expected_upstreams = ORIGINS
        self.admin_token = token_file(Path("/run/secrets/catchplate/admin.token"))
        self.credential = self.client_token = self.wrong_token = None
        self.issued_tokens, self.observations, self.mutations = [], [], []
        self.policy_hash = None

    def save(self, name, value):
        smoke.private_output(self.job / name, encoded(value))

    def load(self, name):
        return document(read(self.job / name))

    def loaded(self, expected=None):
        if expected is not None:
            self.policy_hash = expected["policy"]["policy_hash"]
        else:
            self.policy_hash = self.catalog()["policy"]["policy_hash"]
        result, _ = self.wait_catalog_loaded("public_proxy", expected_mutation=expected)
        while not self.drained():
            time.sleep(min(.2, self.timeout()))
        return result

    def chain(self):
        result = self.control_json("/api/audit/verify?limit=10000", authenticated=True)
        require(result.get("ok") is True and result.get("complete") is True and result.get("backend") == "sqlite", "audit chain incomplete")

    def post(self, name, before, route, payload, *, result_key, creates=False, token=False, authority_changed=False):
        require((name, route, result_key, creates, token, authority_changed) in {
            ("create-app", "/applications", "application", True, True, False),
            ("create-rule", "/access-rules", "access_rule", True, False, True),
            ("revoke-rule", "/access-rules/revoke", "access_rule", False, False, True),
            ("revoke-app", "/applications/revoke", "application", False, False, False)}, "mutation is outside closed plan")
        self.save(name + ".claim.json", {"run_id": self.run_id, "route": route,
            "payload_sha256": smoke.sha(encoded(payload)), "revision": before["revision"],
            "policy_hash": before["policy"]["policy_hash"], "replayAllowed": False})
        # Claim is fsynced BEFORE calling the real one-POST CAS helper.
        resource, issued, result = OperatorCatalogCheck.submit_mutation(self, before, route, payload,
            result_key=result_key, creates=creates, token=token, authority_changed=authority_changed)
        self.save(name + ".response.json", {"result": result, "client_token": issued})
        current = self.loaded(result)
        require(self.resource(current, "applications" if result_key == "application" else "access_rules", resource["id"])["version"] == resource["version"], "mutation readback differs")
        return resource, issued, current

    def authorization_hash(self):
        expected = {"CATCHPLATE_OPERATOR_DEMO": "1", "CATCHPLATE_RELEASE_CHANNEL": "dev",
            "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane", "CATCHPLATE_KEY_RELEASE_REQUIRED": "0",
            "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite", "CATCHPLATE_DATA_DIR": "/data"}
        require(all(os.environ.get(key) == value for key, value in expected.items())
                and not os.environ.get("CATCHPLATE_MASTER_KEY") and not os.environ.get("CATCHPLATE_MASTER_KEY_UNSEAL_COMMAND"), "existing development custody required")
        key, database = Path("/data/master.key"), Path("/data/catchplate.sqlite3")
        require(len(read(key, maximum=32)) == 32 and database.resolve(strict=True) == database
                and stat.S_ISREG(database.lstat().st_mode) and database.lstat().st_nlink == 1
                and CA.parent.resolve(strict=True) == CA.parent, "existing custody missing")
        original = identity(key.lstat())
        # A docker-exec child is a fresh process: admit the existing managed
        # Google read snapshot before config/db import, without runtime startup.
        # This borrows the existing SH lock and WAL-aware mode=ro transaction;
        # SQLite may coordinate sidecars, but no business state is initialized.
        from catchplate import operator_google_managed_config as managed
        require(managed.enabled(), "retained managed profile required")
        managed.bootstrap()
        require(managed.selected() is False, "Google must remain unconfigured")
        from catchplate import db
        core = db.get_credential(CREDENTIAL, include_secret=True)
        require(core is not None and core["id"] == CREDENTIAL and core["name"] == CREDENTIAL_NAME
                and core["credential_version"] == 1 and core["lifecycle_status"] == "active"
                and re.fullmatch(r"synthetic-operator-[A-Za-z0-9_-]{32,128}", core["secret"]), "owned synthetic material differs")
        require(identity(key.lstat()) == original, "existing custody changed")
        self.credential = core["secret"]  # Memory-only leak detector; never exported.
        return smoke.sha(("Bearer " + self.credential).encode("ascii"))

    def prepare(self, expected_hash):
        require(not (self.job / "original.json").exists(), "preparation already claimed")
        before = self.loaded()
        require(before["revision"] == 81 and before["policy"]["sequence"] == 31
                and before["policy"]["policy_hash"] == expected_hash
                and all(len(before[key]) == 20 for key in COLLECTIONS), "reviewed baseline changed")
        credential = self.resource(before, "credentials", CREDENTIAL)
        require(credential["name"] == CREDENTIAL_NAME and credential["status"] == "active"
                and credential["auth_type"] == "bearer" and credential["header_name"] == "Authorization"
                and credential["credential_generation"] == 1, "synthetic credential binding differs")
        smoke.preflight_catalog(before)
        require(before["capabilities"]["application_proxy_authentication"]["modes"] == ["bearer", "basic_and_bearer_v1"], "Basic capability unavailable")
        self.chain()
        counts = self.counts()
        require(counts[1] == 0, "run already reached upstream")
        self.save("original.json", {"run_id": self.run_id, "catalog": before, "counts": counts,
            "audit": features.audit_cutoff(self.audit()[:100]), "binary": BINARY})
        authorization_hash = self.authorization_hash()
        ca = read(CA, private=False, maximum=32768).decode("ascii")
        ssl.create_default_context(cadata=ca)  # Parse public certificate; no connection.
        smoke.require_catalog_unchanged(before, self.loaded(before), "baseline changed before create")
        app, token, current = self.post("create-app", before, "/applications", {
            "name": self.run_id + "-application", "token_lifetime_seconds": 3600,
            "proxy_authentication": "basic_and_bearer_v1"}, result_key="application", creates=True, token=True)
        require(app["proxy_authentication"] == "basic_and_bearer_v1" and app["principal_id"] == "agent:operator-demo:" + app["id"], "new app identity differs")
        preserve(before, current, app["id"])
        values = smoke.access_rule_values(self.run_id + "-rule", app["id"], CREDENTIAL)
        values["placeholder"] = DUMMY
        values["allowed_headers"] = ["accept", "accept-encoding", "user-agent"]
        rule, _, current = self.post("create-rule", current, "/access-rules", values,
            result_key="access_rule", creates=True, authority_changed=True)
        smoke.require_rule_contract(new_rule(current, rule["id"]), values)
        preserve(before, current, app["id"], rule["id"])
        require(self.counts() == counts, "unexpected upstream contact during preparation")
        config = {"schema": "catchplate.publicProxySmoke/v1", "run_id": self.run_id,
            "application_id": app["id"], "client_token": token, "credential_id": CREDENTIAL, "rule_id": rule["id"],
            "policy_hash": current["policy"]["policy_hash"], "authorization_sha256": authorization_hash,
            "ca_pem": ca, "ca_sha256": smoke.sha(ca.encode("ascii"))}
        self.save("client.json", config)
        self.save("prepared.json", {"catalog": current, "client_sha256": smoke.sha(encoded(config))})
        return {"ok": True, "phase": "prepare", "run_id": self.run_id, "application_id": app["id"], "rule_id": rule["id"], "policy_hash": config["policy_hash"]}

    def retained(self):
        original, prepared, config = self.load("original.json"), self.load("prepared.json"), self.load("client.json")
        require(original["run_id"] == config["run_id"] == self.run_id and original["binary"] == BINARY
                and smoke.sha(encoded(config)) == prepared["client_sha256"] and config["credential_id"] == CREDENTIAL, "retained input changed")
        self.client_token = config["client_token"]
        return original, prepared, config

    def status(self, result_path=None):
        if not (self.job / "prepared.json").exists():
            current = self.catalog()
            return {"ok": False, "phase": "status", "state": "incomplete_no_replay", "run_id": self.run_id,
                "owned_rows": [{"collection": key, "id": row["id"], "status": row["status"]}
                    for key in COLLECTIONS for row in current[key] if row.get("name") in {self.run_id + "-application", self.run_id + "-rule"}]}
        original, prepared, config = self.retained()
        expected = self.load("revoked.json")["catalog"] if (self.job / "revoked.json").exists() else prepared["catalog"]
        current = self.loaded(expected)
        smoke.require_catalog_unchanged(expected, current, "owned catalog drift")
        preserve(original["catalog"], current, config["application_id"], config["rule_id"])
        counts = self.counts()
        require(counts[0] - original["counts"][0] == counts[1] and counts[1] in {0, 1}, "upstream contact budget differs")
        events = self.audit()
        cutoff = features.audit_cutoff(events[:100]) if len(events) < 100 else {row["id"]: row["event_hash"] for row in events}
        require(all(cutoff.get(key) == value for key, value in original["audit"].items()), "audit cutoff lost")
        self.chain()
        proof = None
        if result_path is not None:
            require(result_path in {self.job / "positive-result.json", self.job / "revoked-result.json"}, "client result path refused")
            client = document(read(result_path))
            require(client.get("mode") == result_path.name.removesuffix("-result.json")
                    and (client["mode"] != "revoked" or (self.job / "revoked.json").exists()), "client phase differs")
            proof = join_result(config, client, events, counts[1])
        return {"ok": True, "phase": "status", "run_id": self.run_id, "upstream_dispatches": counts[1],
                "audit_chain_verified": True, "old_resources_preserved": True, "audit_proof": proof}

    def revoke(self):
        original, prepared, config = self.retained()
        self.save("revoke.claim.json", {"run_id": self.run_id, "replayAllowed": False})
        current = self.loaded(prepared["catalog"])
        smoke.require_catalog_unchanged(prepared["catalog"], current, "catalog changed before revocation")
        for label, route, kind, identifier in (("revoke-rule", "/access-rules/revoke", "access_rule", config["rule_id"]),
                                              ("revoke-app", "/applications/revoke", "application", config["application_id"])):
            resource, _, current = self.post(label, current, route, {"id": identifier}, result_key=kind, authority_changed=kind == "access_rule")
            require(resource["id"] == identifier and resource["status"] == "revoked", "revocation readback differs")
            preserve(original["catalog"], current, config["application_id"], config["rule_id"])
        self.chain()
        self.save("revoked.json", {"catalog": current})
        return {"ok": True, "phase": "revoke", "run_id": self.run_id, "owned_resources_revoked": 2, "credential_unchanged": True}


def join_result(config, result, events, arrivals):
    require(type(result) is dict and set(result) == RESULT_FIELDS and result["schema"] == "catchplate.publicProxySmokeResult/v1"
            and result["ok"] is True and result["peer"] == "203.0.113.10" and result["proxy_tls_verify_result"] == 0
            and all(result[key] == config[key] for key in ("run_id", "application_id", "credential_id", "rule_id", "policy_hash", "ca_sha256")), "client evidence differs")
    if result["mode"] == "revoked":
        require(result["connect_status"] == 403 and result["http_status"] == 0 and arrivals == 1
                and all(result[key] is None for key in ("request_digest", "operation_digest", "response_body_sha256", "response_body_bytes")), "revoked response differs")
        return {"connect_status": 403, "upstream_dispatches": 1}
    require(result["mode"] == "positive" and result["connect_status"] == result["http_status"] == 200 and arrivals == 1
            and all(type(result[key]) is str and smoke.SHA256.fullmatch(result[key]) for key in ("request_digest", "operation_digest", "response_body_sha256"))
            and type(result["response_body_bytes"]) is int and 0 < result["response_body_bytes"] <= 65536, "positive response differs")
    scope = {"principal_id": "agent:operator-demo:" + config["application_id"], "route_id": "operator." + config["rule_id"], "policy_hash": config["policy_hash"]}
    selected = [row for row in events if all(row.get("event", {}).get(key) == value for key, value in scope.items())]
    pair = {kind: [row for row in selected if row["event_type"] == kind] for kind in (smoke.START, smoke.RELEASE, smoke.BLOCK)}
    require(len(pair[smoke.START]) == len(pair[smoke.RELEASE]) == 1 and not pair[smoke.BLOCK], "durable response pair missing")
    start, release = pair[smoke.START][0], pair[smoke.RELEASE][0]
    for row in (start, release):
        event = row["event"]
        require(event["method"] == "POST" and event["body_sha256"] == smoke.sha(BODY)
                and event.get("credential_ref") == CREDENTIAL and type(event.get("credential_version")) is int and event["credential_version"] == 1
                and all(event[key] == result[key] for key in ("request_digest", "operation_digest"))
                and smoke.SHA256.fullmatch(event["attempt_id"]) and event["flow_id"] == event["attempt_id"], "audit commitment mismatch")
    terminal = release["event"]
    require(start["event"]["attempt_id"] == terminal["attempt_id"] and start["event"]["outcome"] == "release_started"
            and terminal["outcome"] == "released" and terminal["upstream_status"] == 200
            and terminal["response_body_sha256"] == result["response_body_sha256"] and terminal["response_body_bytes"] == result["response_body_bytes"]
            and terminal["response_validation"]["ok"] is True and terminal["response_validation"]["mode"] == smoke.RESPONSE_VALIDATION_MODE
            and terminal["response_validation"]["body_bytes_preserved"] is True, "audit terminal mismatch")
    leases = [row for row in selected if features.issued_lease(row, {**scope, "purpose": "dispatchSecret", "credential_id": CREDENTIAL,
        "expected_credential_version": 1, "outcome": "issued", "status_code": 200, "data_plane_binary_digest": BINARY})]
    require(len(leases) == 1, "credential lease binding differs")
    return {"attempt_id": terminal["attempt_id"], "event_ids": [start["id"], release["id"], leases[0]["id"]]}


def failure(phase, error):
    """Code locations only: never exception messages, source text or locals."""
    return {"ok": False, "phase": phase, "error": "controller_refused_or_incomplete_no_post_replay",
        "error_type": type(error).__name__, "frames": [
            {"file": Path(frame.filename).name, "function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__, limit=-8)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "status", "revoke"))
    parser.add_argument("--job-dir", required=True, type=Path)
    parser.add_argument("--expected-policy-hash")
    parser.add_argument("--client-result", type=Path)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        require(args.job_dir.parent == ROOT and re.fullmatch(r"public-proxy-[0-9a-f]{32}", args.job_dir.name)
                and args.job_dir.resolve(strict=True) == args.job_dir, "exact private job path required")
        for folder in (ROOT, args.job_dir):
            info = folder.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() == 10001 and stat.S_IMODE(info.st_mode) == 0o700, "job ownership refused")
        require((args.phase == "prepare") == (args.expected_policy_hash is not None)
                and (args.client_result is None or args.phase == "status"), "phase arguments refused")
        if args.expected_policy_hash is not None:
            require(smoke.SHA256.fullmatch(args.expected_policy_hash), "policy hash refused")
        def expired(*_):
            raise TimeoutError("controller deadline exceeded")
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 90)
        flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if args.phase == "prepare" else 0)
        with os.fdopen(os.open(args.job_dir / ".lock", flags, 0o600), "r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner = Control(args.job_dir)
            result = owner.prepare(args.expected_policy_hash) if args.phase == "prepare" else owner.status(args.client_result) if args.phase == "status" else owner.revoke()
    except Exception as error:
        result = failure(args.phase, error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
