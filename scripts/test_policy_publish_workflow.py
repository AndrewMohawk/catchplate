#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def candidate_bundle(policy_bundle: Any, sequence: int) -> dict[str, Any]:
    bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
    bundle["metadata"]["sequence"] = sequence
    return bundle


def principal_fixture_bundle(
    policy_bundle: Any,
    principals: list[dict[str, Any]],
) -> dict[str, Any]:
    bundle = candidate_bundle(policy_bundle, 1)
    principal_ids = [principal["id"] for principal in principals]
    bundle["principals"] = principals
    for route in bundle["routes"]:
        route["principals"] = list(principal_ids)
    return bundle


def verify_principal_identity_cardinality(policy_bundle: Any) -> None:
    class DuplicateCaseHeaders:
        def multi_items(self) -> list[tuple[str, str]]:
            return [
                ("X-Serverware-Agent", "demo-agent"),
                ("x-serverware-agent", "demo-agent"),
            ]

    reordered = candidate_bundle(policy_bundle, 1)
    policy_bundle.compile_policy_bundle(candidate_bundle(policy_bundle, 1))
    reordered["principals"] = list(reversed(reordered["principals"]))
    reordered_snapshot = policy_bundle.compile_policy_bundle(reordered)
    identified = reordered_snapshot.identify_principal(
        "127.0.0.1",
        {"X-Serverware-Agent": "demo-agent"},
    )
    if identified is None or identified.id != "agent:demo":
        raise AssertionError(
            "principal identification changed when selector order changed"
        )
    if (
        reordered_snapshot.identify_principal(
            "127.0.0.1",
            {"X-Serverware-Agent": "no-match"},
        )
        is not None
    ):
        raise AssertionError("zero-match principal fixture did not deny")
    if (
        reordered_snapshot.identify_principal(
            "127.0.0.1",
            DuplicateCaseHeaders(),
        )
        is not None
    ):
        raise AssertionError(
            "case-variant duplicate identity headers did not deny"
        )
    if (
        reordered_snapshot.identify_principal(
            "127.0.0.1",
            {"X-Serverware-Agent": "demo-agent"},
            {"verified": True, "unexpected": "evidence"},
        )
        is not None
    ):
        raise AssertionError("open mTLS evidence structure did not deny")

    ambiguous_principals = [
        policy_bundle.PrincipalPolicy(
            id="runtime-ambiguous-a",
            source_cidrs=("127.0.0.0/8",),
        ),
        policy_bundle.PrincipalPolicy(
            id="runtime-ambiguous-b",
            source_cidrs=("127.0.0.0/8",),
        ),
    ]
    for ordered in (
        ambiguous_principals,
        list(reversed(ambiguous_principals)),
    ):
        ambiguous_snapshot = policy_bundle.PolicySnapshot(
            raw={},
            hash="sha256:" + "0" * 64,
            principals={principal.id: principal for principal in ordered},
            credentials={},
            routes=(),
        )
        if ambiguous_snapshot.identify_principal("127.0.0.1", {}) is not None:
            raise AssertionError(
                "multi-match principal fixture selected an order-dependent identity"
            )

    token_digest = "sha256:" + hashlib.sha256(b"overlap-token").hexdigest()
    overlap_fixtures = {
        "network": [
            {"id": "network-a", "sourceCidrs": ["10.0.0.0/8"]},
            {"id": "network-b", "sourceCidrs": ["10.1.0.0/16"]},
        ],
        "header": [
            {
                "id": "header-a",
                "sourceCidrs": ["10.0.0.0/8"],
                "requiredHeaders": {"X-Agent-Class": "shared"},
            },
            {
                "id": "header-b",
                "sourceCidrs": ["10.1.0.0/16"],
                "requiredHeaders": {"x-agent-class": "shared"},
            },
        ],
        "token": [
            {
                "id": "token-a",
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenSha256": token_digest,
                    "sourceCidrs": ["127.0.0.0/8"],
                },
            },
            {
                "id": "token-b",
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenSha256": token_digest,
                    "sourceCidrs": ["127.0.0.0/8"],
                },
            },
        ],
        "mtls": [
            {
                "id": "mtls-a",
                "mtls": {
                    "verifiedByTrustedIngress": True,
                    "certificateSha256": "sha256:" + "a" * 64,
                },
            },
            {
                "id": "mtls-b",
                "mtls": {
                    "verifiedByTrustedIngress": True,
                    "certificateSha256": "sha256:" + "a" * 64,
                },
            },
        ],
        "mixed-token-mtls-cidr": [
            {
                "id": "mixed-a",
                "sourceCidrs": ["10.0.0.0/8"],
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenSha256": token_digest,
                    "sourceCidrs": ["10.0.0.0/8"],
                },
                "mtls": {
                    "verifiedByTrustedIngress": True,
                    "sanSpiffeIds": ["spiffe://example.test/workload"],
                },
            },
            {
                "id": "mixed-b",
                "sourceCidrs": ["10.1.0.0/16"],
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenSha256": token_digest,
                    "sourceCidrs": ["10.1.0.0/16"],
                },
                "mtls": {
                    "verifiedByTrustedIngress": True,
                    "sanSpiffeIds": ["spiffe://example.test/workload"],
                },
            },
        ],
    }
    for label, principals in overlap_fixtures.items():
        detail = expect_policy_error(
            f"{label} principal overlap",
            lambda principals=principals: policy_bundle.compile_policy_bundle(
                principal_fixture_bundle(policy_bundle, principals)
            ),
            "identity selector sets overlap",
        )
        if any(principal["id"] in detail for principal in principals):
            raise AssertionError(
                f"{label} principal overlap leaked selector identity details"
            )

    disjoint_mixed = [
        {
            "id": "mixed-disjoint-a",
            "sourceCidrs": ["10.0.0.0/16"],
            "proxyAuthorization": {
                "scheme": "Bearer",
                "tokenSha256": token_digest,
                "sourceCidrs": ["10.0.0.0/16"],
            },
            "mtls": {
                "verifiedByTrustedIngress": True,
                "sanSpiffeIds": ["spiffe://example.test/workload"],
            },
        },
        {
            "id": "mixed-disjoint-b",
            "sourceCidrs": ["10.1.0.0/16"],
            "proxyAuthorization": {
                "scheme": "Bearer",
                "tokenSha256": token_digest,
                "sourceCidrs": ["10.1.0.0/16"],
            },
            "mtls": {
                "verifiedByTrustedIngress": True,
                "sanSpiffeIds": ["spiffe://example.test/workload"],
            },
        },
    ]
    policy_bundle.compile_policy_bundle(
        principal_fixture_bundle(policy_bundle, disjoint_mixed)
    )

    mtls_principals = [
        {
            "id": "mtls-runtime",
            "mtls": {
                "verifiedByTrustedIngress": True,
                "sanSpiffeIds": ["spiffe://example.test/runtime"],
            },
        }
    ]
    mtls_snapshot = policy_bundle.compile_policy_bundle(
        principal_fixture_bundle(policy_bundle, mtls_principals)
    )
    if (
        mtls_snapshot.identify_principal(
            None,
            {},
            {
                "verified": True,
                "san_spiffe_ids": ["spiffe://example.test/runtime"],
            },
        )
        is None
    ):
        raise AssertionError("closed valid mTLS evidence did not identify principal")
    for malformed in (
        {"verified": 1, "san_spiffe_ids": ["spiffe://example.test/runtime"]},
        {"verified": True, "san_spiffe_ids": ["not-spiffe"]},
        {
            "verified": True,
            "san_spiffe_ids": ["spiffe://example.test/runtime"],
            "certificate_sha256": None,
        },
        {
            "verified": True,
            "certificate_sha256": "SHA256:" + "a" * 64,
        },
    ):
        if mtls_snapshot.identify_principal(None, {}, malformed) is not None:
            raise AssertionError("malformed mTLS evidence matched a principal")

    expect_policy_error(
        "multi-SAN principal overlap",
        lambda: policy_bundle.compile_policy_bundle(
            principal_fixture_bundle(
                policy_bundle,
                [
                    {
                        "id": "san-a",
                        "mtls": {
                            "verifiedByTrustedIngress": True,
                            "sanSpiffeIds": ["spiffe://example.test/a"],
                        },
                    },
                    {
                        "id": "san-b",
                        "mtls": {
                            "verifiedByTrustedIngress": True,
                            "sanSpiffeIds": ["spiffe://example.test/b"],
                        },
                    },
                ],
            )
        ),
        "identity selector sets overlap",
    )

    source_bound_proxy = principal_fixture_bundle(
        policy_bundle,
        [
            {
                "id": "source-bound-proxy",
                "requiredHeaders": {"X-Agent-Class": "bounded"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenSha256": token_digest,
                    "sourceCidrs": ["127.0.0.0/8"],
                },
            }
        ],
    )
    policy_bundle.compile_policy_bundle(
        source_bound_proxy,
        validate_schema=True,
    )
    unbound_proxy = principal_fixture_bundle(
        policy_bundle,
        [
            {
                "id": "unbound-proxy",
                "requiredHeaders": {"X-Agent-Class": "unbounded"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenSha256": token_digest,
                    "sourceCidrs": ["0.0.0.0/0", "::/0"],
                },
            }
        ],
    )
    expect_policy_error(
        "unbound proxy requiredHeaders schema",
        lambda: policy_bundle.compile_policy_bundle(
            unbound_proxy,
            validate_schema=True,
        ),
        "policy schema validation failed",
    )


def verify_checked_in_demo_policy(policy_bundle: Any) -> None:
    path = ROOT / "policies" / "demo.policy.json"
    raw = policy_bundle.strict_json_loads(path.read_text())
    if not isinstance(raw, dict):
        raise AssertionError("checked-in demo policy was not an object")
    snapshot = policy_bundle.compile_policy_bundle(
        raw,
        validate_schema=True,
    )
    if snapshot.raw["metadata"]["id"] != "serverware-demo":
        raise AssertionError("checked-in demo policy identity changed")


def verify_snapshot_immutability(policy_bundle: Any) -> None:
    snapshot = policy_bundle.compile_policy_bundle(
        candidate_bundle(policy_bundle, 1)
    )
    mutations = (
        lambda: snapshot.raw["defaults"].__setitem__("action", "allow"),
        lambda: snapshot.raw["routes"].append({}),
        lambda: snapshot.principals.__setitem__("attacker", None),
        lambda: snapshot.routes[0].adapter_config.__setitem__(
            "credentialMode", "none"
        ),
    )
    for mutate in mutations:
        try:
            mutate()
        except TypeError:
            continue
        raise AssertionError("verified policy snapshot admitted mutation")
    mutable_copy = copy.deepcopy(snapshot.raw)
    mutable_copy["defaults"]["action"] = "allow"
    if snapshot.raw["defaults"]["action"] != "deny":
        raise AssertionError("mutable policy copy poisoned verified snapshot")


def verify_shared_cache_immutability(policy_bundle: Any) -> None:
    first = policy_bundle.get_policy_snapshot()
    if first is None:
        raise AssertionError("shared-cache fixture requires an active policy")
    try:
        first.raw["defaults"]["action"] = "allow"
    except TypeError:
        pass
    else:
        raise AssertionError("cached verified snapshot admitted mutation")
    dict.__setitem__(first.raw["defaults"], "action", "allow")
    second = policy_bundle.get_policy_snapshot()
    if (
        second is None
        or second is first
        or second.hash != first.hash
        or second.raw["defaults"]["action"] != "deny"
    ):
        raise AssertionError("verified snapshot mutation poisoned shared cache")


def dry_run_case(app_module: Any, *, expect: str = "allow") -> Any:
    return app_module.PolicyDryRunCase(
        principalId="agent:demo",
        scheme="https",
        host="demo-upstream",
        port=8443,
        method="GET",
        path="/echo",
        expect=expect,
    )


def sign_publish_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str) -> dict[str, Any]:
    report = app_module._policy_candidate_report(
        bundle=payload.bundle,
        dry_run=payload.dry_run,
        enforce_monotonic=True,
    )
    digest = app_module._policy_publication_ceremony_payload_digest(
        payload,
        candidate_policy_hash=report["candidate"]["policyHash"],
        previous_policy_hash=report["current"]["policyHash"],
        candidate_bundle_sha256=app_module._policy_canary_bundle_digest(
            report["signedBundle"]
        ),
    )
    policy_id = payload.bundle["metadata"]["id"]
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if "demo-token-from-vault" in serialized_options:
        raise AssertionError("policy publish WebAuthn challenge leaked credential material")
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> None:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return
    raise AssertionError(f"{label} unexpectedly succeeded")


def expect_policy_error(label: str, func: Any, expected_detail: str) -> str:
    from serverware.policy_bundle import PolicyBundleError

    try:
        func()
    except PolicyBundleError as exc:
        if expected_detail not in str(exc):
            raise AssertionError(f"{label} failed with wrong error: {exc}") from exc
        return str(exc)
    raise AssertionError(f"{label} unexpectedly succeeded")


def publication_status(db: Any, policy_hash: str) -> str | None:
    with db.connect() as connection:
        row = connection.execute(
            "SELECT status FROM policy_publications WHERE policy_hash = ?",
            (policy_hash,),
        ).fetchone()
    return str(row["status"]) if row else None


class PostgreSQLCommitAcknowledgementLost(RuntimeError):
    pass


class CommitThenLoseAcknowledgement:
    """Model psycopg committing successfully before reporting transport loss."""

    def __init__(self, connection: Any, committed: list[bool]):
        self._connection = connection
        self._committed = committed
        self._policy_commit = False

    def __enter__(self) -> "CommitThenLoseAcknowledgement":
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> Any:
        if exc_type is None and self._policy_commit:
            self._connection.__exit__(None, None, None)
            self._committed.append(True)
            raise PostgreSQLCommitAcknowledgementLost(
                "injected PostgreSQL commit acknowledgement loss"
            )
        return self._connection.__exit__(exc_type, exc, traceback)

    @property
    def in_transaction(self) -> bool:
        return bool(self._connection.in_transaction)

    def execute(self, sql: str, params: Any = None) -> Any:
        result = self._connection.execute(sql, params)
        normalized = " ".join(sql.lower().split())
        if (
            normalized.startswith(
                "update policy_publications set status = ?, committed_at = ?"
            )
            and params
            and params[0] == "committed"
        ):
            self._policy_commit = True
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


def multiprocess_publish_worker(
    data_dir: str,
    sequence: int,
    start: Any,
    results: Any,
) -> None:
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
    from serverware import policy_bundle

    start.wait()
    try:
        snapshot = policy_bundle.write_policy_bundle(
            candidate_bundle(policy_bundle, sequence)
        )
    except BaseException as exc:
        results.put(("error", sequence, type(exc).__name__, str(exc)))
    else:
        results.put(("ok", sequence, snapshot.hash, ""))


def multiprocess_migration_worker(
    data_dir: str,
    start: Any,
    results: Any,
) -> None:
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
    from serverware import db

    start.wait()
    try:
        db.init_db()
    except BaseException as exc:
        results.put(("migration-error", 0, type(exc).__name__, str(exc)))
    else:
        results.put(("migration-ok", 0, "", ""))


def verify_multiprocess_publication(
    policy_bundle: Any,
    db: Any,
    data_dir: str,
) -> None:
    baseline = policy_bundle.get_policy_snapshot()
    if baseline is None:
        raise AssertionError("multi-process fixture requires an active policy")
    baseline_sequence = int(baseline.raw["metadata"]["sequence"])
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=multiprocess_publish_worker,
            args=(data_dir, baseline_sequence + offset, start, results),
        )
        for offset in (1, 2)
    ]
    processes.append(
        context.Process(
            target=multiprocess_migration_worker,
            args=(data_dir, start, results),
        )
    )
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            raise AssertionError("multi-process policy writer did not terminate")
    outcomes = [results.get(timeout=2) for _ in processes]
    final_snapshot = policy_bundle.get_policy_snapshot()
    final_high_water = db.get_policy_high_water()
    expected_sequence = baseline_sequence + 2
    if (
        final_snapshot is None
        or int(final_snapshot.raw["metadata"]["sequence"]) != expected_sequence
        or final_high_water is None
        or final_high_water["sequence"] != expected_sequence
        or final_high_water["policy_hash"] != final_snapshot.hash
        or not any(
            outcome[0] == "ok" and outcome[1] == expected_sequence
            for outcome in outcomes
        )
        or not any(outcome[0] == "migration-ok" for outcome in outcomes)
    ):
        raise AssertionError(
            f"multi-process publication did not preserve the highest winner: {outcomes}"
        )


def verify_mixed_backend_rejection(db: Any) -> None:
    original_metadata_backend = db.metadata_store_backend_name
    original_audit_backend = db.audit_store_backend_name
    db.metadata_store_backend_name = lambda: "postgres"
    db.audit_store_backend_name = lambda: "sqlite"
    try:
        try:
            db.init_db()
        except db.MetadataStoreError as exc:
            if "mixed metadata/audit store backends" not in str(exc):
                raise AssertionError(
                    f"mixed backend topology failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("mixed metadata/audit topology was accepted")
    finally:
        db.metadata_store_backend_name = original_metadata_backend
        db.audit_store_backend_name = original_audit_backend


def verify_ambiguous_commit_recovery(
    app_module: Any,
    policy_bundle: Any,
    db: Any,
    webauthn: Any,
    identity: Any,
    user_id: str,
) -> None:
    baseline = policy_bundle.get_policy_snapshot()
    if baseline is None:
        raise AssertionError("ambiguous commit fixture requires an active policy")
    next_sequence = int(baseline.raw["metadata"]["sequence"]) + 1
    payload = app_module.PolicyPublishRequest(
        bundle=candidate_bundle(policy_bundle, next_sequence),
        dryRun=[dry_run_case(app_module)],
    )
    payload.mfa = {
        "assertion": sign_publish_assertion(
            app_module,
            webauthn,
            payload,
            user_id,
        )
    }
    original_connect = db.connect
    committed: list[bool] = []

    def ambiguous_connect() -> CommitThenLoseAcknowledgement:
        return CommitThenLoseAcknowledgement(original_connect(), committed)

    db.connect = ambiguous_connect
    try:
        published = app_module.policy_publish(payload, identity=identity)
    finally:
        db.connect = original_connect
    if len(committed) != 1:
        raise AssertionError(
            "PostgreSQL-style acknowledgement-loss fixture did not commit once"
        )
    committed_snapshot = policy_bundle.get_policy_snapshot()
    if (
        committed_snapshot is None
        or committed_snapshot.hash != published.get("policyHash")
        or publication_status(db, committed_snapshot.hash) != "committed"
    ):
        raise AssertionError(
            "exact committed candidate was restored after acknowledgement loss"
        )

    predecessor = committed_snapshot
    predecessor_bytes = policy_bundle.POLICY_BUNDLE_PATH.read_bytes()
    losing_candidate = candidate_bundle(
        policy_bundle,
        int(predecessor.raw["metadata"]["sequence"]) + 1,
    )
    losing_prepared = policy_bundle._prepare_policy_publication(losing_candidate)
    winning_candidate = copy.deepcopy(losing_candidate)
    winning_candidate["metadata"]["rollbackEpoch"] = (
        int(winning_candidate["metadata"]["rollbackEpoch"]) + 1
    )
    winner = None
    winner_bytes = None
    try:
        with app_module._restore_files_on_error(
            app_module.POLICY_BUNDLE_PATH,
            authoritative_policy=lambda: losing_prepared.snapshot,
        ):
            winner = policy_bundle.write_policy_bundle(winning_candidate)
            winner_bytes = policy_bundle.POLICY_BUNDLE_PATH.read_bytes()
            raise PostgreSQLCommitAcknowledgementLost(
                "injected acknowledgement loss after a competing winner committed"
            )
    except PostgreSQLCommitAcknowledgementLost:
        pass
    else:
        raise AssertionError(
            "different committed winner incorrectly suppressed acknowledgement loss"
        )
    current = policy_bundle.get_policy_snapshot()
    high_water = db.get_policy_high_water()
    if (
        winner is None
        or winner_bytes is None
        or current is None
        or current.hash != winner.hash
        or high_water is None
        or high_water["policy_hash"] != winner.hash
        or publication_status(db, winner.hash) != "committed"
        or policy_bundle.POLICY_BUNDLE_PATH.read_bytes() != winner_bytes
        or policy_bundle.POLICY_BUNDLE_PATH.read_bytes() == predecessor_bytes
    ):
        raise AssertionError(
            "ambiguous recovery restored a stale predecessor over a committed winner"
        )


def verify_secure_policy_paths(
    policy_bundle: Any,
    baseline: Any,
    baseline_bytes: bytes,
) -> None:
    path = policy_bundle.POLICY_BUNDLE_PATH
    original_geteuid = policy_bundle.os.geteuid
    policy_bundle.os.geteuid = lambda: original_geteuid() + 1
    try:
        expect_policy_error(
            "wrong-owner policy",
            lambda: policy_bundle._validate_policy_file_stat(path.lstat()),
            "owned by the service effective user",
        )
    finally:
        policy_bundle.os.geteuid = original_geteuid
    if policy_bundle.get_policy_snapshot() is None:
        raise AssertionError("owner fixture did not restore policy access")

    os.chmod(path, 0o640)
    policy_bundle._SNAPSHOT_CACHE = None
    if policy_bundle.get_policy_snapshot() is not None:
        raise AssertionError("wrong-mode policy fixture did not deny")
    os.chmod(path, 0o600)
    if policy_bundle.get_policy_snapshot() is None:
        raise AssertionError("mode fixture did not restore policy access")

    backing = path.with_name(f".{path.name}.path-security")
    os.replace(path, backing)
    try:
        path.symlink_to(backing.name)
        policy_bundle._SNAPSHOT_CACHE = None
        if policy_bundle.get_policy_snapshot() is not None:
            raise AssertionError("symlink policy fixture did not deny")
        path.unlink()
        os.link(backing, path)
        policy_bundle._SNAPSHOT_CACHE = None
        if policy_bundle.get_policy_snapshot() is not None:
            raise AssertionError("hardlinked policy fixture did not deny")
        path.unlink()
    finally:
        if path.is_symlink():
            path.unlink()
        if not path.exists():
            os.replace(backing, path)
        else:
            backing.unlink(missing_ok=True)
    restored = policy_bundle.get_policy_snapshot()
    if restored is None or restored.hash != baseline.hash:
        raise AssertionError("policy path security fixtures did not restore policy")

    parent_mode = path.parent.stat().st_mode & 0o777
    os.chmod(path.parent, 0o500)
    try:
        policy_bundle._SNAPSHOT_CACHE = None
        read_only_parent_snapshot = policy_bundle.get_policy_snapshot()
        if (
            read_only_parent_snapshot is None
            or read_only_parent_snapshot.hash != baseline.hash
        ):
            raise AssertionError(
                "read-only trust ancestry made policy verification unavailable"
            )
        expect_policy_error(
            "read-only publication parent",
            lambda: policy_bundle.write_policy_bundle(
                candidate_bundle(
                    policy_bundle,
                    int(baseline.raw["metadata"]["sequence"]) + 1,
                )
            ),
            "mutation directory must be owned and writable",
        )
    finally:
        os.chmod(path.parent, parent_mode)

    publication_lock = Path(str(path) + ".publish.lock")
    os.chmod(publication_lock, 0o640)
    try:
        expect_policy_error(
            "wrong-mode publication lock",
            lambda: policy_bundle.write_policy_bundle(
                candidate_bundle(
                    policy_bundle,
                    int(baseline.raw["metadata"]["sequence"]) + 1,
                )
            ),
            "must use mode 0600",
        )
    finally:
        os.chmod(publication_lock, 0o600)
    lock_backing = publication_lock.with_name(
        f".{publication_lock.name}.symlink-target"
    )
    os.replace(publication_lock, lock_backing)
    try:
        publication_lock.symlink_to(lock_backing.name)
        expect_policy_error(
            "symlink publication lock",
            lambda: policy_bundle.write_policy_bundle(
                candidate_bundle(
                    policy_bundle,
                    int(baseline.raw["metadata"]["sequence"]) + 1,
                )
            ),
            "non-symlink regular file",
        )
        publication_lock.unlink()
    finally:
        if publication_lock.is_symlink():
            publication_lock.unlink()
        if not publication_lock.exists():
            os.replace(lock_backing, publication_lock)
        else:
            lock_backing.unlink(missing_ok=True)
    lock_alias = publication_lock.with_name(
        f".{publication_lock.name}.hardlink"
    )
    os.link(publication_lock, lock_alias)
    try:
        expect_policy_error(
            "hardlinked publication lock",
            lambda: policy_bundle.write_policy_bundle(
                candidate_bundle(
                    policy_bundle,
                    int(baseline.raw["metadata"]["sequence"]) + 1,
                )
            ),
            "must not be hardlinked",
        )
    finally:
        lock_alias.unlink(missing_ok=True)

    public_key = policy_bundle.POLICY_SIGNING_PUBLIC_KEY_PATH
    os.chmod(public_key, 0o600)
    policy_bundle._SNAPSHOT_CACHE = None
    if policy_bundle.get_policy_snapshot() is not None:
        raise AssertionError("wrong-mode public key fixture did not deny")
    os.chmod(public_key, 0o644)
    public_key_backing = public_key.with_name(
        f".{public_key.name}.symlink-target"
    )
    os.replace(public_key, public_key_backing)
    try:
        public_key.symlink_to(public_key_backing.name)
        policy_bundle._SNAPSHOT_CACHE = None
        if policy_bundle.get_policy_snapshot() is not None:
            raise AssertionError("symlink public key fixture did not deny")
        public_key.unlink()
    finally:
        if public_key.is_symlink():
            public_key.unlink()
        if not public_key.exists():
            os.replace(public_key_backing, public_key)
        else:
            public_key_backing.unlink(missing_ok=True)
    public_key_alias = public_key.with_name(f".{public_key.name}.hardlink")
    os.link(public_key, public_key_alias)
    try:
        policy_bundle._SNAPSHOT_CACHE = None
        if policy_bundle.get_policy_snapshot() is not None:
            raise AssertionError("hardlinked public key fixture did not deny")
    finally:
        public_key_alias.unlink(missing_ok=True)

    private_key = policy_bundle.POLICY_SIGNING_KEY_PATH
    signing_lock = Path(str(private_key) + ".lock")
    signing_lock_alias = signing_lock.with_name(
        f".{signing_lock.name}.hardlink"
    )
    os.link(signing_lock, signing_lock_alias)
    try:
        expect_policy_error(
            "hardlinked signing key lock",
            lambda: policy_bundle.sign_policy_bundle(
                candidate_bundle(
                    policy_bundle,
                    int(baseline.raw["metadata"]["sequence"]) + 1,
                )
            ),
            "must not be hardlinked",
        )
    finally:
        signing_lock_alias.unlink(missing_ok=True)
    private_key_alias = private_key.with_name(f".{private_key.name}.hardlink")
    os.link(private_key, private_key_alias)
    try:
        expect_policy_error(
            "hardlinked private key",
            lambda: policy_bundle.sign_policy_bundle(
                candidate_bundle(
                    policy_bundle,
                    int(baseline.raw["metadata"]["sequence"]) + 1,
                )
            ),
            "must not be hardlinked",
        )
    finally:
        private_key_alias.unlink(missing_ok=True)

    current_key_id = policy_bundle.policy_public_key_hash()
    mismatched_key_id = json.loads(json.dumps(baseline.raw))
    mismatched_key_id["metadata"]["signingKeyId"] = "sha256:" + "0" * 64
    expect_policy_error(
        "signed metadata key identity mismatch",
        lambda: policy_bundle.compile_policy_bundle(
            mismatched_key_id,
            verify_signature=True,
            validate_schema=True,
        ),
        "does not match trusted public key",
    )
    previous_revocations = os.environ.get(
        "SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS"
    )
    os.environ["SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS"] = current_key_id
    policy_bundle._SNAPSHOT_CACHE = None
    if policy_bundle.get_policy_snapshot() is not None:
        raise AssertionError("revoked signing key reused the policy cache")
    if previous_revocations is None:
        os.environ.pop("SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS", None)
    else:
        os.environ[
            "SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS"
        ] = previous_revocations
    restored = policy_bundle.get_policy_snapshot()
    if restored is None or restored.hash != baseline.hash:
        raise AssertionError("signing trust fixture did not restore policy")
    if path.read_bytes() != baseline_bytes:
        raise AssertionError("path security fixtures changed policy bytes")


def verify_policy_file_identity_and_rollback(
    policy_bundle: Any,
    db: Any,
) -> None:
    path = policy_bundle.POLICY_BUNDLE_PATH
    baseline = policy_bundle.get_policy_snapshot()
    if baseline is None:
        raise AssertionError("policy identity fixtures require an active snapshot")
    baseline_bytes = path.read_bytes()
    baseline_stat = path.stat()

    signature_marker = b'"signature": "ed25519:'
    signature_offset = baseline_bytes.find(signature_marker)
    if signature_offset < 0:
        raise AssertionError("signed policy fixture did not contain a signature")
    signature_offset += len(signature_marker)
    same_mtime_mutation = bytearray(baseline_bytes)
    same_mtime_mutation[signature_offset] = (
        ord("A")
        if same_mtime_mutation[signature_offset] != ord("A")
        else ord("B")
    )
    path.write_bytes(bytes(same_mtime_mutation))
    os.utime(
        path,
        ns=(baseline_stat.st_atime_ns, baseline_stat.st_mtime_ns),
    )
    mutated_stat = path.stat()
    if (
        mutated_stat.st_size != baseline_stat.st_size
        or mutated_stat.st_mtime_ns != baseline_stat.st_mtime_ns
    ):
        raise AssertionError("same-mtime policy mutation fixture was not stable")
    if policy_bundle.get_policy_snapshot() is not None:
        raise AssertionError("same-mtime signed policy mutation reused the cache")
    policy_bundle._atomic_write_policy(path, baseline_bytes.decode("utf-8"))
    restored = policy_bundle.get_policy_snapshot()
    if restored is None or restored.hash != baseline.hash:
        raise AssertionError("same-mtime fixture did not restore the active policy")

    cached_before_replace = policy_bundle._SNAPSHOT_CACHE
    if (
        not isinstance(cached_before_replace, tuple)
        or cached_before_replace[0] is None
    ):
        raise AssertionError("policy cache omitted stable file identity")
    identity_before_replace = cached_before_replace[0]
    replacement_path = path.with_name(f".{path.name}.identity-replacement")
    try:
        policy_bundle._atomic_write_policy(
            replacement_path, baseline_bytes.decode("utf-8")
        )
        replacement_stat = path.stat()
        os.utime(
            replacement_path,
            ns=(replacement_stat.st_atime_ns, replacement_stat.st_mtime_ns),
        )
        os.replace(replacement_path, path)
    finally:
        replacement_path.unlink(missing_ok=True)
    atomically_reloaded = policy_bundle.get_policy_snapshot()
    cached_after_replace = policy_bundle._SNAPSHOT_CACHE
    if (
        atomically_reloaded is None
        or atomically_reloaded.hash != baseline.hash
        or not isinstance(cached_after_replace, tuple)
        or cached_after_replace[0] is None
        or cached_after_replace[0].inode == identity_before_replace.inode
        or cached_after_replace[0].file_sha256
        != identity_before_replace.file_sha256
    ):
        raise AssertionError(
            "atomic policy replacement did not refresh the complete file identity"
        )

    policy_bundle._SNAPSHOT_CACHE = None
    original_read = policy_bundle.os.read
    replaced_during_read = False

    def replace_policy_during_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced_during_read
        chunk = original_read(descriptor, count)
        if chunk and not replaced_during_read:
            replaced_during_read = True
            policy_bundle._atomic_write_policy(
                path, baseline_bytes.decode("utf-8")
            )
        return chunk

    policy_bundle.os.read = replace_policy_during_read
    try:
        unstable_result = policy_bundle.get_policy_snapshot()
    finally:
        policy_bundle.os.read = original_read
    if not replaced_during_read or unstable_result is not None:
        raise AssertionError("unstable policy read did not fail closed")
    stable_after_race = policy_bundle.get_policy_snapshot()
    if stable_after_race is None or stable_after_race.hash != baseline.hash:
        raise AssertionError("stable policy did not recover after read race")

    policy_bundle._SNAPSHOT_CACHE = None
    original_identity_recheck = policy_bundle._recheck_policy_path_identity
    replaced_after_verification = False

    def replace_policy_after_verification(
        checked_path: Path,
        expected_identity: Any,
    ) -> None:
        nonlocal replaced_after_verification
        if not replaced_after_verification:
            replaced_after_verification = True
            policy_bundle._atomic_write_policy(
                checked_path,
                baseline_bytes.decode("utf-8"),
            )
        original_identity_recheck(checked_path, expected_identity)

    policy_bundle._recheck_policy_path_identity = (
        replace_policy_after_verification
    )
    try:
        post_read_replace_result = policy_bundle.get_policy_snapshot()
    finally:
        policy_bundle._recheck_policy_path_identity = original_identity_recheck
    if not replaced_after_verification or post_read_replace_result is not None:
        raise AssertionError("post-verification policy replacement did not deny")
    stable_after_post_read_replace = policy_bundle.get_policy_snapshot()
    if (
        stable_after_post_read_replace is None
        or stable_after_post_read_replace.hash != baseline.hash
    ):
        raise AssertionError(
            "policy did not recover after post-verification replacement"
        )

    verify_secure_policy_paths(
        policy_bundle,
        baseline,
        baseline_bytes,
    )

    original_db_verify = db.verify_policy_high_water
    high_water_fast_path_checks = 0

    def reject_cached_high_water(**_: Any) -> dict[str, Any]:
        nonlocal high_water_fast_path_checks
        high_water_fast_path_checks += 1
        raise db.MetadataStoreError("injected exact high-water rejection")

    db.verify_policy_high_water = reject_cached_high_water
    try:
        if policy_bundle.get_policy_snapshot() is not None:
            raise AssertionError(
                "cache fast path skipped exact high-water verification"
            )
    finally:
        db.verify_policy_high_water = original_db_verify
    if high_water_fast_path_checks < 1:
        raise AssertionError("cache fast path did not query high-water state")
    if policy_bundle.get_policy_snapshot() is None:
        raise AssertionError("high-water fast-path fixture did not recover")

    oversized_candidate = candidate_bundle(
        policy_bundle,
        int(baseline.raw["metadata"]["sequence"]) + 1,
    )
    high_water_before_oversize = db.get_policy_high_water()
    bytes_before_oversize = path.read_bytes()
    original_maximum = policy_bundle.MAX_POLICY_BUNDLE_BYTES
    policy_bundle.MAX_POLICY_BUNDLE_BYTES = 1
    try:
        expect_policy_error(
            "oversize policy publication",
            lambda: policy_bundle.write_policy_bundle(oversized_candidate),
            "publication size bound",
        )
    finally:
        policy_bundle.MAX_POLICY_BUNDLE_BYTES = original_maximum
    if (
        db.get_policy_high_water() != high_water_before_oversize
        or path.read_bytes() != bytes_before_oversize
    ):
        raise AssertionError(
            "oversize policy changed authority or the active policy file"
        )

    next_sequence = int(baseline.raw["metadata"]["sequence"]) + 1
    stale_successor = candidate_bundle(
        policy_bundle,
        next_sequence + 1,
    )
    stale_successor_prepared = policy_bundle._prepare_policy_publication(
        stale_successor
    )
    policy_bundle._stage_policy_publication(stale_successor_prepared)
    winner = policy_bundle.write_policy_bundle(
        candidate_bundle(policy_bundle, next_sequence)
    )
    winner_bytes = path.read_bytes()
    conflicting = candidate_bundle(policy_bundle, next_sequence)
    conflicting["metadata"]["rollbackEpoch"] = (
        int(conflicting["metadata"]["rollbackEpoch"]) + 1
    )
    expect_policy_error(
        "equal-sequence lost update",
        lambda: policy_bundle.write_policy_bundle(conflicting),
        "does not exceed persisted high-water",
    )
    if path.read_bytes() != winner_bytes:
        raise AssertionError("rejected lost update changed the active policy file")
    current_high_water = db.get_policy_high_water()
    if (
        current_high_water is None
        or current_high_water["sequence"] != next_sequence
        or current_high_water["policy_hash"] != winner.hash
    ):
        raise AssertionError(
            f"lost-update winner did not remain authoritative: {current_high_water}"
        )
    expect_policy_error(
        "stale pending predecessor",
        lambda: policy_bundle.write_policy_bundle(stale_successor),
        "predecessor is stale",
    )
    if path.read_bytes() != winner_bytes:
        raise AssertionError(
            "stale pending successor overwrote its concurrent winner"
        )

    policy_bundle._atomic_write_policy(path, baseline_bytes.decode("utf-8"))
    if policy_bundle.get_policy_snapshot() is not None:
        raise AssertionError(
            "ordinary same-directory policy rollback bypassed high-water state"
        )
    restored_winner = policy_bundle.write_policy_bundle(winner.raw)
    if restored_winner.hash != winner.hash:
        raise AssertionError("idempotent rollback recovery changed policy digest")

    policy_bundle._SNAPSHOT_CACHE = None
    restarted = policy_bundle.get_policy_snapshot()
    if restarted is None or restarted.hash != winner.hash:
        raise AssertionError(
            "restart did not enforce and recover exact high-water policy state"
        )

    interrupted = candidate_bundle(policy_bundle, next_sequence + 2)
    interrupted_prepared = policy_bundle._prepare_policy_publication(
        interrupted
    )
    original_atomic_write = policy_bundle._atomic_write_policy

    def fail_before_policy_replace(path: Path, payload: str) -> None:
        raise OSError("injected policy replacement failure")

    policy_bundle._atomic_write_policy = fail_before_policy_replace
    try:
        try:
            policy_bundle.write_policy_bundle(interrupted)
        except OSError:
            pass
        else:
            raise AssertionError("interrupted policy publication succeeded")
    finally:
        policy_bundle._atomic_write_policy = original_atomic_write
    active_after_interruption = policy_bundle.get_policy_snapshot()
    if (
        active_after_interruption is None
        or active_after_interruption.hash != winner.hash
    ):
        raise AssertionError(
            "failed publication did not preserve the committed active policy"
        )
    if publication_status(db, interrupted_prepared.snapshot.hash) != "pending":
        raise AssertionError(
            "failed publication did not retain durable pending intent"
        )
    recovered = policy_bundle.write_policy_bundle(interrupted)
    if publication_status(db, recovered.hash) != "committed":
        raise AssertionError("retry did not commit pending publication")
    policy_bundle._SNAPSHOT_CACHE = None
    recovered_after_restart = policy_bundle.get_policy_snapshot()
    if (
        recovered_after_restart is None
        or recovered_after_restart.hash != recovered.hash
    ):
        raise AssertionError(
            "interrupted publication did not recover idempotently after restart"
        )

    crash_candidate = candidate_bundle(
        policy_bundle,
        int(recovered.raw["metadata"]["sequence"]) + 1,
    )
    crash_prepared = policy_bundle._prepare_policy_publication(crash_candidate)
    crash_staged = policy_bundle._stage_policy_bundle_for_transaction(
        crash_candidate,
        expected_previous_policy_hash=recovered.hash,
    )
    high_water_before_crash = db.get_policy_high_water()

    class SimulatedProcessDeath(BaseException):
        pass

    try:
        with policy_bundle._policy_publication_lock():
            with db.connect() as connection:
                db.lock_policy_publication(connection)
                expect_policy_error(
                    "raw transactional publication bypass",
                    lambda: policy_bundle._write_policy_bundle_in_transaction(
                        crash_prepared.signed,
                        connection=connection,
                    ),
                    "private staged capability",
                )
                policy_bundle._write_policy_bundle_in_transaction(
                    crash_staged,
                    connection=connection,
                )
                raise SimulatedProcessDeath()
    except SimulatedProcessDeath:
        pass
    if db.get_policy_high_water() != high_water_before_crash:
        raise AssertionError(
            "process-death fixture committed transactional high-water"
        )
    policy_bundle._SNAPSHOT_CACHE = None
    if policy_bundle.get_policy_snapshot() is not None:
        raise AssertionError(
            "loader authorized a file from a rolled-back publication transaction"
        )
    if publication_status(db, crash_prepared.snapshot.hash) != "pending":
        raise AssertionError(
            "rolled-back publication lost its durable pending marker"
        )
    recovered_crash = policy_bundle.write_policy_bundle(crash_candidate)
    if (
        recovered_crash.hash != crash_prepared.snapshot.hash
        or publication_status(db, recovered_crash.hash) != "committed"
    ):
        raise AssertionError(
            "same-snapshot crash recovery was not exact and idempotent"
        )

    boundary = policy_bundle.POLICY_HIGH_WATER_TRUST_BOUNDARY
    if (
        "metadata high-water store" not in boundary
        or "coherent rollback" not in boundary
        or "cannot be detected internally" not in boundary
    ):
        raise AssertionError(
            "anti-rollback test omitted the external coherent-storage boundary"
        )


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import db, policy_bundle, webauthn
        from serverware.attestation import attestation_document, canonical_json, sha256_prefixed, verify_attestation_quote
        from serverware.auth import AdminIdentity

        db.init_db()
        verify_mixed_backend_rejection(db)
        verify_checked_in_demo_policy(policy_bundle)
        verify_principal_identity_cardinality(policy_bundle)
        verify_snapshot_immutability(policy_bundle)
        user_id = "user:publisher"
        webauthn.create_dev_credential(user_id)
        identity = AdminIdentity(user_id, frozenset({"policy_publisher", "policy_author"}), "admin-token-header")
        initial = policy_bundle.write_policy_bundle(candidate_bundle(policy_bundle, 1))
        verify_shared_cache_immutability(policy_bundle)
        policy_bundle.enforce_policy_high_water(initial)
        try:
            policy_bundle.write_policy_bundle(
                candidate_bundle(policy_bundle, 2),
                enforce_high_water=False,
            )
        except TypeError:
            pass
        else:
            raise AssertionError(
                "public policy writer retained a rollback-protection bypass"
            )

        substituted_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        substituted_payload.mfa = {
            "assertion": sign_publish_assertion(
                app_module,
                webauthn,
                substituted_payload,
                user_id,
            )
        }
        original_publication_file_lock = (
            app_module._policy_publication_file_lock
        )

        class SubstituteCandidateAtPublicationLock:
            def __enter__(self) -> None:
                substituted_payload.bundle["metadata"]["sequence"] = 3
                self._locked = original_publication_file_lock()
                self._locked.__enter__()

            def __exit__(
                self,
                exc_type: Any,
                exc: Any,
                traceback: Any,
            ) -> Any:
                return self._locked.__exit__(exc_type, exc, traceback)

        app_module._policy_publication_file_lock = (
            SubstituteCandidateAtPublicationLock
        )
        try:
            expect_http_error(
                "approved policy candidate substitution",
                lambda: app_module.policy_publish(
                    substituted_payload,
                    identity=identity,
                ),
                409,
                "candidate or predecessor changed",
            )
        finally:
            app_module._policy_publication_file_lock = (
                original_publication_file_lock
            )
        unchanged_after_substitution = policy_bundle.get_policy_snapshot()
        if (
            unchanged_after_substitution is None
            or unchanged_after_substitution.hash != initial.hash
            or db.get_policy_high_water()["policy_hash"] != initial.hash
        ):
            raise AssertionError(
                "candidate substitution changed active policy authority"
            )

        publish_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        publish_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, publish_payload, user_id)}
        published = app_module.policy_publish(publish_payload, identity=identity)
        if published.get("published") is not True or published["candidate"]["sequence"] != 2:
            raise AssertionError(f"policy publish returned invalid result: {published}")
        if published["dryRun"]["passed"] is not True or published["dryRun"]["count"] != 1:
            raise AssertionError(f"policy publish did not run dry-run checks: {published}")
        active = policy_bundle.get_policy_snapshot()
        if not active or active.hash != published["policyHash"]:
            raise AssertionError("active policy snapshot was not updated after publish")
        high_water = db.get_policy_high_water()
        if not high_water or high_water["sequence"] != 2 or high_water["policy_hash"] != active.hash:
            raise AssertionError(f"policy high-water state did not advance with publish: {high_water}")
        if policy_bundle.enforce_policy_high_water(active) != high_water:
            raise AssertionError("exact active policy was not accepted idempotently")
        attestation = attestation_document("policy-high-water-test")
        claims = verify_attestation_quote(attestation)
        evidence = attestation.get("policy_high_water")
        if not isinstance(evidence, dict):
            raise AssertionError(f"attestation omitted policy high-water evidence: {attestation}")
        expected_high_water_digest = sha256_prefixed(canonical_json(evidence).encode("utf-8"))
        if attestation.get("policy_high_water_digest") != expected_high_water_digest:
            raise AssertionError("attestation policy high-water digest was invalid")
        for field in ("policy_sequence", "policy_high_water_digest"):
            if claims.get(field) != attestation.get(field):
                raise AssertionError(f"quote did not bind {field}")

        original_floor = policy_bundle.POLICY_MIN_SEQUENCE
        policy_bundle.POLICY_MIN_SEQUENCE = 3
        try:
            expect_policy_error(
                "configured policy sequence floor",
                lambda: policy_bundle.enforce_policy_high_water(active),
                "below configured floor",
            )
        finally:
            policy_bundle.POLICY_MIN_SEQUENCE = original_floor

        expect_policy_error(
            "default writer policy rollback",
            lambda: policy_bundle.write_policy_bundle(
                candidate_bundle(policy_bundle, 1)
            ),
            "does not exceed persisted high-water",
        )
        unchanged = policy_bundle.get_policy_snapshot()
        if unchanged is None or unchanged.hash != active.hash:
            raise AssertionError(
                "default writer changed active policy after rollback rejection"
            )

        changed_id = candidate_bundle(policy_bundle, 3)
        changed_id["metadata"]["id"] = "serverware-other"
        changed_id_snapshot = policy_bundle.compile_policy_bundle(
            policy_bundle.sign_policy_bundle(changed_id),
            verify_signature=True,
            validate_schema=True,
        )
        expect_policy_error(
            "policy id switch",
            lambda: policy_bundle.enforce_policy_high_water(changed_id_snapshot),
            "not the exact persisted high-water state",
        )
        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"policy publish audit outbox did not drain: {delivery}")
        audits = db.list_audit_events(limit=20)
        policy_events = [item for item in audits if item["event_type"] == "policy.published"]
        if not policy_events:
            raise AssertionError(f"policy publish audit event missing: {audits}")
        audit_payload = policy_events[0]["event"]
        if audit_payload.get("control_plane_mfa", {}).get("method") != "webauthn":
            raise AssertionError(f"policy publish audit event missing MFA evidence: {audit_payload}")
        if audit_payload.get("dry_run", {}).get("passed") is not True:
            raise AssertionError(f"policy publish audit event missing dry-run evidence: {audit_payload}")

        stale_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        stale_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, stale_payload, user_id)}
        idempotent_publish = app_module.policy_publish(
            stale_payload,
            identity=identity,
        )
        if (
            idempotent_publish.get("published") is not True
            or idempotent_publish.get("policyHash") != active.hash
        ):
            raise AssertionError(
                "exact committed app publication retry was not idempotent"
            )

        no_dry_run_payload = app_module.PolicyPublishRequest(bundle=candidate_bundle(policy_bundle, 3), dryRun=[])
        expect_http_error(
            "policy publish without dry-run",
            lambda: app_module.policy_publish(no_dry_run_payload, identity=identity),
            412,
            "dry-run decision tests",
        )

        failing_dry_run_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3),
            dryRun=[dry_run_case(app_module, expect="deny")],
        )
        expect_http_error(
            "policy publish with failing dry-run",
            lambda: app_module.policy_publish(failing_dry_run_payload, identity=identity),
            409,
            "policy dry-run failed",
        )

        missing_mfa_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "policy publish without MFA",
            lambda: app_module.policy_publish(missing_mfa_payload, identity=identity),
            412,
            "WebAuthn assertion required",
        )
        verify_policy_file_identity_and_rollback(policy_bundle, db)
        verify_multiprocess_publication(policy_bundle, db, tmp)
        verify_ambiguous_commit_recovery(
            app_module,
            policy_bundle,
            db,
            webauthn,
            identity,
            user_id,
        )

    print(json.dumps({"ok": True, "policy_publish_workflow": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
