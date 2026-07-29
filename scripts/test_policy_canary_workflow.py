#!/usr/bin/env python3
from __future__ import annotations

import json
import multiprocessing
import os
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def contending_policy_directory_lock_worker(
    lock_path: str,
    attempted: Any,
    entered: Any,
    results: Any,
) -> None:
    from serverware import policy_bundle

    attempted.set()
    try:
        with policy_bundle._exclusive_secure_file_lock(
            Path(lock_path),
            label="contending production publication lock",
            thread_lock=threading.RLock(),
            state=threading.local(),
            directory_lock=True,
        ):
            (Path(lock_path) / "contender-mutation").write_bytes(b"entered")
            entered.set()
    except Exception as exc:
        results.put(("error", type(exc).__name__, str(exc)))
    else:
        results.put(("entered", "", ""))


def candidate_bundle(
    policy_bundle: Any, sequence: int, credential_id: str
) -> dict[str, Any]:
    bundle = policy_bundle.demo_policy_bundle(credential_id)
    bundle["metadata"]["sequence"] = sequence
    return bundle


def dry_run_case(app_module: Any) -> Any:
    return app_module.PolicyDryRunCase(
        principalId="agent:demo",
        scheme="https",
        host="demo-upstream",
        port=8443,
        method="GET",
        path="/echo",
        expect="allow",
    )


def sign_publish_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str) -> dict[str, Any]:
    report = app_module._policy_candidate_report(
        bundle=payload.bundle,
        dry_run=payload.dry_run,
        enforce_monotonic=True,
    )
    candidate_bundle_digest = app_module._policy_canary_bundle_digest(
        report["signedBundle"]
    )
    digest = app_module._policy_canary_start_payload_digest(
        payload,
        candidate_policy_hash=report["candidate"]["policyHash"],
        previous_policy_hash=report["current"]["policyHash"],
        candidate_bundle_sha256=candidate_bundle_digest,
    )
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=payload.bundle["metadata"]["id"],
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if "demo-token-from-vault" in serialized_options:
        raise AssertionError("policy canary WebAuthn challenge leaked credential material")
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> dict[str, Any]:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
    raise AssertionError(f"{label} unexpectedly succeeded")


def verify_canary_file_security(
    app_module: Any,
    policy_bundle: Any,
) -> None:
    fixtures = (
        (
            app_module.POLICY_CANARY_STATE_PATH,
            app_module._read_policy_canary_state,
        ),
        (
            app_module.POLICY_CANARY_BUNDLE_PATH,
            app_module._read_policy_canary_bundle,
        ),
    )
    for path, reader in fixtures:
        file_stat = path.lstat()
        if file_stat.st_nlink != 1 or (file_stat.st_mode & 0o777) != 0o600:
            raise AssertionError("canary file security contract was not installed")

        os.chmod(path, 0o640)
        try:
            expect_http_error(
                "wrong-mode canary file",
                reader,
                503,
                "unreadable",
            )
        finally:
            os.chmod(path, 0o600)

        alias = path.with_name(f".{path.name}.hardlink")
        os.link(path, alias)
        try:
            expect_http_error(
                "hardlinked canary file",
                reader,
                503,
                "unreadable",
            )
        finally:
            alias.unlink(missing_ok=True)

        backing = path.with_name(f".{path.name}.symlink-target")
        os.replace(path, backing)
        try:
            path.symlink_to(backing.name)
            expect_http_error(
                "symlink canary file",
                reader,
                503,
                "unreadable",
            )
            path.unlink()
        finally:
            if path.is_symlink():
                path.unlink()
            if not path.exists():
                os.replace(backing, path)
            else:
                backing.unlink(missing_ok=True)

        original_geteuid = policy_bundle.os.geteuid
        policy_bundle.os.geteuid = lambda: original_geteuid() + 1
        try:
            try:
                policy_bundle._validate_secure_file_stat(
                    path.lstat(),
                    label="canary owner fixture",
                    expected_mode=0o600,
                    maximum_size=app_module.MAX_POLICY_BUNDLE_BYTES,
                )
            except policy_bundle.PolicyBundleError as exc:
                if "owned by the service effective user" not in str(exc):
                    raise AssertionError(
                        f"canary owner fixture failed incorrectly: {exc}"
                    ) from exc
            else:
                raise AssertionError("wrong-owner canary file was accepted")
        finally:
            policy_bundle.os.geteuid = original_geteuid

    original_release_channel = policy_bundle.RELEASE_CHANNEL
    policy_bundle.RELEASE_CHANNEL = "production"
    root_owned_read_only = SimpleNamespace(
        st_mode=0o040555,
        st_nlink=2,
        st_uid=0,
        st_gid=0,
    )
    unsafe_root_owned_writable = SimpleNamespace(
        st_mode=0o040777,
        st_nlink=2,
        st_uid=0,
        st_gid=0,
    )
    service_owned_protected_lock_leaf = SimpleNamespace(
        st_mode=0o040755,
        st_nlink=2,
        st_uid=os.geteuid(),
        st_gid=os.getegid(),
    )
    try:
        policy_bundle._validate_secure_directory_stat(
            root_owned_read_only,
            label="root-owned read-only trust",
            leaf=True,
            mutation_target=False,
        )
        try:
            policy_bundle._validate_secure_directory_stat(
                root_owned_read_only,
                label="root-owned publication target",
                leaf=True,
                mutation_target=True,
            )
        except policy_bundle.PolicyBundleError:
            pass
        else:
            raise AssertionError(
                "root-owned read-only trust directory was accepted for mutation"
            )
        try:
            policy_bundle._validate_secure_directory_stat(
                unsafe_root_owned_writable,
                label="writable trust ancestry",
                leaf=False,
                mutation_target=False,
            )
        except policy_bundle.PolicyBundleError:
            pass
        else:
            raise AssertionError(
                "group/world-writable production trust ancestry was accepted"
            )
        policy_bundle._validate_secure_directory_stat(
            service_owned_protected_lock_leaf,
            label="service-owned protected policy-volume lock leaf",
            leaf=True,
            mutation_target=True,
            trusted_lock_namespace=True,
            allow_service_owned_lock_leaf=True,
        )
        try:
            policy_bundle._validate_secure_directory_stat(
                service_owned_protected_lock_leaf,
                label="service-owned replaceable lock ancestor",
                leaf=False,
                mutation_target=False,
                trusted_lock_namespace=True,
                allow_service_owned_lock_leaf=True,
            )
        except policy_bundle.PolicyBundleError:
            pass
        else:
            raise AssertionError(
                "service-owned directory above the immutable lock leaf was accepted"
            )
        if (
            policy_bundle._PRODUCTION_POLICY_PUBLICATION_LOCK_PATH
            != policy_bundle.POLICY_BUNDLE_PATH.parent
            or "shared policy-volume mounts" not in (
                policy_bundle.POLICY_PUBLICATION_LOCK_TRUST_BOUNDARY
            )
        ):
            raise AssertionError(
                "production publication lock is not bound to the shared policy volume"
            )
    finally:
        policy_bundle.RELEASE_CHANNEL = original_release_channel

    parent = app_module.POLICY_CANARY_STATE_PATH.parent
    original_parent_mode = parent.stat().st_mode & 0o777
    os.chmod(parent, 0o777)
    try:
        expect_http_error(
            "writable canary parent",
            app_module._read_policy_canary_state,
            503,
            "unreadable",
        )
    finally:
        os.chmod(parent, original_parent_mode)

    canonical_parent = Path(os.path.realpath(parent))
    real_parent = canonical_parent / ".canary-parent-fixture"
    linked_parent = canonical_parent / ".canary-parent-symlink"
    real_parent.mkdir(mode=0o700)
    fixture_path = real_parent / "state.json"
    fixture_path.write_bytes(b"{}")
    os.chmod(fixture_path, 0o600)
    linked_parent.symlink_to(real_parent.name)
    original_release_channel = policy_bundle.RELEASE_CHANNEL
    policy_bundle.RELEASE_CHANNEL = "production"
    try:
        try:
            policy_bundle._read_stable_secure_file(
                linked_parent / fixture_path.name,
                label="symlinked canary parent",
                expected_mode=0o600,
                maximum_size=1024,
            )
        except policy_bundle.PolicyBundleError:
            pass
        else:
            raise AssertionError("symlinked canary parent was accepted")
    finally:
        policy_bundle.RELEASE_CHANNEL = original_release_channel
        linked_parent.unlink(missing_ok=True)
        fixture_path.unlink(missing_ok=True)
        real_parent.rmdir()

    replaced_parent = canonical_parent / ".canary-parent-replace"
    moved_parent = canonical_parent / ".canary-parent-replace-moved"
    replaced_parent.mkdir(mode=0o700)
    replaced_fixture = replaced_parent / "state.json"
    replaced_fixture.write_bytes(b"{}")
    os.chmod(replaced_fixture, 0o600)
    original_read_for_parent = policy_bundle.os.read
    parent_replaced = False

    def replace_parent_during_read(descriptor: int, count: int) -> bytes:
        nonlocal parent_replaced
        chunk = original_read_for_parent(descriptor, count)
        if chunk and not parent_replaced:
            parent_replaced = True
            os.replace(replaced_parent, moved_parent)
            replaced_parent.mkdir(mode=0o700)
            replacement = replaced_parent / replaced_fixture.name
            replacement.write_bytes(b"{}")
            os.chmod(replacement, 0o600)
        return chunk

    policy_bundle.os.read = replace_parent_during_read
    try:
        try:
            policy_bundle._read_stable_secure_file(
                replaced_fixture,
                label="replaced canary parent",
                expected_mode=0o600,
                maximum_size=1024,
            )
        except policy_bundle.PolicyBundleError as exc:
            if "parent directory changed" not in str(exc):
                raise AssertionError(
                    f"parent replacement failed incorrectly: {exc}"
                ) from exc
        else:
            raise AssertionError("replaced canary parent was accepted")
    finally:
        policy_bundle.os.read = original_read_for_parent
        (replaced_parent / replaced_fixture.name).unlink(missing_ok=True)
        if replaced_parent.exists():
            replaced_parent.rmdir()
        (moved_parent / replaced_fixture.name).unlink(missing_ok=True)
        if moved_parent.exists():
            moved_parent.rmdir()
    if not parent_replaced:
        raise AssertionError("parent replacement fixture did not replace its path")

    split_lock_anchor = canonical_parent / ".policy-lock-anchor"
    split_lock_namespace = split_lock_anchor / "namespace"
    split_lock_path = split_lock_namespace / "policy-volume"
    moved_lock_namespace = split_lock_anchor / "namespace-moved"
    replacement_lock = canonical_parent / ".policy-lock-replacement"
    split_lock_anchor.mkdir(mode=0o700)
    split_lock_namespace.mkdir(mode=0o700)
    split_lock_path.mkdir(mode=0o700)
    replacement_lock.mkdir(mode=0o700)
    os.chmod(split_lock_namespace, 0o555)
    os.chmod(split_lock_anchor, 0o555)
    context = multiprocessing.get_context("spawn")
    contender_attempted = context.Event()
    contender_entered = context.Event()
    contender_results = context.Queue()
    contender = context.Process(
        target=contending_policy_directory_lock_worker,
        args=(
            str(split_lock_path),
            contender_attempted,
            contender_entered,
            contender_results,
        ),
    )
    try:
        with policy_bundle._exclusive_secure_file_lock(
            split_lock_path,
            label="first production publication lock",
            thread_lock=threading.RLock(),
            state=threading.local(),
            directory_lock=True,
        ):
            contender.start()
            if not contender_attempted.wait(timeout=3):
                raise AssertionError(
                    "contending publication process did not attempt the lock"
                )
            if contender_entered.wait(timeout=1):
                raise AssertionError(
                    "second publication process entered while the first held the lock"
                )
            if not contender.is_alive():
                raise AssertionError(
                    "contending publication process exited instead of blocking"
                )
            if os.geteuid() != 0:
                try:
                    os.replace(replacement_lock, split_lock_path)
                except PermissionError:
                    pass
                else:
                    raise AssertionError(
                        "service replaced the policy-volume lock inode while it was held"
                    )
                try:
                    os.replace(split_lock_namespace, moved_lock_namespace)
                except PermissionError:
                    pass
                else:
                    raise AssertionError(
                        "service replaced the production lock parent while it was held"
                    )
            if contender_entered.is_set():
                raise AssertionError(
                    "second publication mutation entered during replacement attempts"
                )
            if (split_lock_path / "contender-mutation").exists():
                raise AssertionError(
                    "second publication process mutated while the first held the lock"
                )
        contender.join(timeout=5)
        if contender.is_alive():
            contender.terminate()
            contender.join(timeout=2)
            raise AssertionError(
                "contending publication process remained blocked after unlock"
            )
        result = contender_results.get(timeout=2)
        if (
            result[0] != "entered"
            or not contender_entered.is_set()
            or not (split_lock_path / "contender-mutation").is_file()
        ):
            raise AssertionError(
                f"contending publication process did not enter exactly once: {result}"
            )
    finally:
        if contender.is_alive():
            contender.terminate()
            contender.join(timeout=2)
        if split_lock_anchor.exists():
            os.chmod(split_lock_anchor, 0o700)
        if split_lock_namespace.exists():
            os.chmod(split_lock_namespace, 0o700)
        if replacement_lock.exists():
            replacement_lock.rmdir()
        if split_lock_path.exists():
            (split_lock_path / "contender-mutation").unlink(missing_ok=True)
            split_lock_path.rmdir()
        if split_lock_namespace.exists():
            split_lock_namespace.rmdir()
        if split_lock_anchor.exists():
            split_lock_anchor.rmdir()
        if moved_lock_namespace.exists():
            os.chmod(moved_lock_namespace, 0o700)
            moved_lock_path = moved_lock_namespace / split_lock_path.name
            if moved_lock_path.exists():
                (moved_lock_path / "contender-mutation").unlink(missing_ok=True)
                moved_lock_path.rmdir()
            moved_lock_namespace.rmdir()

    state = app_module._read_policy_canary_state()
    bundle = app_module._read_policy_canary_bundle()
    if state is None:
        raise AssertionError("canary state disappeared during file fixtures")
    state_path = app_module.POLICY_CANARY_STATE_PATH
    state_bytes = state_path.read_bytes()
    original_read = policy_bundle.os.read
    replaced_during_read = False

    def replace_canary_during_read(
        descriptor: int,
        count: int,
    ) -> bytes:
        nonlocal replaced_during_read
        chunk = original_read(descriptor, count)
        if chunk and not replaced_during_read:
            replaced_during_read = True
            policy_bundle._atomic_write_secure_file(
                state_path,
                state_bytes,
                label="policy canary state",
                mode=0o600,
            )
        return chunk

    policy_bundle.os.read = replace_canary_during_read
    try:
        expect_http_error(
            "unstable canary state read",
            app_module._read_policy_canary_state,
            503,
            "unreadable",
        )
    finally:
        policy_bundle.os.read = original_read
    if not replaced_during_read:
        raise AssertionError("unstable canary read fixture did not replace its path")
    tampered_bundle = json.loads(json.dumps(bundle))
    tampered_bundle["metadata"]["sequence"] = (
        int(tampered_bundle["metadata"]["sequence"]) + 1
    )
    app_module._write_policy_canary_bundle(tampered_bundle)
    try:
        expect_http_error(
            "canary bundle/state digest mismatch",
            lambda: app_module._verified_policy_canary_bundle(state),
            409,
            "no longer matches state",
        )
    finally:
        app_module._write_policy_canary_bundle(bundle)
    original_state_bound = app_module._POLICY_CANARY_STATE_MAX_BYTES
    app_module._POLICY_CANARY_STATE_MAX_BYTES = 1
    try:
        expect_http_error(
            "oversize canary state",
            lambda: app_module._write_policy_canary_state(state),
            503,
            "size bound",
        )
    finally:
        app_module._POLICY_CANARY_STATE_MAX_BYTES = original_state_bound
    original_bundle_bound = app_module.MAX_POLICY_BUNDLE_BYTES
    app_module.MAX_POLICY_BUNDLE_BYTES = 1
    try:
        expect_http_error(
            "oversize canary bundle",
            lambda: app_module._write_policy_canary_bundle(bundle),
            503,
            "size bound",
        )
    finally:
        app_module.MAX_POLICY_BUNDLE_BYTES = original_bundle_bound


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
        os.environ["SERVERWARE_POLICY_CANARY_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import db, policy_bundle, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:publisher"
        identity = AdminIdentity(user_id, frozenset({"policy_publisher", "policy_author", "auditor"}), "admin-token-header")
        webauthn.create_dev_credential(user_id)
        credential = db.create_credential(
            "Canary demo",
            "bearer",
            "demo-token-from-vault",
            {"provider": "demo", "scopes": ["demo"]},
        )
        credential_id = credential["id"]
        initial = policy_bundle.write_policy_bundle(
            candidate_bundle(policy_bundle, 1, credential_id)
        )
        initial_high_water = policy_bundle.enforce_policy_high_water(initial)
        if initial_high_water["policy_hash"] != initial.hash:
            raise AssertionError(
                "default policy writer was not high-water idempotent"
            )
        active_before = policy_bundle.get_policy_snapshot()

        missing_credential_payload = app_module.PolicyCandidateRequest(
            bundle=candidate_bundle(policy_bundle, 2, "cred-does-not-exist"),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "candidate with missing stored credential",
            lambda: app_module.policy_candidate(
                missing_credential_payload, _=identity
            ),
            409,
            "credential cred-does-not-exist",
        )
        wrong_injection_credential = db.create_credential(
            "Wrong injection",
            "header",
            "demo-token-from-vault",
            {
                "provider": "demo",
                "scopes": ["demo"],
                "injection_name": "x-api-key",
            },
        )
        wrong_injection_payload = app_module.PolicyCandidateRequest(
            bundle=candidate_bundle(
                policy_bundle, 2, wrong_injection_credential["id"]
            ),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "candidate with incompatible stored injection",
            lambda: app_module.policy_candidate(
                wrong_injection_payload, _=identity
            ),
            409,
            "injection type",
        )

        full_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2, credential_id),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "direct full publish while canary is required",
            lambda: app_module.policy_publish(full_payload, identity=identity),
            412,
            "canary activation",
        )

        empty_status = app_module.policy_canary_status(_=identity)
        if empty_status != {"ok": True, "canary": None, "monitoring": None}:
            raise AssertionError(f"empty canary status was not idempotent: {empty_status}")

        exact_current_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 1, credential_id),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        expect_http_error(
            "exact-current canary staging",
            lambda: app_module.policy_publish(
                exact_current_payload,
                identity=identity,
            ),
            409,
            "policy_canary_candidate_already_active",
        )
        if app_module._read_policy_canary_state() is not None:
            raise AssertionError(
                "exact-current candidate synthesized canary state"
            )

        substituted_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2, credential_id),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        substituted_payload.mfa = {
            "assertion": sign_publish_assertion(
                app_module,
                webauthn,
                substituted_payload,
                user_id,
            )
        }
        original_start_policy_canary = app_module._start_policy_canary

        def substitute_after_approval(**kwargs: Any) -> dict[str, Any]:
            kwargs["payload"].bundle["metadata"]["sequence"] = 3
            return original_start_policy_canary(**kwargs)

        app_module._start_policy_canary = substitute_after_approval
        try:
            expect_http_error(
                "candidate substitution after approval",
                lambda: app_module.policy_publish(
                    substituted_payload,
                    identity=identity,
                ),
                409,
                "candidate or predecessor changed",
            )
        finally:
            app_module._start_policy_canary = original_start_policy_canary
        if app_module._read_policy_canary_state() is not None:
            raise AssertionError(
                "candidate substitution race wrote unapproved canary state"
            )

        canary_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2, credential_id),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        try:
            app_module.PolicyPublishRequest(
                bundle=candidate_bundle(policy_bundle, 2, credential_id),
                dryRun=[dry_run_case(app_module)],
                activationMode="canary",
                canaryPercent=10.0,
            )
        except Exception as exc:
            if type(exc).__name__ != "ValidationError":
                raise
        else:
            raise AssertionError("removed canary traffic percentage was still accepted")
        canary_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, canary_payload, user_id)}
        canary = app_module.policy_publish(canary_payload, identity=identity)
        canary_id = canary["canary"]["id"]
        candidate_hash = canary["candidate"]["policyHash"]
        if canary_id != app_module._policy_canary_id(
            candidate_hash,
            2,
            active_before.hash,
        ):
            raise AssertionError(
                "persisted canary identity did not bind full candidate and predecessor"
            )
        if canary.get("published") is not False or canary["policyHash"] != active_before.hash:
            raise AssertionError(f"canary publish activated the policy instead of staging it: {canary}")
        if not app_module.POLICY_CANARY_BUNDLE_PATH.exists():
            raise AssertionError("canary signed bundle was not written")
        verify_canary_file_security(app_module, policy_bundle)
        still_active = policy_bundle.get_policy_snapshot()
        if not still_active or still_active.hash != active_before.hash:
            raise AssertionError("active policy changed during canary start")

        db.record_audit_event(
            "data_plane.response.released",
            {
                "route_id": "demo.echo",
                "decision": "allow",
                "latency_ms": 12.5,
                "policy_hash": candidate_hash,
            },
            actor_id="decision-gate-rs",
        )
        db.record_audit_event(
            "data_plane.response.released",
            {
                "route_id": "demo.echo",
                "decision": "allow",
                "latency_ms": 1,
                "policy_hash": active_before.hash,
            },
            actor_id="decision-gate-rs",
        )
        db.record_audit_event(
            "data_plane.response.released",
            {
                "decision": "allow",
                "latency_ms": 2,
                "policy_hash": candidate_hash,
            },
            actor_id="decision-gate-rs",
        )
        status = app_module.policy_canary_status(_=identity)
        if (
            status["monitoring"]["auditEvents"] != 0
            or status["monitoring"]["candidateShadowEvaluationImplemented"]
            is not False
        ):
            raise AssertionError(
                f"baseline traffic was accepted as canary evidence: {status}"
            )
        unavailable_activation = app_module.PolicyCanaryActivationRequest(
            canaryId=canary_id
        )
        expect_http_error(
            "canary activation without shadow evaluator",
            lambda: app_module.policy_canary_activate(
                unavailable_activation,
                identity=identity,
            ),
            412,
            "policy_canary_shadow_evaluation_unavailable",
        )

        evidence = {
            "provenance_version": "serverware.candidate-shadow/v1",
            "canary_id": canary_id,
            "evaluation_mode": "candidate_shadow",
            "candidate_evaluated": True,
            "active_policy_hash": active_before.hash,
            "candidate_policy_hash": candidate_hash,
            "route_id": "demo.echo",
            "request_digest": "sha256:" + "4" * 64,
            "active_decision": "allow",
            "candidate_decision": "allow",
            "candidate_latency_ms": 12.5,
            "measurement_digest": "sha256:" + "2" * 64,
        }
        evidence["evidence_id"] = app_module._policy_canary_evidence_identity(
            evidence
        )
        db.record_audit_event(
            "policy.canary.shadow.evaluated",
            evidence,
            actor_id="decision-gate-rs",
        )
        db.record_audit_event(
            "policy.canary.shadow.evaluated",
            evidence,
            actor_id="decision-gate-rs",
        )
        second_untrusted = dict(evidence)
        second_untrusted["request_digest"] = "sha256:" + "5" * 64
        second_untrusted["evidence_id"] = (
            app_module._policy_canary_evidence_identity(second_untrusted)
        )
        db.record_audit_event(
            "policy.canary.shadow.evaluated",
            second_untrusted,
            actor_id="decision-gate-rs",
        )
        status = app_module.policy_canary_status(_=identity)
        monitoring = status["monitoring"]
        if (
            monitoring["candidateShadowEvaluationImplemented"] is not False
            or monitoring["auditEvents"] != 0
            or monitoring["untrustedEvidenceRows"] != 2
            or monitoring["duplicateEvidenceRows"] != 1
            or monitoring["coveredRoutes"]
            or monitoring["routeCoverageComplete"] is not False
            or "demo.echo" not in monitoring["requiredRouteCoverage"]
        ):
            raise AssertionError(
                "caller-fabricated or duplicate audit rows gained canary authority: "
                f"{status}"
            )
        coverage_state = dict(app_module._read_policy_canary_state() or {})
        coverage_state["diff"] = {
            "routes": {
                "added": [],
                "changed": ["demo.echo", "demo.second"],
                "removed": [],
            }
        }
        coverage_monitor = app_module._policy_canary_monitor(coverage_state)
        if (
            coverage_monitor["requiredRouteCoverage"]
            != ["demo.echo", "demo.second"]
            or coverage_monitor["routeCoverageComplete"] is not False
        ):
            raise AssertionError(
                "repeated one-route rows satisfied multi-route canary coverage"
            )
        expect_http_error(
            "well-shaped direct database evidence",
            lambda: app_module.policy_canary_activate(
                unavailable_activation,
                identity=identity,
            ),
            412,
            "policy_canary_shadow_evaluation_unavailable",
        )
        audits = db.list_audit_events(limit=50)
        if any(
            item["event_type"]
            in {"policy.canary.activated", "policy.published"}
            for item in audits
        ):
            raise AssertionError(
                "untrusted canary evidence synthesized activation audit records"
            )

        first_prefix_hash = "sha256:" + "a" * 64
        colliding_prefix_hash = "sha256:" + "a" * 16 + "b" * 48
        collision_id = app_module._policy_canary_id(
            first_prefix_hash,
            2,
            active_before.hash,
        )
        if collision_id == app_module._policy_canary_id(
            colliding_prefix_hash,
            2,
            active_before.hash,
        ):
            raise AssertionError("canary identity used only a candidate hash prefix")
        if collision_id == app_module._policy_canary_id(
            first_prefix_hash,
            2,
            "sha256:" + "f" * 64,
        ):
            raise AssertionError("canary identity omitted its exact predecessor")
        ceremony_digest = app_module._policy_publication_ceremony_payload_digest(
            canary_payload,
            candidate_policy_hash=first_prefix_hash,
            previous_policy_hash=active_before.hash,
            candidate_bundle_sha256="sha256:" + "c" * 64,
        )
        if ceremony_digest == (
            app_module._policy_publication_ceremony_payload_digest(
                canary_payload,
                candidate_policy_hash=colliding_prefix_hash,
                previous_policy_hash=active_before.hash,
                candidate_bundle_sha256="sha256:" + "c" * 64,
            )
        ):
            raise AssertionError(
                "approval digest used only a candidate hash prefix"
            )
        if ceremony_digest == (
            app_module._policy_publication_ceremony_payload_digest(
                canary_payload,
                candidate_policy_hash=first_prefix_hash,
                previous_policy_hash="sha256:" + "f" * 64,
                candidate_bundle_sha256="sha256:" + "c" * 64,
            )
        ):
            raise AssertionError("approval digest omitted its exact predecessor")
        if ceremony_digest == (
            app_module._policy_publication_ceremony_payload_digest(
                canary_payload,
                candidate_policy_hash=first_prefix_hash,
                previous_policy_hash=active_before.hash,
                candidate_bundle_sha256="sha256:" + "d" * 64,
            )
        ):
            raise AssertionError("approval digest omitted the full signed-bundle digest")

        cancelled_initial = app_module.policy_canary_cancel(
            app_module.PolicyCanaryCancelRequest(
                canaryId=canary_id,
                note="authenticated candidate shadow is unavailable",
            ),
            identity=identity,
        )
        if cancelled_initial["canary"]["status"] != "cancelled":
            raise AssertionError("unavailable canary could not be cancelled")

        active_bundle = json.loads(json.dumps(active_before.raw))
        active_metadata = active_bundle["metadata"]
        exact_current_canary_id = app_module._policy_canary_id(
            active_before.hash,
            active_metadata["sequence"],
            active_before.hash,
        )
        app_module._write_policy_canary_bundle(active_bundle)
        app_module._write_policy_canary_state(
            {
                "version": "serverware.policyCanary/v1",
                "id": exact_current_canary_id,
                "status": "running",
                "policy_id": active_metadata["id"],
                "previous_policy_hash": active_before.hash,
                "candidate_policy_hash": active_before.hash,
                "candidate_sequence": active_metadata["sequence"],
                "candidate_rollback_epoch": active_metadata["rollbackEpoch"],
                "started_at": app_module._now_iso(),
                "candidate_bundle_sha256": (
                    app_module._policy_canary_bundle_digest(active_bundle)
                ),
                "candidate_route_ids": ["demo.echo"],
            }
        )
        expect_http_error(
            "legacy exact-current canary activation",
            lambda: app_module.policy_canary_activate(
                app_module.PolicyCanaryActivationRequest(
                    canaryId=exact_current_canary_id
                ),
                identity=identity,
            ),
            409,
            "policy_canary_candidate_already_active",
        )
        original_get_policy_snapshot = app_module.get_policy_snapshot
        original_policy_canary_authority_hash = (
            app_module._policy_canary_authority_hash
        )
        app_module.get_policy_snapshot = lambda: None
        app_module._policy_canary_authority_hash = lambda: active_before.hash
        try:
            expect_http_error(
                "durable-authority exact-current canary activation",
                lambda: app_module.policy_canary_activate(
                    app_module.PolicyCanaryActivationRequest(
                        canaryId=exact_current_canary_id
                    ),
                    identity=identity,
                ),
                409,
                "policy_canary_candidate_already_active",
            )
        finally:
            app_module.get_policy_snapshot = original_get_policy_snapshot
            app_module._policy_canary_authority_hash = (
                original_policy_canary_authority_hash
            )
        exact_current_state = app_module._read_policy_canary_state()
        if (
            exact_current_state is None
            or exact_current_state.get("status") != "running"
            or exact_current_state.get("activated_at") is not None
        ):
            raise AssertionError(
                "exact-current activation synthesized activated canary evidence"
            )
        app_module.policy_canary_cancel(
            app_module.PolicyCanaryCancelRequest(
                canaryId=exact_current_canary_id,
                note="exact-current no-op fixture",
            ),
            identity=identity,
        )

        active_before_start_race = policy_bundle.get_policy_snapshot()
        if active_before_start_race is None:
            raise AssertionError("canary start race had no active policy")
        active_bytes_before_start_race = app_module.POLICY_BUNDLE_PATH.read_bytes()
        high_water_before_start_race = db.get_policy_high_water()
        first_start_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 4, credential_id),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        second_start_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 5, credential_id),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        original_mutation_webauthn_required = (
            app_module.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED
        )
        app_module.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED = False
        first_start_holds_lock = threading.Event()
        release_first_start = threading.Event()
        second_start_attempted_lock = threading.Event()
        original_write_canary_bundle = app_module._write_policy_canary_bundle
        start_results: dict[str, Any] = {}

        def block_first_canary_write(bundle: dict[str, Any]) -> None:
            if threading.current_thread().name == "first-canary-starter":
                first_start_holds_lock.set()
                if not release_first_start.wait(timeout=5):
                    raise AssertionError("timed out holding first canary start lock")
            original_write_canary_bundle(bundle)

        def start_first_canary() -> None:
            try:
                start_results["first"] = app_module.policy_publish(
                    first_start_payload, identity=identity
                )
            except BaseException as exc:
                start_results["first_error"] = exc

        def start_second_canary() -> None:
            second_start_attempted_lock.set()
            try:
                start_results["second"] = app_module.policy_publish(
                    second_start_payload, identity=identity
                )
            except BaseException as exc:
                start_results["second_error"] = exc

        app_module._write_policy_canary_bundle = block_first_canary_write
        first_start_thread = threading.Thread(
            target=start_first_canary, name="first-canary-starter"
        )
        second_start_thread = threading.Thread(
            target=start_second_canary, name="second-canary-starter"
        )
        try:
            first_start_thread.start()
            if not first_start_holds_lock.wait(timeout=5):
                raise AssertionError("first canary start did not hold the shared lock")
            second_start_thread.start()
            if not second_start_attempted_lock.wait(timeout=5):
                raise AssertionError("second canary start did not attempt the transition")
            second_start_thread.join(timeout=0.1)
            if not second_start_thread.is_alive():
                raise AssertionError("concurrent canary starts were not serialized")
            release_first_start.set()
            first_start_thread.join(timeout=10)
            second_start_thread.join(timeout=10)
        finally:
            release_first_start.set()
            app_module.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED = (
                original_mutation_webauthn_required
            )
            app_module._write_policy_canary_bundle = original_write_canary_bundle
        if first_start_thread.is_alive() or second_start_thread.is_alive():
            raise AssertionError("concurrent canary starts did not terminate")
        if (
            start_results.get("first_error") is not None
            or start_results.get("first", {}).get("published") is not False
        ):
            raise AssertionError(f"first canary start did not commit: {start_results}")
        second_start_error = start_results.get("second_error")
        if (
            getattr(second_start_error, "status_code", None) != 409
            or "already" not in str(getattr(second_start_error, "detail", ""))
        ):
            raise AssertionError(
                f"second serialized canary start was not rejected: {start_results}"
            )
        final_running = app_module.policy_canary_status(_=identity)
        if (
            final_running["canary"]["status"] != "running"
            or final_running["canary"]["id"]
            != start_results["first"]["canary"]["id"]
        ):
            raise AssertionError(
                f"concurrent canary starts overwrote running state: {final_running}"
            )
        active_after_start_race = policy_bundle.get_policy_snapshot()
        high_water_after_start_race = db.get_policy_high_water()
        persisted_canary_state = json.loads(
            app_module.POLICY_CANARY_STATE_PATH.read_text(encoding="utf-8")
        )
        if (
            active_after_start_race is None
            or active_after_start_race.hash != active_before_start_race.hash
            or app_module.POLICY_BUNDLE_PATH.read_bytes()
            != active_bytes_before_start_race
            or high_water_after_start_race != high_water_before_start_race
            or persisted_canary_state.get("candidate_policy_hash")
            != start_results["first"]["candidate"]["policyHash"]
        ):
            raise AssertionError(
                "serialized canary lost-update fixture changed active policy, "
                "high-water state, or the winning candidate"
            )

        final_cancel = app_module.PolicyCanaryCancelRequest(
            canaryId=final_running["canary"]["id"], note="serialized cleanup"
        )
        cancelled = app_module.policy_canary_cancel(final_cancel, identity=identity)
        if cancelled["canary"]["status"] != "cancelled":
            raise AssertionError(f"canary cancel did not update state: {cancelled}")
        cancelled_activation = app_module.PolicyCanaryActivationRequest(
            canaryId=final_running["canary"]["id"]
        )
        expect_http_error(
            "activate cancelled canary",
            lambda: app_module.policy_canary_activate(cancelled_activation, identity=identity),
            409,
            "cancelled",
        )

    print(json.dumps({"ok": True, "policy_canary_workflow": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
