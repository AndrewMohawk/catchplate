#!/usr/bin/env python3
"""Bounded ordinary-app component checks in an already isolated Linux container.

No dependency installation, image pull/build, browser, SDK, deployment or live
checker is performed here. Provision requirements.lock and the standalone
examples/managed-client/requirements.lock separately; neither is installed here.
Execution requires a network namespace containing only loopback; local HTTP
fixtures still work. Mount source and dependencies read-only, drop capabilities,
and supply a fresh writable result parent (see ordinary-regression.yml).

Logs are projected to test identifiers, traceback locations and exception types.
Arbitrary exception messages/streams are never persisted or printed. Exit status,
timeouts, output overflow and a raw-stream digest remain visible, not suppressed.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_SECONDS = 900
MAX_PARTITION_SECONDS = 600
PARTITIONS = ("all", "python-1", "python-2", "python-3", "node")
# Fixed source boundaries, not timing-dependent discovery. Historical hosted
# observations were roughly 335/277/308s, before two new direct suites per shard.
# The last includes an incomplete notification run; these are not acceptance.
PYTHON_PARTITION_BOUNDARIES = ("test_operator_workload_renewal.py", "test_native_jit_prepare.py")
MAX_OUTPUT_BYTES = 100 * 1024
SCHEMA = "serverware.ordinaryRegression/v1"
EXCLUDED = ("rendered_browser", "stock_sdk", "rust_data_plane", "live_deployment", "native_admission")


@dataclass(frozen=True)
class Suite:
    category: str
    script: str
    runtime: str = "python"
    arguments: tuple[str, ...] = ()
    seconds: int = 240


# Deliberately reviewed, not wildcard discovery. A missing entry is a failure.
# Several files named *_browser use an inert DOM; none below launches Chromium.
SUITES = (
    Suite("backend", "test_authority_api_classification.py", seconds=60),
    Suite("backend", "test_operator_demo_runtime.py"),
    Suite("backend", "test_operator_workspace_api.py"),
    Suite("backend", "test_approval_capabilities_http.py", seconds=120),
    Suite("backend", "test_authority_jit_review_receipt.py", seconds=60),
    Suite("backend", "test_operator_workload_renewal_contract.py", seconds=60),
    Suite("backend", "test_proxy_managed_renewal.py", seconds=60),
    Suite("backend", "test_operator_workload_renewal_store.py"),
    Suite("backend", "test_operator_workload_renewal_api.py", seconds=60),
    # Direct shared-fixture controls are distributed across the fixed shards;
    # importing these fixtures from another suite does not test their methods.
    Suite("backend", "test_authority_index_join.py", seconds=60),
    Suite("backend", "test_authority_indexed_mutation.py", seconds=60),
    Suite("backend", "test_operator_workload_renewal.py"),
    Suite("backend", "test_managed_client.py", seconds=60),
    Suite("backend", "test_operator_managed_helper_connected.py", seconds=60),
    Suite("backend", "test_operator_catalog_body_routing.py"),
    Suite("backend", "test_operator_catalog_header_replacement.py"),
    Suite("backend", "test_jit_denial_api.py", seconds=60),
    Suite("backend", "test_native_jit_decision_fences_http.py", seconds=60),
    Suite("backend", "test_runtime_grant_publication.py", seconds=60),
    Suite("backend", "test_authority_jit_denial.py", seconds=60),
    Suite("backend", "test_authority_jit_approval.py", seconds=60),
    Suite("backend", "test_authority_jit_request.py", seconds=60),
    # Synthetic request/AEAD/owner components only; no native admission or
    # real broker, hardware, protected approval, or provider is exercised.
    Suite("backend", "test_authority_jit_private_request.py", seconds=60),
    Suite("backend", "test_native_jit_review_material.py", seconds=60),
    Suite("backend", "test_native_jit_review_owner.py", seconds=60),
    # Real crypto with synthetic keys/quotes; loader stops before native admission.
    Suite("backend", "test_authority_native_jit_review_custody.py", seconds=60),
    Suite("backend", "test_authority_native_jit_review_registration.py", seconds=60),
    Suite("backend", "test_authority_transition_registry.py", seconds=60),
    # Fixed schema and privilege-source contracts are ordinary regression gates;
    # these pure controls do not assert PostgreSQL or native-role acceptance.
    Suite("backend", "test_authority_schema_source.py", seconds=60),
    Suite("backend", "test_authority_verifier_read_source.py", seconds=60),
    Suite("backend", "test_authority_table_acl_source.py", seconds=60),
    Suite("backend", "test_authority_revocation_proof_bundle.py", seconds=180),
    # Protected review components use synthetic authority/launch observations;
    # none establishes native admission, a database commit or private disclosure.
    # Root-owned FD metadata tests have a separate isolated root-only lane.
    Suite("backend", "test_native_jit_review_open_owner.py", seconds=60),
    Suite("backend", "test_authority_native_jit_review_current_chunks.py", seconds=60),
    Suite("backend", "test_authority_native_jit_review_current_read.py", seconds=60),
    Suite("backend", "test_authority_native_jit_review_open.py", seconds=60),
    Suite("backend", "test_authority_native_jit_review_plan.py", seconds=60),
    Suite("backend", "test_authority_native_jit_review_plan_replay.py", seconds=180),
    Suite("backend", "test_authority_launcher_native_review_credentials.py", seconds=60),
    Suite("backend", "test_native_jit_review_portal.py", seconds=60),
    # Synthetic pending, writer-boundary, legacy-reader and ASGI controls only;
    # no native startup, PostgreSQL transaction or provider acceptance.
    Suite("backend", "test_authority_native_jit_pending.py", seconds=60),
    Suite("backend", "test_authority_native_jit_executor_retention.py", seconds=60),
    Suite("backend", "test_native_jit_legacy_reader.py", seconds=60),
    Suite("backend", "test_native_jit_sqlite_bootstrap.py", seconds=60),
    Suite("backend", "test_authority_native_jit_submission.py", seconds=60),
    Suite("backend", "test_authority_native_jit_retained_history.py", seconds=60),
    Suite("backend", "test_native_jit_submission_http.py", seconds=60),
    Suite("backend", "test_authority_release_private_input.py", seconds=60),
    Suite("backend", "test_authority_release_private_request.py", seconds=60),
    Suite("backend", "test_authority_release_private_ingress.py", seconds=60),
    Suite("backend", "test_authority_complete_query_batch.py", seconds=60),
    Suite("backend", "test_authority_counted_root_transition.py", seconds=60),
    Suite("backend", "test_native_jit_prepare.py", seconds=60),
    Suite("backend", "test_authority_complete_read_write.py", seconds=60),
    Suite("backend", "test_authority_revocation_read_write.py", seconds=60),
    Suite("backend", "test_approval_history_metadata.py", seconds=60),
    Suite("backend", "test_operator_catalog_npm_install.py"),
    Suite("backend", "test_github_app.py"),
    Suite("backend", "test_operator_catalog_github_app.py"),
    Suite("backend", "test_operator_github_app_key_replacement.py"),
    Suite("backend", "test_operator_github_app_lease.py"),
    Suite("backend", "test_github_app_secret_boundary.py"),
    Suite("backend", "test_operator_x_accounts_api.py"),
    Suite("backend", "test_operator_x_transport.py"),
    Suite("backend", "test_operator_x_refresh.py"),
    Suite("backend", "test_operator_x_lease_reconciliation.py"),
    Suite("backend", "test_operator_x_lease_boundary.py"),
    Suite("backend", "test_operator_x_secret_boundary.py"),
    Suite("backend", "test_operator_x_readiness.py"),
    Suite("backend", "test_operator_catalog_x_post.py"),
    Suite("backend", "test_operator_x_quota.py"),
    Suite("backend", "test_operator_x_quota_api.py"),
    Suite("backend", "test_operator_x_post_profiles.py", seconds=60),
    Suite("backend", "test_operator_x_post_fixture.py", seconds=60),
    Suite("backend", "test_operator_x_quota_fixture.py", seconds=60),
    Suite("backend", "test_operator_x_post_checker.py", seconds=60),
    Suite("backend", "test_operator_x_quota_checker.py", seconds=60),
    Suite("backend", "test_operator_x_quota_fault_relay.py", arguments=("--loopback",), seconds=60),
    Suite("backend", "test_operator_x_quota_fault_fixture.py", seconds=60),
    Suite("backend", "test_operator_x_quota_fault_checker.py", seconds=60),
    Suite("backend", "test_prepare_operator_x_post_fixture.py", seconds=60),
    Suite("backend", "test_prepare_operator_python_bytecode.py", seconds=60),
    Suite("backend", "test_run_operator_x_post_fixture.py", seconds=60),
    Suite("backend", "test_operator_rollout_x_quota.py", seconds=60),
    Suite("backend", "test_operator_rollout_snapshot.py", seconds=60),
    # Inert copied-state harness controls only; no retained state or Docker access.
    Suite("backend", "test_operator_source_revision_retained.py", seconds=60),
    Suite("backend", "test_operator_source_revision_retained_host.py", seconds=60),
    Suite("backend", "test_operator_guided_checker.py", seconds=60),
    Suite("backend", "test_operator_guided_fixture.py", seconds=60),
    Suite("backend", "test_operator_public_proxy.py", seconds=60),
    Suite("backend", "test_operator_public_proxy_control.py", seconds=60),
    Suite("notifications", "test_operator_notification_events.py"),
    Suite("notifications", "test_operator_notification_google_events.py"),
    Suite("notifications", "test_operator_notification_google_integration.py"),
    Suite("notifications", "test_operator_notification_provider_integration.py"),
    Suite("ui_contract", "test_operator_catalog_assets.py", seconds=60),
    Suite("ui_contract", "test_operator_catalog_browser.cjs", "node", ("--self-test",), 60),
    Suite("ui_contract", "test_operator_guided_browser.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_npm_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_npm_publish_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_npm_install_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_github_app_ui.mjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_gmail_sdk_languages.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_x_accounts_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_x_configuration_ui.mjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_x_quota_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_runtime_browser_assets.cjs", "node", seconds=60),
    Suite("ui_contract", "test_approval_decision_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_workload_renewal_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_pending_actions_ui.cjs", "node", seconds=60),
    Suite("ui_contract", "test_native_jit_review_portal.cjs", "node", seconds=60),
    Suite("ui_contract", "test_operator_auth_state_ui.cjs", "node", seconds=60),
)


class Refused(ValueError):
    """Only fixed public reason codes may leave preflight."""


def partition_suites(partition):
    """One deterministic partition of the complete reviewed source roster."""
    if type(partition) is not str or partition not in PARTITIONS:
        raise Refused("invalid_partition")
    if not SUITES or len({suite.script for suite in SUITES}) != len(SUITES) \
            or any(suite.runtime not in {"python", "node"} for suite in SUITES):
        raise Refused("invalid_suite_roster")
    if partition == "all":
        return SUITES, MAX_SECONDS
    if partition == "node":
        selected = tuple(suite for suite in SUITES if suite.runtime == "node")
    else:
        python = tuple(suite for suite in SUITES if suite.runtime == "python")
        names = tuple(suite.script for suite in python)
        if any(boundary not in names for boundary in PYTHON_PARTITION_BOUNDARIES):
            raise Refused("partition_boundary_missing")
        boundaries = tuple(names.index(boundary) + 1 for boundary in PYTHON_PARTITION_BOUNDARIES)
        if boundaries[0] >= boundaries[1]:
            raise Refused("partition_boundary_order")
        cuts = (0, *boundaries, len(python))
        index = ("python-1", "python-2", "python-3").index(partition)
        selected = python[cuts[index]:cuts[index + 1]]
    if not selected:
        raise Refused("empty_partition")
    return selected, MAX_PARTITION_SECONDS


def require_offline_network():
    if sys.platform != "linux":
        raise Refused("linux_network_namespace_required")
    try:
        interfaces = {p.name for p in Path("/sys/class/net").iterdir()}
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    except OSError:
        raise Refused("network_namespace_unobservable") from None
    if interfaces != {"lo"} or any(row.split()[0] != "lo" for row in routes if row.strip()) \
            or any(row.split()[-1] != "lo" for row in routes6 if row.strip()):
        raise Refused("network_none_required")


def executable(value):
    path = Path(value).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise Refused("runtime_unavailable")
    return str(path)


def environment(root, scratch, python, node, dependencies=None):
    paths = [str(root), str(root / "scripts")]
    if dependencies is not None:
        paths.append(str(dependencies))
    # Do not inherit tokens, proxy variables, cloud credentials, PYTHONSTARTUP,
    # NODE_OPTIONS, user caches or the caller's live data directory.
    return {"PATH": os.pathsep.join(dict.fromkeys((str(Path(python).parent), str(Path(node).parent),
                "/usr/local/bin", "/usr/bin", "/bin"))), "LANG": "C.UTF-8",
        "HOME": str(scratch), "TMPDIR": str(scratch), "PYTHONPATH": os.pathsep.join(paths),
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "SERVERWARE_TEST_PYTHON": python, "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
        "SERVERWARE_RELEASE_CHANNEL": "dev", "SERVERWARE_DATA_DIR": str(scratch / "data")}


def unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def node_failure(script, raw):
    """Only this reviewed suite emits a closed, numeric failure receipt."""
    if script != "test_operator_github_app_ui.mjs":
        return None
    lines = raw.splitlines()
    if not lines or not 0 < len(lines[-1]) <= 512:
        return None
    try:
        value = json.loads(lines[-1].decode("utf-8"), object_pairs_hook=unique_json_object)
    except (ValueError, UnicodeError):
        return None
    if type(value) is not dict or set(value) != {"ok", "group", "frames"} or value["ok"] is not False \
            or type(value["group"]) is not int or not 0 <= value["group"] <= 10000 \
            or type(value["frames"]) is not list or len(value["frames"]) > 5:
        return None
    if any(type(frame) is not list or len(frame) != 2 or any(
            type(number) is not int or not 1 <= number <= 9999999 for number in frame)
            for frame in value["frames"]):
        return None
    return {"script": "test_operator_github_app_ui.mjs", "group": value["group"],
        "frames": [{"line": line, "column": column} for line, column in value["frames"]]}


def diagnostics(raw, *, completion_script=None):
    """Closed structural diagnostics, not a blacklist of possible secret values."""
    text = raw.decode("utf-8", "replace")
    failures = re.findall(r"^(?:FAIL|ERROR): (test_[A-Za-z0-9_]+)(?:\s|$)", text, re.M)
    frames = [{"file": Path(name).name, "line": int(line)}
        for name, line in re.findall(r'^\s*File "([^"\n]+\.(?:py|mjs|cjs|js))", line ([0-9]{1,7})', text, re.M)]
    frames += [{"file": Path(name).name, "line": int(line)} for name, line in
        re.findall(r"(?:\(|\s)([^\s()]+\.(?:cjs|mjs|js)):([0-9]{1,7}):[0-9]+", text)]
    exceptions = re.findall(r"^([A-Za-z][A-Za-z0-9_.]*(?:Error|Exception))(?::|$)", text, re.M)
    totals = re.findall(r"^Ran ([0-9]+) tests? in [0-9.]+s$", text, re.M)
    skips = re.findall(r"^(?:OK|FAILED) \([^\n]*\bskipped=([0-9]+)[^\n]*\)$", text, re.M)
    result = {"failedTests": list(dict.fromkeys(failures))[:64], "frames": frames[-64:],
        "exceptionTypes": list(dict.fromkeys(exceptions))[:32],
        "observedUnittestCounts": [int(v) for v in totals[-32:]],
        "observedSkippedTests": sum(int(v) for v in skips),
        "outputBytes": len(raw), "outputSha256": hashlib.sha256(raw).hexdigest()}
    failure = node_failure(completion_script, raw)
    if failure is not None:
        result["observedNodeFailure"] = failure
    return result


def child_exit_status(process):
    """Keep our leader PID reserved until group cleanup, including pipe orphans."""
    if type(process.pid) is not int or process.pid <= 1 or process.returncode is not None:
        raise Refused("child_ownership_unavailable")
    try:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        raise Refused("child_ownership_unavailable") from None
    if result is None:
        return None
    if result.si_pid != process.pid or result.si_code not in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}:
        raise Refused("child_exit_observation_invalid")
    return result.si_status if result.si_code == os.CLD_EXITED else -result.si_status


def stop_group(process):
    # Never poll/wait before this ownership check: reaping would release the ID.
    child_exit_status(process)
    try:
        if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid \
                or process.pid == os.getpgrp():
            raise Refused("child_group_ownership_differs")
    except ProcessLookupError:
        raise Refused("child_group_ownership_unavailable") from None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        # An unreaped owned zombie can have no live group members left.
        pass
    process.wait(timeout=5)


def node_completion(script, raw):
    """Admit the actual terminal output contract, without historical test counts."""
    common = {"ok": True, "browser": False, "network": False, "generated_recipe_executed": False}
    shapes = {
        "test_operator_catalog_browser.cjs": {"ok": True,
            "scope": "pure exported client command generator; no browser or requests"},
        "test_operator_guided_browser.cjs": {"ok": True, "browser": False, "network": False,
            "providerRequests": 0, "scope": "pure guided browser protocol and private download controls"},
        "test_operator_npm_ui.cjs": {**common,
            "scope": "public catalog, inert DOM connect/download handlers, npm recipe and source-pin joins; not browser or provider acceptance"},
        "test_operator_npm_publish_ui.cjs": common,
        "test_operator_npm_install_ui.cjs": common,
        "test_operator_github_app_ui.mjs": {"ok": True, "network": False, "browser": False, "provider": False,
            "scope": "actual UI functions and core mutation; inert DOM and independent in-memory API, not provider acceptance"},
        "test_operator_gmail_sdk_languages.cjs": {"ok": True, "browser": False, "sdk": False,
            "providerRequests": 0, "scope": "pure UI helper and inert local shell stubs"},
        "test_operator_x_accounts_ui.cjs": {"ok": True, "browser": False, "network": False,
            "scope": "actual public UI helpers and controller with inert DOM; no provider or backend acceptance"},
        "test_operator_x_configuration_ui.mjs": {"ok": True, "browser": False, "network": False,
            "scope": "actual JS with inert DOM and independent synthetic API DTOs; not backend, browser or provider acceptance"},
        "test_operator_x_quota_ui.cjs": {"ok": True, "browser": False, "network": False,
            "scope": "shared X posting-attempt quota UI contracts; no backend or enforcement acceptance"},
        "test_approval_decision_ui.cjs": {"ok": True, "browser": False, "network": False,
            "scope": "actual approval UI functions with inert DOM and synthetic API/WebAuthn; not browser or protected authority acceptance"},
        "test_operator_workload_renewal_ui.cjs": {"ok": True, "browser": False, "network": False,
            "source": "closed renewal DTO and inert DOM only"},
        "test_operator_pending_actions_ui.cjs": {"ok": True, "backendAcceptance": False,
            "nativeReviewAcceptance": False,
            "scope": "public queue module with inert DOM and synthetic GET responses"},
        "test_native_jit_review_portal.cjs": {"ok": True, "synthetic": True,
            "nativeAdmission": False, "providerRequests": False},
        "test_operator_auth_state_ui.cjs": {"ok": True,
            "scope": "actual workspace, notification and audit controllers; inert DOM and synthetic deferred GETs, not browser or backend acceptance"},
    }
    try:
        lines = raw.decode("utf-8").splitlines()
        if not lines:
            return None
        if script == "test_operator_runtime_browser_assets.cjs":
            match = re.fullmatch(r"PASS ([1-9][0-9]*) pure runtime-browser asset groups; no browser or service calls", lines[-1])
            count = int(match[1]) if match else 0
        else:
            expected = shapes[script]
            if script == "test_operator_pending_actions_ui.cjs":
                expected = {**expected, "sourceSha256": hashlib.sha256(
                    (ROOT / "serverware/operator_demo_web/workspace_pending_actions.js").read_bytes()).hexdigest()}
            result = json.loads(lines[-1], object_pairs_hook=unique_json_object)
            if type(result) is not dict or set(result) != set(expected) | {"groups"} \
                    or any(type(result[key]) is not type(value) or result[key] != value for key, value in expected.items()):
                return None
            count = result["groups"]
        if type(count) is not int or not 0 < count <= 10000:
            return None
        if script in {"test_operator_catalog_browser.cjs", "test_operator_gmail_sdk_languages.cjs"}:
            return count if len(lines) == 1 else None
        return count if len(lines) - 1 == count and all(line.startswith("PASS ") for line in lines[:-1]) else None
    except (OSError, ValueError, KeyError, UnicodeError):
        return None


def run_process(command, *, cwd, env, seconds, completion_script=None):
    began = time.monotonic()
    raw = bytearray()
    outcome = "passed"
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout, selectors.EVENT_READ)
            while poll.get_map():
                remaining = seconds - (time.monotonic() - began)
                if remaining <= 0:
                    outcome = "timeout"
                    break
                for key, _ in poll.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, min(8192, MAX_OUTPUT_BYTES + 1 - len(raw)))
                    if not chunk:
                        poll.unregister(key.fileobj)
                    else:
                        raw.extend(chunk)
                if len(raw) > MAX_OUTPUT_BYTES:
                    outcome = "output_limit"
                    break
            if outcome == "passed":
                while True:
                    code = child_exit_status(process)
                    if code is not None:
                        if code != 0:
                            outcome = "failed"
                        break
                    remaining = seconds - (time.monotonic() - began)
                    if remaining <= 0:
                        outcome = "timeout"
                        break
                    time.sleep(min(0.01, remaining))
    finally:
        try:
            stop_group(process)
        finally:
            process.stdout.close()
    detail = diagnostics(bytes(raw), completion_script=completion_script)
    if outcome == "passed" and detail["observedSkippedTests"]:
        outcome = "required_tests_skipped"
    if completion_script is not None:
        detail["observedNodeGroups"] = node_completion(completion_script, bytes(raw))
        if outcome == "passed" and detail["observedNodeGroups"] is None:
            outcome = "node_completion_unobserved"
    return {"status": outcome, "exitCode": process.returncode,
        "elapsedSeconds": round(time.monotonic() - began, 3), **detail}


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def run(args):
    suites, maximum_seconds = partition_suites(args.partition)
    require_offline_network()  # Before children, output creation, or fixture state.
    python = executable(args.python)
    node = executable(args.node or shutil.which("node") or "")
    dependencies = args.dependency_root.resolve(strict=True) if args.dependency_root else None
    if dependencies is not None and not dependencies.is_dir():
        raise Refused("dependency_root_unavailable")
    for suite in SUITES:
        path = ROOT / "scripts" / suite.script
        if path.is_symlink() or not path.is_file():
            raise Refused("mandatory_suite_unavailable")
    output = args.output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise Refused("fresh_output_required")
    output.mkdir(mode=0o700)
    began = time.monotonic()
    rows = []
    for index, suite in enumerate(suites):
        remaining = maximum_seconds - (time.monotonic() - began)
        row = {"category": suite.category, "script": suite.script, "arguments": list(suite.arguments),
            "sourceSha256": hashlib.sha256((ROOT / "scripts" / suite.script).read_bytes()).hexdigest()}
        if remaining <= 0:
            row.update(status="not_run_budget", exitCode=None)
        else:
            with tempfile.TemporaryDirectory(prefix="ordinary-case-") as directory:
                scratch = Path(directory)
                command = [python, "-B"] if suite.runtime == "python" else [node]
                command += [str(ROOT / "scripts" / suite.script), *suite.arguments]
                row.update(run_process(command, cwd=ROOT,
                    env=environment(ROOT, scratch, python, node, dependencies),
                    seconds=min(suite.seconds, remaining),
                    completion_script=suite.script if suite.runtime == "node" else None))
                if suite.runtime == "python" and row["status"] == "passed" \
                        and not any(row.get("observedUnittestCounts", ())):
                    row["status"] = "unittest_execution_unobserved"
        rows.append(row)
        save(output / f"{index:02d}.json", row)
        print(json.dumps({"script": suite.script, "status": row["status"],
            "exitCode": row["exitCode"]}), flush=True)
    result = {"schema": SCHEMA, "success": all(row["status"] == "passed" for row in rows),
        "partition": args.partition, "totalSuiteCount": len(SUITES),
        "suiteRosterSha256": hashlib.sha256(json.dumps([
            {"category": suite.category, "script": suite.script, "runtime": suite.runtime,
                "arguments": list(suite.arguments), "seconds": suite.seconds}
            for suite in SUITES], sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest(),
        "scope": "ordinary-app offline component regressions", "network": "loopback-only",
        "sourceRoot": str(ROOT), "requirementsSha256": hashlib.sha256((ROOT / "requirements.lock").read_bytes()).hexdigest(),
        "managedClientRequirementsSha256": hashlib.sha256((ROOT / "examples" / "managed-client" / "requirements.lock").read_bytes()).hexdigest(),
        "elapsedSeconds": round(time.monotonic() - began, 3), "maximumSeconds": maximum_seconds,
        "maximumOutputBytesPerSuite": MAX_OUTPUT_BYTES, "suites": rows,
        "notExecuted": list(EXCLUDED), "productionAcceptance": False}
    save(output / "result.json", result)
    print(json.dumps({"success": result["success"], "partition": args.partition,
        "suites": len(rows), "notExecuted": list(EXCLUDED)}))
    return 0 if result["success"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--node")
    parser.add_argument("--dependency-root", type=Path)
    parser.add_argument("--partition", choices=PARTITIONS, default="all",
        help="fixed CI partition (600s each), or the complete roster (default, 900s)")
    parser.add_argument("--output", type=Path, required=True, help="new directory in a private writable parent")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        return run(args)
    except (OSError, Refused) as error:
        reason = str(error) if isinstance(error, Refused) else "orchestration_io_failed"
        print(json.dumps({"success": False, "status": "preflight_or_orchestration_failed", "reason": reason}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
