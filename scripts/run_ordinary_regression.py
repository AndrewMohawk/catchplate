#!/usr/bin/env python3
"""Bounded ordinary-app component checks in an already isolated Linux container.

No dependency installation, image pull/build, browser, SDK, deployment or live
checker is performed here. Provision the existing requirements.lock separately.
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
    Suite("backend", "test_operator_demo_runtime.py"),
    Suite("backend", "test_operator_workspace_api.py"),
    Suite("backend", "test_operator_catalog_body_routing.py"),
    Suite("backend", "test_operator_catalog_header_replacement.py"),
    Suite("backend", "test_jit_denial_api.py", seconds=60),
    Suite("backend", "test_authority_jit_denial.py", seconds=60),
    Suite("backend", "test_authority_jit_approval.py", seconds=60),
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
    Suite("backend", "test_operator_guided_checker.py", seconds=60),
    Suite("backend", "test_operator_guided_fixture.py", seconds=60),
    Suite("backend", "test_operator_public_proxy.py", seconds=60),
    Suite("backend", "test_operator_public_proxy_control.py", seconds=60),
    Suite("notifications", "test_operator_notification_events.py"),
    Suite("notifications", "test_operator_notification_google_events.py"),
    Suite("notifications", "test_operator_notification_google_integration.py"),
    Suite("notifications", "test_operator_notification_provider_integration.py"),
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
)


class Refused(ValueError):
    """Only fixed public reason codes may leave preflight."""


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


def diagnostics(raw):
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
    return {"failedTests": list(dict.fromkeys(failures))[:64], "frames": frames[-64:],
        "exceptionTypes": list(dict.fromkeys(exceptions))[:32],
        "observedUnittestCounts": [int(v) for v in totals[-32:]],
        "observedSkippedTests": sum(int(v) for v in skips),
        "outputBytes": len(raw), "outputSha256": hashlib.sha256(raw).hexdigest()}


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
            "scope": "public catalog, inert DOM connect handlers, metadata-only recipe text; not browser or provider acceptance"},
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
    }
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value
    try:
        lines = raw.decode("utf-8").splitlines()
        if not lines:
            return None
        if script == "test_operator_runtime_browser_assets.cjs":
            match = re.fullmatch(r"PASS ([1-9][0-9]*) pure runtime-browser asset groups; no browser or service calls", lines[-1])
            count = int(match[1]) if match else 0
        else:
            expected = shapes[script]
            result = json.loads(lines[-1], object_pairs_hook=unique)
            if type(result) is not dict or set(result) != set(expected) | {"groups"} \
                    or any(type(result[key]) is not type(value) or result[key] != value for key, value in expected.items()):
                return None
            count = result["groups"]
        if type(count) is not int or not 0 < count <= 10000:
            return None
        if script in {"test_operator_catalog_browser.cjs", "test_operator_gmail_sdk_languages.cjs"}:
            return count if len(lines) == 1 else None
        return count if len(lines) - 1 == count and all(line.startswith("PASS ") for line in lines[:-1]) else None
    except (ValueError, KeyError, UnicodeError):
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
    detail = diagnostics(bytes(raw))
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
    for index, suite in enumerate(SUITES):
        remaining = MAX_SECONDS - (time.monotonic() - began)
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
        "scope": "ordinary-app offline component regressions", "network": "loopback-only",
        "sourceRoot": str(ROOT), "requirementsSha256": hashlib.sha256((ROOT / "requirements.lock").read_bytes()).hexdigest(),
        "elapsedSeconds": round(time.monotonic() - began, 3), "maximumSeconds": MAX_SECONDS,
        "maximumOutputBytesPerSuite": MAX_OUTPUT_BYTES, "suites": rows,
        "notExecuted": list(EXCLUDED), "productionAcceptance": False}
    save(output / "result.json", result)
    print(json.dumps({"success": result["success"], "suites": len(rows), "notExecuted": list(EXCLUDED)}))
    return 0 if result["success"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--node")
    parser.add_argument("--dependency-root", type=Path)
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
