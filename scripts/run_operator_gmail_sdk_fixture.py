#!/usr/bin/env python3
"""One bounded, isolated official-Go-Gmail-SDK acceptance, never a deployment.

Requires a clean exact source checkout and prebuilt, explicitly pinned gate and
Go example. No build/download/retry or Python SDK overlay. The opt-in browser
uses cached host Chromium and an exact checker-container stdio bridge. Each
invocation claims a new private root; failed state and bounded logs are retained.
"""
from __future__ import annotations

import argparse
import datetime
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.run_operator_x_examples_fixture import Run, absolute_path, sha256, require, failure_site

SOURCE_FILE = Path(__file__).resolve()
SOURCE_SCRIPT = "scripts/run_operator_gmail_sdk_fixture.py"
WORK_SECONDS, CLEANUP_SECONDS = 390, 60
NODE = Path("/home/catchplate/.nvm/versions/node/v25.5.0/bin/node")
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"
CHROME = Path("/home/catchplate/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell")
CHROME_SHA256 = "27e55cc30e487493b89b663085d6deeb0707be201a568657c922fac9076c317c"
BROWSER_DRIVER = "scripts/check_operator_gmail_sdk_browser.cjs"


class GmailSdkRun(Run):
    """Reuse the existing bounded process/log and exact project-ID helpers."""

    def __init__(self, args):
        super().__init__(args)
        self.deadline = None
        self.browser_unit = None
        self.browser_unit_armed = False

    def browser_units(self, label):
        raw = self.command(label, ["systemctl", "--user", "list-units", "--all", "--plain",
            "--no-legend", "--no-pager", self.browser_unit], 3)
        return bool(raw.strip())

    def browser_preflight(self, recipe):
        for file, pin in ((NODE, NODE_SHA256), (CHROME, CHROME_SHA256)):
            require(file.is_file() and not file.is_symlink() and recipe.base.digest(file) == pin)
        self.browser_unit = self.project + "-browser.service"
        require(re.fullmatch(r"serverware-gmail-sdk-private-[0-9a-f]{12}-browser\.service", self.browser_unit))
        require(not self.browser_units("browser-unit-before"), "browser unit already exists")
        # systemd 255 returns 1 for an empty exact-name unit-file match. Keep
        # command errors fatal: include one known static sentinel and require
        # that exact row alone, rather than accepting a nonzero exit status.
        unit_files = self.command("browser-unit-files-before", ["systemctl", "--user", "list-unit-files",
            "--no-legend", "--no-pager", self.browser_unit, "default.target"], 3)
        require([line.split() for line in unit_files.decode("ascii").splitlines()] == [["default.target", "static", "-"]],
            "browser unit file exists or sentinel differs")
        self.save("browser-inputs.json", {"unit": self.browser_unit, "nodeSha256": NODE_SHA256,
            "chromiumSha256": CHROME_SHA256, "driverSha256": recipe.base.digest(self.args.source / BROWSER_DRIVER),
            "hostRendering": True, "containerStdioTransport": True, "runtimeMaxSeconds": 185,
            "timeoutStopSeconds": 5, "killMode": "control-group", "restart": "no"})

    def browser_cleanup(self):
        if not self.browser_unit_armed:
            return True
        present = self.browser_units("browser-unit-cleanup-before")
        if present:
            self.command("browser-unit-stop", ["systemctl", "--user", "stop", self.browser_unit], 8)
        present = self.browser_units("browser-unit-cleanup-after")
        if present:
            raw = self.command("browser-unit-terminal", ["systemctl", "--user", "show", self.browser_unit,
                "--property=ActiveState,SubState,ControlGroup,MainPID"], 3).decode()
            fields = dict(line.split("=", 1) for line in raw.splitlines())
            require(fields.get("ActiveState") in {"inactive", "failed"}
                and fields.get("MainPID") == "0" and not fields.get("ControlGroup"), "browser descendants remain")
        self.save("browser-cleanup.json", {"unit": self.browser_unit, "clean": True, "collected": not present})
        return True

    def command(self, name, arguments, seconds=30):
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            require(remaining > 6, "Gmail SDK phase budget expired")
            # Parent command's forced kill/reap still has its existing 5s cap.
            seconds = min(seconds, remaining - 6)
        return super().command(name, arguments, seconds)

    def cleanup(self):
        self.deadline = time.monotonic() + CLEANUP_SECONDS
        errors = []
        try:
            self.browser_cleanup()
        except Exception:
            errors.append("browser-unit")
        try:
            rows = self.container_rows("cleanup-before")
        except Exception:
            return False, ["inspect"]
        # Logs are optional observations; reserve at least 35s for exact stop,
        # remove and final independent project listings. Never reset the timer.
        for row in rows:
            if self.deadline - time.monotonic() < 38:
                break
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            try:
                self.command("retained-" + name + "-logs", ["docker", "logs", "--tail", "120", row["Id"]], 2)
            except Exception:
                errors.append("log-capture:" + name)
        ids = [row["Id"] for row in rows]
        if ids:
            for name, argv, seconds in (("stop", ["docker", "stop", "--time", "5", *ids], 15),
                    ("remove", ["docker", "rm", "--force", *ids], 10)):
                try:
                    self.command("cleanup-" + name, argv, seconds)
                except Exception:
                    errors.append(name)
        try:
            clean = not self.container_rows("cleanup-after")
            clean = self.no_project_networks("cleanup-networks") and clean
        except Exception:
            clean = False
            errors.append("verification")
        return clean and "browser-unit" not in errors, errors

    def wait_edge_ready(self, edge):
        """Observe this existing process; never restart it or extend its clock."""
        until = time.monotonic() + 10
        if self.deadline is not None:
            until = min(until, self.deadline - 6)
        expected = {"ready": True, "syntheticOnly": True, "headerRewriting": False}
        for attempt in range(40):
            remaining = until - time.monotonic()
            require(remaining > 0, "Gmail SDK edge readiness deadline expired")
            label = "edge-ready" if attempt == 0 else "edge-ready-" + str(attempt)
            raw = self.command(label, ["docker", "logs", edge], min(2, remaining))
            if raw.strip():
                require(json.loads(raw) == expected, "Gmail SDK edge readiness differs")
            remaining = until - time.monotonic()
            require(remaining > 0, "Gmail SDK edge readiness deadline expired")
            state = json.loads(self.command("edge-ready-state-" + str(attempt),
                ["docker", "inspect", "--format", "{{json .State}}", edge], min(2, remaining)))
            require(state["Status"] == "running" and not state["OOMKilled"],
                "Gmail SDK edge terminated before readiness")
            require(time.monotonic() < until, "Gmail SDK edge readiness deadline expired")
            if raw.strip():
                return
            time.sleep(min(0.25, max(0, until - time.monotonic())))
        raise ValueError("Gmail SDK edge readiness observation bound exceeded")

    def inspect_runtime(self, config, image_ids, recipe, *, keeper_anchor):
        rows = self.container_rows("created")
        require(len(rows) == 6 and {row["Config"]["Labels"]["com.docker.compose.service"]
            for row in rows} == recipe.RUNTIME_SERVICES)
        network = next(row for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "network")
        observations = []
        for row in rows:
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            service, host = config["services"][name], row["HostConfig"]
            if name == "check" and service.get("stdin_open"):
                require(row["Config"].get("OpenStdin") is True and row["Config"].get("Tty") is False,
                    "browser checker stdio differs")
            require(row["RestartCount"] == 0 and not row["State"]["OOMKilled"]
                and not host["Privileged"] and host["ReadonlyRootfs"] and not host["PortBindings"]
                and row["Image"] == image_ids[service["image"]]
                and host["NetworkMode"] == ("none" if name == "network" else "container:" + network["Id"]))
            require(host["CapDrop"] == ["ALL"]
                and {value.removeprefix("CAP_") for value in host["CapAdd"] or []} == set(service.get("cap_add", []))
                and set(host["SecurityOpt"]) in ({"no-new-privileges:true"}, {"no-new-privileges"})
                and row["Config"]["User"] == service["user"])
            actual = {(mount["Source"], mount["Destination"], not mount["RW"])
                for mount in row["Mounts"] if mount["Type"] == "bind"}
            require(actual == {(mount["source"], mount["target"], mount["read_only"])
                for mount in service["volumes"]})
            require(row["State"]["Status"] == ("created" if name == "check" else "running"))
            if name in {"network", "provider", "serverware", "decision-gate-rs"}:
                require(row["State"].get("Health", {}).get("Status") == "healthy")
            if name in {"network", "provider", "edge"}:
                started = datetime.datetime.fromisoformat(row["State"]["StartedAt"].replace("Z", "+00:00"))
                age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
                limit = recipe.PRECHECK_SECONDS if name != "edge" else recipe.EDGE_SECONDS - recipe.CHECKER_OUTER_SECONDS
                require(0 <= age < limit, "original fixture lifetime insufficient")
            observations.append({"id": row["Id"], "service": name, "state": row["State"]["Status"],
                "network": host["NetworkMode"], "bindMounts": len(actual), "image": row["Image"]})
        require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
        self.save("container-observations.json", observations)
        edge = next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "edge")
        self.wait_edge_ready(edge)
        return next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check")

    def execute(self):
        args = self.args
        require(re.fullmatch(r"[0-9a-f]{40}", args.commit))
        for directory in (args.source, args.job_root, args.evidence):
            require(directory.is_dir())
        require(all(not left.is_relative_to(right) and not right.is_relative_to(left)
            for left, right in ((args.source, args.job_root), (args.source, args.evidence), (args.job_root, args.evidence))))
        for directory in (args.job_root, args.evidence):
            info = directory.stat()
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        require(not list(args.job_root.iterdir()) and not list(args.evidence.iterdir()))
        self.save("run.claim.json", {"schema": "serverware.privateGmailSdkRunClaim/v1",
            "sourceCommit": args.commit, "jobRoot": str(args.job_root)})
        phase, success, armed, clean = "inputs", False, False, False
        errors, failure = [], None
        begun = time.monotonic()
        self.deadline = begun + WORK_SECONDS
        try:
            require(SOURCE_FILE == args.source / SOURCE_SCRIPT)
            require(self.command("source-commit", ["git", "rev-parse", "HEAD"], 10).decode().strip() == args.commit)
            require(not self.command("source-status", ["git", "status", "--porcelain=v1"], 10).strip())
            recipe = importlib.import_module("scripts.prepare_operator_gmail_sdk_fixture")
            for path, expected in ((args.binary, args.expected_binary_sha256), (args.go, args.expected_go_sha256),
                    (args.initializer, recipe.base.INITIALIZER_SHA256)):
                require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 4
                    and recipe.base.digest(path) == expected)
            config = recipe.build(args.source, args.binary, args.initializer, args.job_root, args.go,
                expected_binary_sha256=args.expected_binary_sha256, expected_go_sha256=args.expected_go_sha256,
                browser_permission=getattr(args, "browser_permission", False))
            self.project, self.services = config["name"], config["services"]
            if getattr(args, "browser_permission", False):
                self.browser_preflight(recipe)
            image_ids = {}
            for index, image in enumerate(sorted({service["image"] for service in self.services.values()})):
                require(re.fullmatch(r"(?:python@)?sha256:[0-9a-f]{64}", image))
                actual = self.command("image-" + str(index),
                    ["docker", "image", "inspect", "--format", "{{.Id}}", image], 10).decode().strip()
                require(re.fullmatch(r"sha256:[0-9a-f]{64}", actual)
                    and (not image.startswith("sha256:") or actual == image))
                image_ids[image] = actual
            require(not self.container_rows("preexisting") and self.no_project_networks("preexisting-networks"))
            armed = True
            (args.job_root / "runtime").mkdir(mode=0o700)
            compose_path = args.job_root / "compose.json"
            with compose_path.open("x", encoding="utf-8") as output:
                json.dump(config, output, sort_keys=True, indent=2); output.write("\n")
                output.flush(); os.fsync(output.fileno())
            compose = ["docker", "compose", "-f", str(compose_path), "-p", self.project]
            self.save("run-inputs.json", {"sourceCommit": args.commit,
                "binarySha256": args.expected_binary_sha256, "goSha256": args.expected_go_sha256,
                "initializerSha256": recipe.base.INITIALIZER_SHA256, "composeSha256": recipe.base.digest(compose_path),
                "project": self.project, "images": image_ids, "initialAccessTokenSeconds": 90,
                "keeperLifetimeSeconds": recipe.KEEPER_SECONDS, "checkerSeconds": recipe.CHECKER_SECONDS,
                "syntheticOnly": True, "realGoogleVerified": False, "productionReady": False})
            phase = "initialize"
            self.command(phase, compose + ["--profile", "prepare", "run", "--rm", "--no-deps", "--pull", "never", "initialize"], 35)
            phase = "network"
            keeper_anchor = time.monotonic()
            self.deadline = min(self.deadline, keeper_anchor + recipe.PRECHECK_SECONDS)
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait",
                "--wait-timeout", "15", "network"], 20)
            phase = "baseline"
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait",
                "--wait-timeout", "45", "provider", "serverware", "decision-gate-rs"], 50)
            phase = "basic-pki"
            self.command(phase, compose + ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"], 25)
            phase = "edge"
            self.command(phase, compose + ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"], 10)
            phase = "create-check"
            self.command(phase, compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build",
                "--pull", "never", "--no-deps", "check"], 10)
            checker = self.inspect_runtime(config, image_ids, recipe, keeper_anchor=keeper_anchor)
            phase = "running-binary"
            actual = self.command(phase, compose + ["exec", "-T", "decision-gate-rs", "python", "-B", "-c",
                "import hashlib; print(hashlib.sha256(open('/usr/local/bin/serverware-decision-gate','rb').read()).hexdigest())"], 10).decode().strip()
            require(actual == args.expected_binary_sha256)
            require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
            # This is the original keeper cutoff, not a new lifetime allocation.
            self.deadline = min(begun + WORK_SECONDS, keeper_anchor + recipe.KEEPER_SECONDS - 15)
            phase = "checker"
            if getattr(args, "browser_permission", False):
                require(not self.browser_units("browser-unit-at-start"), "browser unit appeared before start")
                self.browser_unit_armed = True  # Uncertain launch still owns exact-unit cleanup.
                raw = self.command("checker-browser", ["systemd-run", "--user", "--wait", "--pipe", "--collect",
                    "--quiet", "--service-type=exec", "--unit=" + self.browser_unit,
                    "--property=RuntimeMaxSec=185", "--property=TimeoutStopSec=5",
                    "--property=KillMode=control-group", "--property=Restart=no",
                    "--property=MemoryMax=2G", "--property=TasksMax=128", "--property=UMask=0077",
                    str(NODE), str(args.source / BROWSER_DRIVER), checker, str(args.evidence)], 190)
                importlib.import_module("scripts.operator_gmail_sdk_browser").validate_joined_result(json.loads(raw))
                exit_code = 0
                require(not self.browser_units("browser-unit-after"), "completed browser unit was not collected")
            else:
                self.command("checker-start", ["docker", "start", checker], 10)
                exit_code = int(self.command("checker-wait", ["docker", "wait", checker], 190))
                raw = self.command("checker-result", ["docker", "logs", checker], 5)
                importlib.import_module("scripts.check_operator_gmail_sdk").validate_success_result(json.loads(raw))
            terminal = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", checker], 5))
            require(exit_code == 0 and terminal["Status"] == "exited" and terminal["ExitCode"] == 0 and not terminal["OOMKilled"])
            success, phase = True, "complete"
        except (Exception, KeyboardInterrupt) as error:
            failure = failure_site(error, args.source)
        finally:
            if armed:
                clean, errors = self.cleanup()
            self.save("terminal.json", {"schema": "serverware.privateGmailSdkRun/v1", "phase": phase,
                "success": success, "cleanup": clean, "cleanupErrors": errors,
                "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True,
                "productionReady": False, "realGoogleVerified": False,
                **({"failureSite": failure} if failure is not None else {})})
            print(json.dumps({"phase": phase, "success": success, "cleanup": clean}), flush=True)
        return 0 if success and clean else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "job-root", "evidence", "binary", "go", "initializer"):
        parser.add_argument("--" + name, type=absolute_path, required=True)
    parser.add_argument("--commit", required=True)
    for name in ("expected-binary-sha256", "expected-go-sha256"):
        parser.add_argument("--" + name, type=sha256, required=True)
    parser.add_argument("--browser-permission", action="store_true")
    args = parser.parse_args()
    # One fixed local daemon reaches inherited helpers and every child command.
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
        os.environ.pop(name, None)
    os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    os.umask(0o077)
    return GmailSdkRun(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
