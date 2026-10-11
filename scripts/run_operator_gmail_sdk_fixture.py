#!/usr/bin/env python3
"""One bounded, isolated official-Go-Gmail-SDK acceptance, never a deployment.

Requires a clean exact source checkout and prebuilt, explicitly pinned gate and
Go example. No build/download/retry, Node runtime, or Python SDK overlay. Each
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


class GmailSdkRun(Run):
    """Reuse the existing bounded process/log and exact project-ID helpers."""

    def __init__(self, args):
        super().__init__(args)
        self.deadline = None

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
        return clean, errors

    def inspect_runtime(self, config, image_ids, recipe, *, keeper_anchor):
        rows = self.container_rows("created")
        require(len(rows) == 6 and {row["Config"]["Labels"]["com.docker.compose.service"]
            for row in rows} == recipe.RUNTIME_SERVICES)
        network = next(row for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "network")
        observations = []
        for row in rows:
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            service, host = config["services"][name], row["HostConfig"]
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
        require(json.loads(self.command("edge-ready", ["docker", "logs", edge], 3)) ==
            {"ready": True, "syntheticOnly": True, "headerRewriting": False})
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
                expected_binary_sha256=args.expected_binary_sha256, expected_go_sha256=args.expected_go_sha256)
            self.project, self.services = config["name"], config["services"]
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
            self.command("checker-start", ["docker", "start", checker], 10)
            exit_code = int(self.command("checker-wait", ["docker", "wait", checker], 190))
            raw = self.command("checker-result", ["docker", "logs", checker], 5)
            terminal = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", checker], 5))
            require(exit_code == 0 and terminal["Status"] == "exited" and terminal["ExitCode"] == 0 and not terminal["OOMKilled"])
            importlib.import_module("scripts.check_operator_gmail_sdk").validate_success_result(json.loads(raw))
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
    args = parser.parse_args()
    # One fixed local daemon reaches inherited helpers and every child command.
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
        os.environ.pop(name, None)
    os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    os.umask(0o077)
    return GmailSdkRun(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
