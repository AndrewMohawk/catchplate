#!/usr/bin/env python3
"""One bounded npm example acceptance using existing offline artifacts only.

No install, build, pull, retry, public registry or live data. A clean exact
checkout, separately pinned adjacent dependencies and two new private roots
are mandatory. Failed evidence/state is retained, exact owned containers removed.
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

from scripts.run_operator_gmail_sdk_fixture import GmailSdkRun
from scripts.run_operator_x_examples_fixture import absolute_path, sha256, require, failure_site

SOURCE_FILE = Path(__file__).resolve()
SOURCE_SCRIPT = "scripts/run_operator_npm_example_fixture.py"
WORK_SECONDS, CLEANUP_SECONDS = 390, 60


def memory_bytes(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*[mg]", value))
    return int(value[:-1]) * (1024**2 if value[-1] == "m" else 1024**3)


def environment(values):
    require(type(values) is list and len(values) <= 256)
    result = {}
    for value in values:
        require(isinstance(value, str) and "=" in value and len(value) <= 16384 and "\0" not in value)
        key, item = value.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in result)
        result[key] = item
    return result


class NpmExampleRun(GmailSdkRun):
    """Reuse bounded process/log, project discovery and same-ID readiness waits."""

    def cleanup(self):
        # The actual Node example deliberately owns a detached worker group.
        # On uncertainty, destroy its container before any other runtime work;
        # an exited checker leader alone is not proof that all children exited.
        self.deadline = time.monotonic() + CLEANUP_SECONDS
        errors = []
        try:
            rows = self.container_rows("cleanup-before")
        except Exception:
            return False, ["inspect"]
        checks = [row for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check"]
        if len(checks) > 1:
            return False, ["checker-identity"]
        remaining = [row for row in rows if row not in checks]
        if checks:
            checker = checks[0]["Id"]
            try:
                self.command("retained-check-logs", ["docker", "logs", "--tail", "120", checker], 2)
            except Exception:
                errors.append("log-capture:check")
            try:
                self.command("cleanup-check-remove", ["docker", "rm", "--force", checker], 10)
            except Exception:
                errors.append("checker-remove")
                # Continue exact cleanup, but never report a successful run.
                remaining = rows
        for row in remaining:
            if self.deadline - time.monotonic() < 38:
                break
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            try:
                self.command("retained-" + name + "-logs", ["docker", "logs", "--tail", "120", row["Id"]], 2)
            except Exception:
                errors.append("log-capture:" + name)
        ids = [row["Id"] for row in remaining]
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
        return clean and "checker-remove" not in errors, errors

    def inspect_runtime(self, config, image_ids, recipe, *, keeper_anchor):
        rows = self.container_rows("created")
        require(len(rows) == 6 and {row["Config"]["Labels"]["com.docker.compose.service"]
            for row in rows} == recipe.RUNTIME_SERVICES)
        network = next(row for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "network")
        observations = []
        for row in rows:
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            service, host, actual_config = config["services"][name], row["HostConfig"], row["Config"]
            require(row["RestartCount"] == 0 and not row["State"]["OOMKilled"] and not host["Privileged"]
                and host["ReadonlyRootfs"] and not host["PortBindings"]
                and row["Image"] == image_ids[service["image"]]
                and host["NetworkMode"] == ("none" if name == "network" else "container:" + network["Id"]))
            require(host["CapDrop"] == ["ALL"]
                and {value.removeprefix("CAP_") for value in host["CapAdd"] or []} == set(service.get("cap_add", []))
                and set(host["SecurityOpt"]) in ({"no-new-privileges:true"}, {"no-new-privileges"})
                and actual_config["User"] == service["user"]
                and (actual_config["Entrypoint"] or []) == service["entrypoint"]
                and (actual_config["Cmd"] or []) == service["command"]
                and actual_config["WorkingDir"] == service["working_dir"])
            require(environment(actual_config["Env"]) == {
                **self.image_environments[service["image"]], **service.get("environment", {})},
                "runtime environment differs from selected image and recipe")
            require(host["Memory"] == host["MemorySwap"] == memory_bytes(service["mem_limit"])
                and host["NanoCpus"] == int(service["cpus"] * 10**9)
                and host["PidsLimit"] == service["pids_limit"]
                and bool(host.get("Init")) == service["init"]
                and host["RestartPolicy"]["Name"] == "no"
                and not any(host.get(key) for key in ("Devices", "DeviceRequests", "VolumesFrom", "ExtraHosts", "PidMode")))
            require(host.get("Sysctls", {}) == service.get("sysctls", {})
                and host["LogConfig"] == {"Type": service["logging"]["driver"], "Config": service["logging"]["options"]})
            tmpfs = dict(value.split(":", 1) for value in service["tmpfs"])
            require(host.get("Tmpfs", {}) == tmpfs and not host.get("Binds"), "unexpected mount mechanism")
            # Docker represents long-syntax mounts in HostConfig.Mounts; inspect
            # Mounts also contains engine-owned /etc files, which are not data
            # volumes. Only the recipe's exact bind set is admitted.
            require(all(mount["Type"] in {"bind", "tmpfs"} for mount in row["Mounts"]))
            actual = {(mount["Source"], mount["Destination"], not mount["RW"])
                for mount in row["Mounts"] if mount["Type"] == "bind"}
            require(len(actual) == len(service["volumes"]) and actual == {
                (mount["source"], mount["target"], mount["read_only"]) for mount in service["volumes"]})
            require(row["State"]["Status"] == ("created" if name == "check" else "running"))
            if name in {"network", "npm-registry", "serverware", "decision-gate-rs"}:
                require(row["State"].get("Health", {}).get("Status") == "healthy")
            if name in {"network", "npm-registry", "edge"}:
                started = datetime.datetime.fromisoformat(row["State"]["StartedAt"].replace("Z", "+00:00"))
                age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
                limit = recipe.PRECHECK_SECONDS if name != "edge" else recipe.EDGE_SECONDS - recipe.CHECKER_OUTER_SECONDS
                require(0 <= age < limit, "original npm fixture lifetime insufficient")
            observations.append({"id": row["Id"], "service": name, "state": row["State"]["Status"],
                "network": host["NetworkMode"], "bindMounts": len(actual), "image": row["Image"]})
        require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
        self.save("container-observations.json", observations)
        edge = next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "edge")
        self.wait_edge_ready(edge)
        return next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check")

    def source_unchanged(self, suffix):
        require(self.command("source-commit-" + suffix, ["git", "rev-parse", "HEAD"], 10).decode().strip() == self.args.commit)
        require(not self.command("source-status-" + suffix, ["git", "status", "--porcelain=v1"], 10).strip())

    def execute(self):
        args = self.args
        require(re.fullmatch(r"[0-9a-f]{40}", args.commit))
        for directory in (args.source, args.job_root, args.evidence):
            require(directory.is_dir() and directory.resolve() == directory and not directory.is_symlink())
        require(all(not left.is_relative_to(right) and not right.is_relative_to(left)
            for left, right in ((args.source, args.job_root), (args.source, args.evidence), (args.job_root, args.evidence))))
        for directory in (args.job_root, args.evidence):
            info = directory.stat()
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and not list(directory.iterdir()))
        self.save("run.claim.json", {"schema": "serverware.privateNpmExampleRunClaim/v1",
            "sourceCommit": args.commit, "jobRoot": str(args.job_root)})
        phase, success, armed, clean = "inputs", False, False, False
        errors, failure = [], None
        begun = time.monotonic()
        self.deadline = begun + WORK_SECONDS
        try:
            require(SOURCE_FILE == args.source / SOURCE_SCRIPT)
            self.source_unchanged("before")
            recipe = importlib.import_module("scripts.prepare_operator_npm_example_fixture")
            node_modules = args.source / recipe.DEPENDENCIES
            for path, expected in ((args.binary, args.expected_binary_sha256), (args.node, recipe.NODE_SHA256),
                    (args.initializer, recipe.base.INITIALIZER_SHA256), (recipe.LIBATOMIC, recipe.LIBATOMIC_SHA256)):
                require(path.is_file() and path.resolve() == path and not path.is_symlink()
                    and path.stat().st_mode & 4 and recipe.base.digest(path) == expected)
            before = recipe.validate_dependencies(node_modules, args.expected_node_modules_sha256)
            self.save("dependencies-before.json", before)
            config = recipe.build(args.source, args.binary, args.initializer, args.job_root, args.node, node_modules,
                expected_binary_sha256=args.expected_binary_sha256,
                expected_node_modules_sha256=args.expected_node_modules_sha256)
            self.project, self.services = config["name"], config["services"]
            image_ids, self.image_environments = {}, {}
            for index, image in enumerate(sorted({service["image"] for service in self.services.values()})):
                require(re.fullmatch(r"(?:python@)?sha256:[0-9a-f]{64}", image))
                image_row = json.loads(self.command("image-" + str(index), ["docker", "image", "inspect",
                    "--format", '{"id":{{json .Id}},"environment":{{json .Config.Env}}}', image], 10))
                require(type(image_row) is dict and set(image_row) == {"id", "environment"})
                actual = image_row["id"]
                require(re.fullmatch(r"sha256:[0-9a-f]{64}", actual)
                    and (not image.startswith("sha256:") or actual == image))
                image_ids[image] = actual
                self.image_environments[image] = environment(image_row["environment"])
            require(not self.container_rows("preexisting") and self.no_project_networks("preexisting-networks"))
            armed = True
            (args.job_root / "runtime").mkdir(mode=0o700)
            compose_path = args.job_root / "compose.json"
            with compose_path.open("x", encoding="utf-8") as output:
                json.dump(config, output, sort_keys=True, indent=2); output.write("\n")
                output.flush(); os.fsync(output.fileno())
            compose = ["docker", "compose", "-f", str(compose_path), "-p", self.project]
            self.save("run-inputs.json", {"sourceCommit": args.commit, "binarySha256": args.expected_binary_sha256,
                "nodeSha256": recipe.NODE_SHA256, "nodeModulesSha256": args.expected_node_modules_sha256,
                "libatomicSha256": recipe.LIBATOMIC_SHA256, "initializerSha256": recipe.base.INITIALIZER_SHA256,
                "composeSha256": recipe.base.digest(compose_path), "project": self.project, "images": image_ids,
                "keeperLifetimeSeconds": recipe.KEEPER_SECONDS, "checkerSeconds": recipe.CHECKER_SECONDS,
                "syntheticOnly": True, "realNpmVerified": False, "productionReady": False})
            for phase, profile, limit in (("initialize", "prepare", 35), ("npm-pki", "npm-pki", 25)):
                self.command(phase, compose + ["--profile", profile, "run", "--rm", "--no-deps", "--pull", "never", phase], limit)
            phase = "network"
            keeper_anchor = time.monotonic()
            self.deadline = min(self.deadline, keeper_anchor + recipe.PRECHECK_SECONDS)
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "15", "network"], 20)
            phase = "baseline"
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait",
                "--wait-timeout", "45", "npm-registry", "serverware", "decision-gate-rs"], 50)
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
            self.command("network-proof", compose + ["exec", "-T", "npm-registry", "python", "-B", "-c",
                "from scripts.operator_npm_metadata_fixture_network import assert_isolated_network; assert_isolated_network()"], 5)
            require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
            # Same original keeper deadline, not another lifetime allocation.
            self.deadline = min(begun + WORK_SECONDS, keeper_anchor + recipe.KEEPER_SECONDS - 15)
            phase = "checker"
            self.command("checker-start", ["docker", "start", checker], 10)
            exit_code = int(self.command("checker-wait", ["docker", "wait", checker], 190))
            raw = self.command("checker-result", ["docker", "logs", checker], 5)
            terminal = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", checker], 5))
            require(exit_code == 0 and terminal["Status"] == "exited" and terminal["ExitCode"] == 0 and not terminal["OOMKilled"])
            result = json.loads(raw)
            importlib.import_module("scripts.check_operator_npm_example").validate_success_result(result)
            require(result["nodeModulesSha256"] == args.expected_node_modules_sha256)
            phase = "immutable-inputs"
            after = recipe.validate_dependencies(node_modules, args.expected_node_modules_sha256)
            self.save("dependencies-after.json", after)
            require(after == before)
            self.source_unchanged("after")
            success, phase = True, "complete"
        except (Exception, KeyboardInterrupt) as error:
            failure = failure_site(error, args.source)
        finally:
            if armed:
                clean, errors = self.cleanup()
            self.save("terminal.json", {"schema": "serverware.privateNpmExampleRun/v1", "phase": phase,
                "success": success, "cleanup": clean, "cleanupErrors": errors,
                "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True,
                "productionReady": False, "realNpmVerified": False,
                **({"failureSite": failure} if failure is not None else {})})
            print(json.dumps({"phase": phase, "success": success, "cleanup": clean}), flush=True)
        return 0 if success and clean else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "job-root", "evidence", "binary", "node", "initializer"):
        parser.add_argument("--" + name, type=absolute_path, required=True)
    parser.add_argument("--commit", required=True)
    for name in ("expected-binary-sha256", "expected-node-modules-sha256"):
        parser.add_argument("--" + name, type=sha256, required=True)
    args = parser.parse_args()
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
        os.environ.pop(name, None)
    os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    os.umask(0o077)
    return NpmExampleRun(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
