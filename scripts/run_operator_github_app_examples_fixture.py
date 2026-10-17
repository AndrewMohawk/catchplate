#!/usr/bin/env python3
"""One explicitly selected, isolated GitHub App SDK proof; never a deployment.

All artifacts must already exist and be independently pinned. No build, fetch,
clock patch, token-cache edit or retry. New private roots preserve failed state.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import prepare_operator_github_app_examples_fixture as recipe
from scripts.run_operator_npm_example_fixture import NpmExampleRun, environment, memory_bytes
from scripts.run_operator_x_examples_fixture import absolute_path, sha256, require, failure_site

SOURCE_SCRIPT = "scripts/run_operator_github_app_examples_fixture.py"
WORK_SECONDS = 390


class AppExamplesRun(NpmExampleRun):
    """Reuse bounded commands and checker-first, exact-ID 60s cleanup unchanged."""

    def inspect_runtime(self, config, image_ids, *, keeper_anchor):
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
                and (actual_config["Entrypoint"] or []) == service.get("entrypoint", [])
                and (actual_config["Cmd"] or []) == service["command"]
                and actual_config["WorkingDir"] == service["working_dir"]
                and environment(actual_config["Env"]) == {
                    **self.image_environments[service["image"]], **service.get("environment", {})})
            require(host["Memory"] == host["MemorySwap"] == memory_bytes(service["mem_limit"])
                and host["NanoCpus"] == int(service["cpus"] * 10**9) and host["PidsLimit"] == service["pids_limit"]
                and bool(host.get("Init")) == service["init"] and host["RestartPolicy"]["Name"] == "no"
                and not any(host.get(key) for key in ("Devices", "DeviceRequests", "VolumesFrom", "ExtraHosts", "PidMode")))
            require(host.get("Sysctls", {}) == service.get("sysctls", {})
                and host["LogConfig"] == {"Type": service["logging"]["driver"], "Config": service["logging"]["options"]}
                and host.get("Tmpfs", {}) == dict(value.split(":", 1) for value in service["tmpfs"])
                and not host.get("Binds") and all(mount["Type"] in {"bind", "tmpfs"} for mount in row["Mounts"]))
            actual = {(mount["Source"], mount["Destination"], not mount["RW"])
                for mount in row["Mounts"] if mount["Type"] == "bind"}
            require(len(actual) == len(service["volumes"]) and actual == {
                (mount["source"], mount["target"], mount["read_only"]) for mount in service["volumes"]})
            require(row["State"]["Status"] == ("created" if name == "check" else "running"))
            if name in {"network", "github", "catchplate", "decision-gate-rs"}:
                require(row["State"].get("Health", {}).get("Status") == "healthy")
            if name in {"network", "github", "edge"}:
                started = datetime.datetime.fromisoformat(row["State"]["StartedAt"].replace("Z", "+00:00"))
                age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
                limit = recipe.PRECHECK_SECONDS if name != "edge" else recipe.EDGE_SECONDS - recipe.CHECKER_OUTER_SECONDS
                require(0 <= age < limit, "original GitHub App fixture lifetime insufficient")
            observations.append({"id": row["Id"], "service": name, "state": row["State"]["Status"],
                "network": host["NetworkMode"], "bindMounts": len(actual), "image": row["Image"]})
        require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
        self.save("container-observations.json", observations)
        edge = next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "edge")
        self.wait_edge_ready(edge)
        return next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check")

    def inputs(self, suffix):
        self.source_unchanged(suffix)
        args = self.args
        for path, expected in ((args.binary, args.expected_binary_sha256), (args.go, args.expected_go_sha256),
                (args.node, recipe.NODE_SHA256), (args.initializer, recipe.base.INITIALIZER_SHA256),
                (recipe.LIBATOMIC, recipe.LIBATOMIC_SHA256)):
            require(path.is_file() and path.resolve() == path and not path.is_symlink()
                and path.stat().st_mode & 4 and recipe.base.digest(path) == expected)
        dependencies = recipe.dependencies(args.node_modules, args.python_runtime, args.python_packages)
        require(recipe.dependencies_sha256(dependencies) == args.expected_dependencies_sha256,
            "externally selected full SDK dependency payload differs")
        self.save("dependencies-" + suffix + ".json", dependencies)
        return dependencies

    def execute(self):
        args = self.args
        require(re.fullmatch(r"[0-9a-f]{40}", args.commit))
        for directory in (args.source, args.job_root, args.evidence):
            require(directory.is_dir() and directory.resolve() == directory and not directory.is_symlink())
        require(all(not left.is_relative_to(right) and not right.is_relative_to(left)
            for left, right in ((args.source, args.job_root), (args.source, args.evidence), (args.job_root, args.evidence))))
        for directory in (args.job_root, args.evidence):
            require(directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700
                and not list(directory.iterdir()))
        self.save("run.claim.json", {"schema": "catchplate.privateGithubAppExamplesRunClaim/v1",
            "sourceCommit": args.commit, "jobRoot": str(args.job_root)})
        phase, success, armed, clean = "inputs", False, False, False
        errors, failure, begun = [], None, time.monotonic()
        self.deadline = begun + WORK_SECONDS
        try:
            require(Path(__file__).resolve() == args.source / SOURCE_SCRIPT)
            before = self.inputs("before")
            config = recipe.build(args.source, args.binary, args.initializer, args.job_root, args.node,
                args.node_modules, args.python_runtime, args.python_packages, args.go,
                expected_binary_sha256=args.expected_binary_sha256, expected_go_sha256=args.expected_go_sha256)
            self.project, self.services = config["name"], config["services"]
            image_ids, self.image_environments = {}, {}
            for index, image in enumerate(sorted({service["image"] for service in self.services.values()})):
                require(re.fullmatch(r"(?:python@)?sha256:[0-9a-f]{64}", image))
                value = json.loads(self.command("image-" + str(index), ["docker", "image", "inspect", "--format",
                    '{"id":{{json .Id}},"environment":{{json .Config.Env}},"entrypoint":{{json (index .Config "Entrypoint")}}}', image], 10))
                require(set(value) == {"id", "environment", "entrypoint"} and value["entrypoint"] in (None, [])
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", value["id"])
                    and (not image.startswith("sha256:") or value["id"] == image))
                image_ids[image], self.image_environments[image] = value["id"], environment(value["environment"])
            require(not self.container_rows("preexisting") and self.no_project_networks("preexisting-networks"))
            armed = True
            (args.job_root / "runtime").mkdir(mode=0o700)
            compose_path = args.job_root / "compose.json"
            with compose_path.open("x", encoding="utf-8") as output:
                json.dump(config, output, sort_keys=True, indent=2); output.write("\n")
                output.flush(); os.fsync(output.fileno())
            compose = ["docker", "compose", "-f", str(compose_path), "-p", self.project]
            self.save("run-inputs.json", {"sourceCommit": args.commit, "binarySha256": args.expected_binary_sha256,
                "goSha256": args.expected_go_sha256, "nodeSha256": recipe.NODE_SHA256,
                "dependenciesSha256": args.expected_dependencies_sha256, "libatomicSha256": recipe.LIBATOMIC_SHA256,
                "initializerSha256": recipe.base.INITIALIZER_SHA256, "composeSha256": recipe.base.digest(compose_path),
                "project": self.project, "images": image_ids, "keeperLifetimeSeconds": recipe.KEEPER_SECONDS,
                "checkerSeconds": recipe.CHECKER_SECONDS, "initialProviderTokenSeconds": 120,
                "keyReplacementStory": True, "generatedAppSigningKeys": 2,
                "syntheticOnly": True, "realGithubVerified": False, "productionReady": False})
            for phase, profile, limit in (("initialize", "prepare", 35), ("github-pki", "github-pki", 25)):
                self.command(phase, compose + ["--profile", profile, "run", "--rm", "--no-deps", "--pull", "never", phase], limit)
            phase, keeper_anchor = "network", time.monotonic()
            self.deadline = min(self.deadline, keeper_anchor + recipe.PRECHECK_SECONDS)
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "15", "network"], 20)
            phase = "baseline"
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait",
                "--wait-timeout", "45", "github", "catchplate", "decision-gate-rs"], 50)
            phase = "basic-pki"
            self.command(phase, compose + ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"], 25)
            phase = "edge"
            self.command(phase, compose + ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"], 10)
            phase = "create-check"
            self.command(phase, compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build",
                "--pull", "never", "--no-deps", "check"], 10)
            checker = self.inspect_runtime(config, image_ids, keeper_anchor=keeper_anchor)
            phase = "running-binary"
            actual = self.command(phase, compose + ["exec", "-T", "decision-gate-rs", "python", "-B", "-c",
                "import hashlib; print(hashlib.sha256(open('/usr/local/bin/catchplate-decision-gate','rb').read()).hexdigest())"], 10).decode().strip()
            require(actual == args.expected_binary_sha256)
            self.command("network-proof", compose + ["exec", "-T", "github", "python", "-B", "-c",
                "from scripts.operator_github_fixture_network import assert_isolated_network; assert_isolated_network()"], 5)
            require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
            self.deadline = min(begun + WORK_SECONDS, keeper_anchor + recipe.KEEPER_SECONDS - 15)
            phase = "checker"
            self.command("checker-start", ["docker", "start", checker], 10)
            exit_code = int(self.command("checker-wait", ["docker", "wait", checker], recipe.CHECKER_OUTER_SECONDS))
            raw = self.command("checker-result", ["docker", "logs", checker], 5)
            terminal = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", checker], 5))
            require(exit_code == 0 and terminal["Status"] == "exited" and terminal["ExitCode"] == 0 and not terminal["OOMKilled"])
            from scripts.check_operator_github_app_examples import validate_success_result
            result = json.loads(raw)
            validate_success_result(result)
            require(result["dataPlaneBinaryDigest"] == "sha256:" + args.expected_binary_sha256
                and result["goExampleSha256"] == args.expected_go_sha256)
            phase = "immutable-inputs"
            require(self.inputs("after") == before)
            success, phase = True, "complete"
        except (Exception, KeyboardInterrupt) as error:
            failure = failure_site(error, args.source)
        finally:
            if armed:
                clean, errors = self.cleanup()
            self.save("terminal.json", {"schema": "catchplate.privateGithubAppExamplesRun/v1", "phase": phase,
                "success": success, "cleanup": clean, "cleanupErrors": errors,
                "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True,
                "realGithubVerified": False, "productionReady": False,
                **({"failureSite": failure} if failure is not None else {})})
            print(json.dumps({"phase": phase, "success": success, "cleanup": clean}), flush=True)
        return 0 if success and clean else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "job-root", "evidence", "binary", "go", "node", "node-modules", "initializer", "python-runtime", "python-packages"):
        parser.add_argument("--" + name, type=absolute_path, required=True)
    parser.add_argument("--commit", required=True)
    for name in ("expected-binary-sha256", "expected-go-sha256", "expected-dependencies-sha256"):
        parser.add_argument("--" + name, type=sha256, required=True)
    args = parser.parse_args()
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
        os.environ.pop(name, None)
    os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    os.umask(0o077)
    return AppExamplesRun(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
