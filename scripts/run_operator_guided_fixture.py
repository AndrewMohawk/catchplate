#!/usr/bin/env python3
"""One isolated real browser→catalog→proxy→browser-revoke journey.

Only existing pinned images, source and normal gate are admitted. No build,
download, seeding, provider account, live deployment or automatic retry.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import prepare_operator_guided_fixture as recipe
from scripts import operator_guided_hosted_profile as hosted
from scripts.check_operator_curated_gate import PROBE
from scripts.run_operator_gmail_sdk_fixture import NODE, NODE_SHA256, CHROME, CHROME_SHA256
from scripts.run_operator_x_post_fixture import XPostRun
from scripts.run_operator_x_examples_fixture import absolute_path, sha256, require, failure_site

SOURCE_SCRIPT = "scripts/run_operator_guided_fixture.py"
WORK_SECONDS, CLEANUP_SECONDS = 300, 60
CHROME_CANONICAL = Path("/srv/catchplate-fast/home-offload/operator/.cache/ms-playwright/"
    "chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell")


def admitted_image_entrypoint(image, entrypoint, hosted_profile=None):
    if hosted_profile is not None:
        hosted.validate(hosted_profile)
        return image in {hosted_profile["app"]["id"], hosted.CLIENT_IMAGE, hosted.GATE_IMAGE} and entrypoint in (None, [])
    if image == recipe.basic.CLIENT_IMAGE:
        return entrypoint == ["/entrypoint.sh"]
    return entrypoint in (None, [])


class GuidedRun(XPostRun):
    """Reuse exact-ID discovery, finite command groups and strict runtime checks."""

    def inputs(self, suffix):
        self.source_unchanged(suffix)
        selected = getattr(self.args, "profile", "homelab-cached-v1")
        provision = getattr(self.args, "hosted_provision", None)
        if selected == hosted.PROFILE:
            require(provision is not None)
            current = hosted.read(provision, source=self.args.source, revision=self.args.commit,
                github=hosted.github_identity(os.environ))
            require(suffix == "before" or current == self.hosted_profile, "hosted provision changed")
            self.hosted_profile = current
        else:
            require(selected == "homelab-cached-v1" and provision is None)
            self.hosted_profile = None
        pins = ((self.args.binary, self.args.expected_binary_sha256),
            (self.args.initializer, recipe.base.INITIALIZER_SHA256), (NODE, NODE_SHA256), (CHROME, CHROME_SHA256))
        for path, expected in pins:
            resolutions = {path, CHROME_CANONICAL} if path == CHROME else {path}
            require(path.is_file() and path.resolve() in resolutions and not path.is_symlink()
                and path.stat().st_mode & 4 and recipe.base.digest(path) == expected, "guided pinned input differs")
        return {str(path): expected for path, expected in pins} | (
            {str(provision): recipe.base.digest(provision)} if provision is not None else {})

    def public_view(self, container, mode, suffix, *, initial):
        require(re.fullmatch(r"[0-9a-f]{64}", container) and mode in {"app", "gate"})
        value = json.loads(self.command("curated-" + mode + "-" + suffix,
            ["docker", "exec", container, "python", "-B", "-c", PROBE, mode, self.args.expected_binary_sha256], 16))
        require(value.get("ok") is True)
        self.save("curated-" + mode + "-" + suffix + ".json", value)
        return {key: value[key] for key in ("leaves", "policy", "export_directory")}

    def inspect_runtime(self, config, image_ids, *, keeper_anchor):
        identities = super().inspect_runtime(config, image_ids, keeper_anchor=keeper_anchor)
        rows = self.container_rows("stdio")
        require({row["Config"]["Labels"]["com.docker.compose.service"]: row["Id"] for row in rows} == identities)
        check = next(row for row in rows if row["Id"] == identities["check"])
        require(check["Config"].get("OpenStdin") is True and check["Config"].get("Tty") is False,
            "guided checker stdio differs")
        return identities

    def admit_checker_window(self, edge, *, keeper_anchor, work_anchor):
        state = json.loads(self.command("edge-launch-state", ["docker", "inspect", "--format", "{{json .State}}", edge], 3))
        require(state["Status"] == "running" and not state["OOMKilled"]
            and state["StartedAt"] == self.edge_started_at, "original guided edge identity changed")
        started = datetime.datetime.fromisoformat(state["StartedAt"].replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
        require(0 <= age < recipe.EDGE_SECONDS - recipe.CHECKER_OUTER_SECONDS,
            "original guided edge lifetime insufficient")
        now = time.monotonic()
        require(now - keeper_anchor < recipe.PRECHECK_SECONDS, "original guided setup budget expired")
        cutoff = min(work_anchor + WORK_SECONDS, keeper_anchor + recipe.KEEPER_SECONDS - 15)
        require(cutoff - now > recipe.CHECKER_OUTER_SECONDS + 6, "original guided browser budget insufficient")
        return cutoff

    def browser_preflight(self):
        self.browser_unit = self.project + "-browser.service"
        require(re.fullmatch(r"catchplate-guided-private-[0-9a-f]{12}-browser\.service", self.browser_unit))
        require(not self.browser_units("browser-unit-before"), "guided browser unit already exists")
        rows = self.command("browser-unit-files-before", ["systemctl", "--user", "list-unit-files",
            "--no-legend", "--no-pager", self.browser_unit, "default.target"], 3).decode("ascii")
        require([row.split() for row in rows.splitlines()] == [["default.target", "static", "-"]])
        self.browser_tmp = Path(tempfile.mkdtemp(prefix="browser-", dir=self.args.job_root))
        info = self.browser_tmp.lstat()
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid())
        self.browser_tmp_identity = (info.st_dev, info.st_ino)
        self.save("browser-inputs.json", {"unit": self.browser_unit, "nodeSha256": NODE_SHA256,
            "chromiumSha256": CHROME_SHA256, "driverSha256": recipe.base.digest(self.args.source / recipe.BROWSER_DRIVER),
            "hostRendering": True, "containerStdioTransport": True, "runtimeMaxSeconds": 185,
            "temporaryDownloadArtifacts": True, "killMode": "control-group", "restart": "no"})

    def cleanup(self):
        self.deadline = time.monotonic() + CLEANUP_SECONDS
        errors = []
        browser_clean = False
        try:
            self.browser_cleanup()
            browser_clean = True
            if getattr(self, "browser_tmp", None) is not None:
                path = self.browser_tmp; info = path.lstat()
                require(path.parent == self.args.job_root and path.resolve() == path and not path.is_symlink()
                    and re.fullmatch(r"browser-[a-z0-9_]{8}", path.name)
                    and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_uid == os.getuid() and (info.st_dev, info.st_ino) == self.browser_tmp_identity)
                # Only our pinned ephemeral download/profile directory, after
                # the exact owning unit is stopped and has no descendants.
                shutil.rmtree(path)
                require(not path.exists())
                self.save("browser-temporary-cleanup.json", {"removed": True, "ownedIdentityVerified": True})
        except Exception:
            errors.append("browser-cleanup")
        try:
            rows = self.container_rows("cleanup-before")
        except Exception:
            return False, errors + ["inspect"]
        checks = [row for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check"]
        if len(checks) > 1:
            return False, errors + ["checker-identity"]
        remaining = rows
        if checks:
            try:
                self.command("cleanup-check-remove", ["docker", "rm", "--force", checks[0]["Id"]], 10)
                remaining = [row for row in rows if row is not checks[0]]
            except Exception:
                errors.append("checker-remove")
        for row in remaining:
            if self.deadline - time.monotonic() < 38:
                break
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            if name == "check":
                continue  # Private stdio frames must never become retained logs.
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
            clean = False; errors.append("verification")
        return clean and browser_clean and not errors, errors

    def execute(self):
        args = self.args
        require(re.fullmatch(r"[0-9a-f]{40}", args.commit))
        for path in (args.source, args.job_root, args.evidence):
            require(path.is_dir() and path.resolve() == path and not path.is_symlink())
        require(all(not left.is_relative_to(right) and not right.is_relative_to(left) for left, right in (
            (args.source, args.job_root), (args.source, args.evidence), (args.job_root, args.evidence))))
        for path in (args.job_root, args.evidence):
            require(path.stat().st_uid == os.getuid() and stat.S_IMODE(path.stat().st_mode) == 0o700 and not list(path.iterdir()))
        self.save("run.claim.json", {"schema": "catchplate.privateGuidedRunClaim/v1", "sourceCommit": args.commit,
            "jobRoot": str(args.job_root)})
        phase, success, armed, clean = "inputs", False, False, False
        failure, errors, begun = None, [], time.monotonic()
        self.deadline = begun + WORK_SECONDS
        try:
            require(Path(__file__).resolve() == args.source / SOURCE_SCRIPT)
            before = self.inputs("before")
            config = recipe.build(args.source, args.binary, args.initializer, args.job_root,
                expected_binary_sha256=args.expected_binary_sha256, hosted_profile=self.hosted_profile,
                hosted_provision=getattr(args, "hosted_provision", None))
            self.project, self.services = config["name"], config["services"]
            image_ids, self.image_environments = {}, {}
            for index, image in enumerate(sorted({item["image"] for item in self.services.values()})):
                require(re.fullmatch(r"(?:python@)?sha256:[0-9a-f]{64}", image))
                value = json.loads(self.command("image-" + str(index), ["docker", "image", "inspect", "--format",
                    '{"id":{{json .Id}},"environment":{{json .Config.Env}},"entrypoint":{{json (index .Config "Entrypoint")}}}', image], 10))
                require(set(value) == {"id", "environment", "entrypoint"}
                    and admitted_image_entrypoint(image, value["entrypoint"], self.hosted_profile)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", value["id"])
                    and (not image.startswith("sha256:") or value["id"] == image))
                from scripts.run_operator_npm_example_fixture import environment
                image_ids[image], self.image_environments[image] = value["id"], environment(value["environment"])
            if self.hosted_profile is not None:
                require(image_ids == {self.hosted_profile["app"]["id"]: self.hosted_profile["app"]["id"],
                    hosted.CLIENT_IMAGE: hosted.CLIENT_ID, hosted.GATE_IMAGE: self.hosted_profile["gate"]["id"]})
                labels = json.loads(self.command("hosted-app-labels", ["docker", "image", "inspect", "--format",
                    "{{json .Config.Labels}}", self.hosted_profile["app"]["id"]], 5))
                require(labels == self.hosted_profile["app"]["labels"], "hosted build provenance differs")
            require(not self.container_rows("preexisting") and self.no_project_networks("preexisting-networks"))
            armed = True
            self.browser_preflight()
            (args.job_root / "runtime").mkdir(mode=0o700)
            compose_path = args.job_root / "compose.json"
            with compose_path.open("x", encoding="utf-8") as stream:
                json.dump(config, stream, sort_keys=True, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
            self.save("run-inputs.json", {"sourceCommit": args.commit, "binarySha256": args.expected_binary_sha256,
                "initializerSha256": recipe.base.INITIALIZER_SHA256, "curlSha256": (
                    recipe.basic.CURL_SHA256 if self.hosted_profile is None else self.hosted_profile["curl"]["sha256"]),
                "composeSha256": recipe.base.digest(compose_path), "project": self.project, "images": image_ids,
                "workSeconds": WORK_SECONDS, "cleanupSeconds": CLEANUP_SECONDS, "syntheticOnly": True,
                "realProviderVerified": False, "productionReady": False})
            compose = ["docker", "compose", "-f", str(compose_path), "-p", self.project]
            for phase, profile in (("initialize", "prepare"), ("network-files", "network-files")):
                self.command(phase, compose + ["--profile", profile, "run", "--rm", "--no-deps", "--pull", "never", phase], 30)
            phase, keeper_anchor = "network", time.monotonic()
            self.deadline = min(begun + WORK_SECONDS, keeper_anchor + recipe.PRECHECK_SECONDS)
            self.command("network", compose + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "15", "network"], 20)
            phase = "app-before-gate"
            self.start_app_then_gate(compose)
            self.command("basic-pki", compose + ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"], 25)
            self.command("edge", compose + ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"], 10)
            self.command("create-check", compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build",
                "--pull", "never", "--no-deps", "check"], 10)
            phase = "runtime-inspection"
            identities = self.inspect_runtime(config, image_ids, keeper_anchor=keeper_anchor)
            app = self.public_view(identities["catchplate"], "app", "before", initial=True)
            gate = self.public_view(identities["decision-gate-rs"], "gate", "before", initial=True)
            require(app == gate == self.initial_view, "guided original curated publication differs")
            self.command("network-proof", ["docker", "exec", identities["provider"], "python", "-B", "-c",
                "from scripts.operator_guided_fixture_network import assert_isolated_network; assert_isolated_network()"], 5)
            self.deadline = self.admit_checker_window(identities["edge"], keeper_anchor=keeper_anchor, work_anchor=begun)
            phase = "browser"
            require(not self.browser_units("browser-unit-at-start"))
            self.browser_unit_armed = True
            raw = self.command("checker-browser", ["systemd-run", "--user", "--wait", "--pipe", "--collect", "--quiet",
                "--service-type=exec", "--unit=" + self.browser_unit, "--property=RuntimeMaxSec=185",
                "--property=TimeoutStopSec=5", "--property=KillMode=control-group", "--property=Restart=no",
                "--property=MemoryMax=2G", "--property=TasksMax=128", "--property=CPUQuota=100%", "--property=UMask=0077",
                "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "DOCKER_HOST=unix:///var/run/docker.sock",
                "TMPDIR=" + str(self.browser_tmp), str(NODE), str(args.source / recipe.BROWSER_DRIVER),
                identities["check"], str(args.evidence)], recipe.CHECKER_OUTER_SECONDS)
            from scripts.check_operator_guided import validate_joined_result
            result = json.loads(raw); validate_joined_result(result)
            require(result["checker"]["dataPlaneBinaryDigest"] == "sha256:" + args.expected_binary_sha256)
            self.save("joined-result.json", result)
            state = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", identities["check"]], 5))
            require(state["Status"] == "exited" and state["ExitCode"] == 0 and not state["OOMKilled"]
                and not self.browser_units("browser-unit-after"), "guided checker or browser remains")
            phase = "immutable-inputs"
            final_app = self.public_view(identities["catchplate"], "app", "after", initial=False)
            final_gate = self.public_view(identities["decision-gate-rs"], "gate", "after", initial=False)
            require(final_app == final_gate and all(final_app[key] == app[key] for key in ("leaves", "export_directory")))
            require(final_app["policy"]["policy_hash"] == result["checker"]["policyHash"])
            require(self.inputs("after") == before)
            rows = self.container_rows("final")
            require({row["Config"]["Labels"]["com.docker.compose.service"]: row["Id"] for row in rows} == identities
                and all(row["RestartCount"] == 0 and not row["State"]["OOMKilled"] for row in rows))
            success, phase = True, "complete"
        except (Exception, KeyboardInterrupt) as error:
            failure = failure_site(error, args.source)
        finally:
            if armed:
                clean, errors = self.cleanup()
            self.save("terminal.json", {"schema": "catchplate.privateGuidedRun/v1", "phase": phase,
                "success": success, "cleanup": clean, "cleanupErrors": errors,
                "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True,
                "realProviderVerified": False, "productionReady": False,
                **({"failureSite": failure} if failure is not None else {})})
            print(json.dumps({"phase": phase, "success": success, "cleanup": clean}), flush=True)
        return 0 if success and clean else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "job-root", "evidence", "binary", "initializer"):
        parser.add_argument("--" + name, type=absolute_path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--expected-binary-sha256", type=sha256, required=True)
    parser.add_argument("--profile", choices=("homelab-cached-v1", hosted.PROFILE), default="homelab-cached-v1")
    parser.add_argument("--hosted-provision", type=absolute_path)
    args = parser.parse_args()
    for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
        os.environ.pop(name, None)
    os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    os.umask(0o077)
    return GuidedRun(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
