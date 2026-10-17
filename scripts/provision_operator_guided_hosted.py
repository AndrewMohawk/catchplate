#!/usr/bin/env python3
"""Provision the closed hosted guided runtime, not the application journey.

One fixed Dockerfile build and public-image metadata probe on an ephemeral
GitHub VM. The public receipt is CI provenance, not protected authority.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import operator_guided_hosted_profile as profile

WORK_SECONDS, CLEANUP_SECONDS = 840, 20
MAX_OUTPUT = 1048576


def output_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))


class Provision:
    def __init__(self, source, github, directory):
        self.source, self.github, self.directory = source, github, directory
        self.namespace = profile.namespace(github)
        self.name, self.tag = self.namespace + "-curl", self.namespace + ":runtime"
        self.deadline = time.monotonic() + WORK_SECONDS
        self.armed, self.identity, self.stage = False, None, "source"
        self.build_pending = False
        self.diagnostic = None
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_BUILDKIT": "0"}

    def command(self, operation, args, seconds):
        self.stage = operation
        remaining = min(seconds, self.deadline - time.monotonic() - 2)
        profile.require(remaining > 0)
        with tempfile.TemporaryFile(dir=self.directory) as out, tempfile.TemporaryFile(dir=self.directory) as err:
            child = subprocess.Popen(args, cwd=self.source, env=self.environment, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, start_new_session=True, preexec_fn=output_limit)
            try:
                status = child.wait(timeout=remaining)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=2)
            profile.require(out.tell() <= MAX_OUTPUT and err.tell() <= MAX_OUTPUT)
            if status != 0:
                err.seek(0); raw = err.read(MAX_OUTPUT + 1)
                self.diagnostic = {"operation": operation, "exitCode": status,
                    "stderrLength": len(raw), "stderrSha256": profile.digest(raw)}
                raise ValueError("hosted provisioning command failed")
            out.seek(0)
            return out.read(MAX_OUTPUT + 1)

    def image(self, reference):
        rows = json.loads(self.command("image-inspect", ["/usr/bin/docker", "image", "inspect", reference], 5))
        profile.require(type(rows) is list and len(rows) == 1)
        value = rows[0]
        profile.require(value["Os"] == "linux" and value["Architecture"] == "amd64"
            and value["Config"].get("Entrypoint") in (None, [])
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value["Id"]))
        return value

    def source_state(self):
        revision = self.command("source-head", ["/usr/bin/git", "rev-parse", "HEAD"], 5).decode("ascii").strip()
        profile.require(re.fullmatch(r"[0-9a-f]{40}", revision)
            and not self.command("source-clean", ["/usr/bin/git", "status", "--porcelain=v1"], 5).strip())
        return revision, profile.source_pins(self.source)

    def discover(self):
        raw = self.command("metadata-discover", ["/usr/bin/docker", "ps", "--all", "--no-trunc",
            "--filter", "name=^/" + self.name + "$", "--format", "{{.ID}}"], 3).decode("ascii").strip()
        profile.require(not raw or re.fullmatch(r"[0-9a-f]{64}", raw))
        if not raw:
            return None
        rows = json.loads(self.command("metadata-inspect", ["/usr/bin/docker", "inspect", raw], 3))
        profile.require(len(rows) == 1)
        row = rows[0]
        profile.require(row["Id"] == raw and row["Name"] == "/" + self.name and row["Image"] == profile.CLIENT_ID
            and row["Config"]["Labels"] == {profile.LABEL: self.namespace}
            and (self.identity is None or self.identity == raw))
        self.identity = raw
        return row

    def metadata(self):
        profile.require(self.discover() is None, "preexisting metadata container")
        self.armed = True
        raw = self.command("metadata-create", ["/usr/bin/docker", "create", "--name", self.name,
            "--label", profile.LABEL + "=" + self.namespace, "--pull", "never", "--network", "none",
            "--read-only", "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "16",
            "--restart", "no", "--init", "--log-driver", "none", "--entrypoint", profile.PYTHON,
            profile.CLIENT_IMAGE, "-I", "-S", "-B", "-c", profile.CURL_PROBE], 10).decode("ascii").strip()
        profile.require(re.fullmatch(r"[0-9a-f]{64}", raw))
        self.identity = raw
        row = self.discover(); host = row["HostConfig"]
        profile.require(row["State"]["Status"] == "created" and row["Config"]["User"] == "65534:65534"
            and row["Config"]["Entrypoint"] == [profile.PYTHON]
            and row["Config"]["Cmd"] == ["-I", "-S", "-B", "-c", profile.CURL_PROBE]
            and host["NetworkMode"] == "none" and host["ReadonlyRootfs"] and not row["Mounts"]
            and host["Memory"] == host["MemorySwap"] == 134217728 and host["NanoCpus"] == 250000000
            and host["PidsLimit"] == 16 and host["CapDrop"] == ["ALL"] and not host["CapAdd"]
            and not host["Privileged"] and not host["PortBindings"] and host["Init"] is True
            and host["RestartPolicy"]["Name"] == "no"
            and set(host["SecurityOpt"]) in ({"no-new-privileges"}, {"no-new-privileges:true"})
            and host["LogConfig"] == {"Type": "none", "Config": {}})
        curl = json.loads(self.command("metadata-start", ["/usr/bin/docker", "start", "--attach", raw], 15))
        profile.validate_curl(curl)
        row = self.discover()
        profile.require(row["State"]["Status"] == "exited" and row["State"]["ExitCode"] == 0
            and not row["State"]["OOMKilled"] and row["RestartCount"] == 0)
        return curl

    def cleanup(self):
        self.deadline = time.monotonic() + CLEANUP_SECONDS
        if not self.armed:
            return not self.build_pending
        row = self.discover()
        if row is not None:
            self.command("metadata-remove", ["/usr/bin/docker", "rm", "--force", row["Id"]], 8)
        # An absent object alone does not close a lost create response.
        return not self.build_pending and self.identity is not None and self.discover() is None

    def run(self):
        revision, pins = self.source_state()
        profile.require(not self.command("app-tag-before", ["/usr/bin/docker", "image", "ls", "--quiet",
            "--filter", "reference=" + self.tag], 5).strip(), "preexisting hosted app tag")
        for reference, seconds in ((profile.CLIENT_IMAGE, 180), (profile.GATE_IMAGE, 60)):
            self.command("public-image-pull", ["/usr/bin/docker", "pull", "--platform", "linux/amd64", reference], seconds)
        client, gate = self.image(profile.CLIENT_IMAGE), self.image(profile.GATE_IMAGE)
        profile.require(client["Id"] == profile.CLIENT_ID and client["Config"].get("Entrypoint") is None
            and "PYTHON_VERSION=3.12.15" in client["Config"]["Env"])
        labels = {profile.LABEL: self.namespace, profile.LABEL + ".source": revision}
        self.build_pending = True
        self.command("app-build", ["/usr/bin/docker", "build", "--platform", "linux/amd64", "--pull", "--force-rm",
            "--memory", "2g", "--memory-swap", "2g", "--cpu-period", "100000", "--cpu-quota", "200000",
            "--target", "production-runtime", "--file", "Dockerfile", "--tag", self.tag,
            *(arg for key, value in labels.items() for arg in ("--label", key + "=" + value)), "."], 600)
        self.build_pending = False
        app = self.image(self.tag)
        profile.require(app["Config"].get("Labels") == labels)
        curl = self.metadata()
        profile.require(self.source_state() == (revision, pins), "build source changed")
        return {"schema": profile.SCHEMA, "profile": profile.PROFILE, "sourceRevision": revision,
            "sourcePins": pins, "github": self.github, "app": {"id": app["Id"], "tag": self.tag,
                "target": "production-runtime", "labels": labels},
            "client": {"reference": profile.CLIENT_IMAGE, "id": profile.CLIENT_ID,
                "python": profile.PYTHON, "entrypoint": None},
            "gate": {"reference": profile.GATE_IMAGE, "id": gate["Id"]}, "curl": curl,
            "metadataContainerRemoved": True, "nativeAuthority": False, "journeyExecuted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    github = profile.github_identity(os.environ)
    profile.require(os.getuid() != 0 and args.source.is_absolute() and args.source.resolve() == args.source
        and Path(__file__).resolve() == args.source / "scripts/provision_operator_guided_hosted.py"
        and args.output.is_absolute() and args.output.parent.resolve() == args.output.parent
        and not args.output.exists() and not args.output.is_symlink()
        and not args.output.is_relative_to(args.source)
        and stat.S_IMODE(args.output.parent.stat().st_mode) == 0o700
        and args.output.parent.stat().st_uid == os.getuid())
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix=profile.namespace(github) + "-", dir=args.output.parent) as temporary:
        owner = Provision(args.source, github, Path(temporary))
        value, failed, failure_stage, diagnostic = None, None, None, None
        try:
            value = owner.run()
        except (Exception, KeyboardInterrupt) as error:
            failed, failure_stage, diagnostic = type(error).__name__, owner.stage, owner.diagnostic
        finally:
            try:
                clean = owner.cleanup()
            except (Exception, KeyboardInterrupt):
                clean = False
        if failed is not None or not clean:
            value = {"schema": "catchplate.guidedHostedProvisionFailure/v1", "ok": False,
                "stage": failure_stage or "cleanup", "exceptionType": failed, "cleanup": clean,
                "diagnostic": diagnostic, "journeyExecuted": False, "nativeAuthority": False}
        else:
            profile.validate(value, source=args.source, github=github)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        profile.require(len(raw) <= 65536)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), 0o444); os.fsync(stream.fileno())
        print(json.dumps({"ok": failed is None and clean, "profile": profile.PROFILE, "journeyExecuted": False}))
        return 0 if failed is None and clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
