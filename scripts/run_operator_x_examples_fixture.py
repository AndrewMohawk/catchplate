#!/usr/bin/env python3
"""Run one explicitly selected, isolated X examples fixture; never deploy it.

Root supplies already-built executables and already-acquired SDK dependencies.
This runner does not build, install, pull images, inventory dependency trees, or
contact X. Each invocation needs a new empty private runtime root and new claim
and evidence filenames. Runtime data and evidence are retained after teardown.
"""
from __future__ import annotations

import argparse
import datetime
import importlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time

PYTHON_IMAGE = "sha256:ec7d6c95cd3692a2e2d228a8b1ca74e4025b54121fcc4c5da6f09cfa473315ad"
LIBATOMIC = Path("/usr/lib/x86_64-linux-gnu/libatomic.so.1.2.0")
RUNTIME_SERVICES = {"network", "x", "catchplate", "decision-gate-rs", "edge", "check"}
MAX_LOG_BYTES = 4 * 1024**2


def require(condition, message="private X examples run refused"):
    if not condition:
        raise ValueError(message)


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise argparse.ArgumentTypeError("an explicit canonical absolute path is required")
    return path


def sha256(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("a lowercase SHA256 is required")
    return value


def limit_command_logs():
    # Bounds both redirected regular files while Docker's own local log driver
    # separately bounds container logs. This limit is not a container setting.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES))


def failure_site(error, source):
    """Return a source code location only, never exception text or local values."""
    site = None
    trace = error.__traceback__
    while trace is not None:
        frame = trace.tb_frame
        try:
            relative = Path(frame.f_code.co_filename).resolve().relative_to(source)
        except (OSError, ValueError, RuntimeError):
            relative = None
        if (relative is not None and relative.suffix == ".py"
                and relative.parts[0] in {"scripts", "catchplate"}
                and all(re.fullmatch(r"[A-Za-z0-9_]+", part) for part in relative.with_suffix("").parts)
                and frame.f_code.co_name != "require"):
            site = {"module": ".".join(relative.with_suffix("").parts), "line": trace.tb_lineno}
        trace = trace.tb_next
    return site


class Run:
    # These are source-fixed profiles, not CLI options or configuration imports.
    SOURCE_FILE = Path(__file__).resolve()
    SOURCE_SCRIPT = "scripts/run_operator_x_examples_fixture.py"
    RECIPE_MODULE = "scripts.prepare_operator_x_fixture"
    CHECKER_MODULE = "scripts.check_operator_x_examples"
    CHECKER_SCRIPT = "/app/scripts/check_operator_x_examples.py"
    PROVIDER_SERVICE = "x"
    PROVIDER_PKI_SERVICE = "x-pki"
    NODE_EXAMPLE_DIRECTORY = "examples/x-username-node"
    GO_MOUNT_TARGET = "/example-go/x-username"
    CLAIM_SCHEMA = "catchplate.privateXExamplesRunClaim/v1"
    TERMINAL_SCHEMA = "catchplate.privateXExamplesRun/v1"
    REAL_PROVIDER_VERIFIED = "realXVerified"

    def __init__(self, args):
        self.args = args
        self.project = None
        self.services = {}

    def save(self, name, value):
        with (self.args.evidence / name).open("x", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())

    def command(self, name, arguments, seconds=30):
        require(re.fullmatch(r"[a-z0-9-]{1,80}", name) and 0 < seconds <= 190)
        print(name, flush=True)
        out_path = self.args.evidence / (name + ".stdout.log")
        with out_path.open("xb") as out, (self.args.evidence / (name + ".stderr.log")).open("xb") as err:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                cwd=self.args.source, start_new_session=True, preexec_fn=limit_command_logs)
            try:
                status = process.wait(timeout=seconds)
            except BaseException:
                # A timed-out unreaped child still reserves its PID. Kill only
                # this command's process group, including its Compose plugin.
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                raise
        require(status == 0, "private X phase failed")
        with out_path.open("rb") as output:
            raw = output.read(MAX_LOG_BYTES + 1)
        require(len(raw) <= MAX_LOG_BYTES)
        return raw

    def container_rows(self, prefix):
        ids = self.command(prefix + "-ids", ["docker", "ps", "-aq", "--no-trunc", "--filter",
            "label=com.docker.compose.project=" + self.project], 5).decode("ascii").split()
        require(len(ids) <= len(self.services) and len(set(ids)) == len(ids)
            and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in ids))
        if not ids:
            return []
        rows = json.loads(self.command(prefix + "-inspect", ["docker", "inspect", *ids], 10))
        require(type(rows) is list and {row["Id"] for row in rows} == set(ids))
        for row in rows:
            labels = row["Config"]["Labels"]
            require(labels["com.docker.compose.project"] == self.project
                and labels["com.docker.compose.service"] in self.services)
        return rows

    def no_project_networks(self, prefix):
        return not self.command(prefix, ["docker", "network", "ls", "-q", "--filter",
            "label=com.docker.compose.project=" + self.project], 5).strip()

    def cleanup(self):
        errors = []
        try:
            rows = self.container_rows("cleanup-before")
        except Exception:
            return False, ["inspect"]  # No broad cleanup when exact targets are unknown.
        ids = [row["Id"] for row in rows]
        for row in rows:
            name = row["Config"]["Labels"]["com.docker.compose.service"]
            try:
                self.command("retained-" + name + "-logs",
                    ["docker", "logs", "--tail", "150", row["Id"]], 10)
            except Exception:
                errors.append("log-capture:" + name)
        if ids:
            try:
                self.command("cleanup-stop", ["docker", "stop", "--time", "5", *ids], 20)
            except Exception:
                errors.append("stop")
            try:
                self.command("cleanup-remove", ["docker", "rm", "--force", *ids], 10)
            except Exception:
                errors.append("remove")
        try:
            clean = not self.container_rows("cleanup-after")
            clean = self.no_project_networks("cleanup-networks") and clean
        except Exception:
            clean = False
            errors.append("verification")
        return clean, errors

    def execute(self):
        args = self.args
        require(re.fullmatch(r"[0-9a-f]{40}", args.commit))
        for directory in (args.source, args.job_root, args.evidence, args.python_runtime, args.python_packages):
            require(directory.is_dir())
        require(args.source != args.evidence and not args.evidence.is_relative_to(args.job_root)
            and not args.job_root.is_relative_to(args.evidence))
        for directory in (args.job_root, args.evidence):
            info = directory.stat()
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        require(not list(args.job_root.iterdir()))
        self.save("run.claim.json", {"schema": self.CLAIM_SCHEMA,
            "sourceCommit": args.commit, "jobRoot": str(args.job_root)})
        phase, success, armed, cleanup = "inputs", False, False, False
        failure = None
        errors = []
        begun = time.monotonic()
        try:
            require(self.command("source-commit", ["git", "rev-parse", "HEAD"], 10).decode().strip() == args.commit)
            require(not self.command("source-status", ["git", "status", "--porcelain=v1"], 10).strip())
            require(self.SOURCE_FILE == args.source / self.SOURCE_SCRIPT)
            sys.path.insert(0, str(args.source))
            recipe = importlib.import_module(self.RECIPE_MODULE)
            from scripts.prepare_operator_catalog_fixture import bind, digest

            for path, expected in ((args.binary, args.expected_binary_sha256),
                    (args.go, args.expected_go_sha256), (args.node, recipe.NODE_SHA256),
                    (args.initializer, recipe.base.INITIALIZER_SHA256)):
                require(path.is_file() and not path.is_symlink() and digest(path) == expected)
            require(LIBATOMIC.is_file() and (args.python_runtime / "pyvenv.cfg").is_file()
                and (args.source / self.NODE_EXAMPLE_DIRECTORY / "node_modules").is_dir())
            config = recipe.build(args.source, args.binary, args.initializer, args.job_root,
                args.node, args.source / self.NODE_EXAMPLE_DIRECTORY,
                expected_binary_sha256=args.expected_binary_sha256)
            self.project, self.services = config["name"], config["services"]
            runtime_services = (RUNTIME_SERVICES - {"x"}) | {self.PROVIDER_SERVICE}
            require(set(self.services) == runtime_services | {"initialize", self.PROVIDER_PKI_SERVICE, "basic-pki"}
                and "networks" not in config)
            check = self.services["check"]
            check["image"], check["entrypoint"] = PYTHON_IMAGE, ["/example-python/bin/python", "-B"]
            require(check["command"][0] == self.CHECKER_SCRIPT)
            require(check["command"][check["command"].index("--timeout-seconds") + 1] == "180")
            check["command"] += ["--expected-go-sha256", args.expected_go_sha256,
                "--expected-initial-revision", "1"]
            node_target = "/app/" + self.NODE_EXAMPLE_DIRECTORY + "/node_modules"
            require([mount for mount in check["volumes"] if mount["target"] == node_target] ==
                [bind(args.source / self.NODE_EXAMPLE_DIRECTORY / "node_modules", node_target)])
            check["volumes"] += [bind(LIBATOMIC, "/usr/lib/x86_64-linux-gnu/libatomic.so.1"),
                bind(args.python_runtime, "/example-python"),
                bind(args.python_packages, "/example-python/lib/python3.12/site-packages"),
                bind(args.go, self.GO_MOUNT_TARGET)]
            require(all("requests-ca" not in mount["target"] for mount in check["volumes"])
                and len({mount["target"] for mount in check["volumes"]}) == len(check["volumes"]))
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
                json.dump(config, output, sort_keys=True, indent=2)
                output.write("\n")
            compose = ["docker", "compose", "-f", str(compose_path), "-p", self.project]
            self.save("run-inputs.json", {"sourceCommit": args.commit,
                "binarySha256": args.expected_binary_sha256, "goSha256": args.expected_go_sha256,
                "nodeSha256": recipe.NODE_SHA256, "initializerSha256": recipe.base.INITIALIZER_SHA256,
                "composeSha256": digest(compose_path), "project": self.project, "images": image_ids,
                "pythonRuntime": str(args.python_runtime), "pythonPackages": str(args.python_packages),
                "cachedDependenciesReused": True, "dependencyPayloadRehashed": False,
                "syntheticOnly": True, "productionReady": False, self.REAL_PROVIDER_VERIFIED: False})
            for phase, seconds, arguments in (
                ("initialize", 30, ["--profile", "prepare", "run", "--rm", "--no-deps", "--pull", "never", "initialize"]),
                (self.PROVIDER_PKI_SERVICE, 30, ["--profile", self.PROVIDER_PKI_SERVICE, "run", "--rm", "--no-deps", "--pull", "never", self.PROVIDER_PKI_SERVICE]),
                ("network", 25, ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "20", "network"]),
                ("baseline", 95, ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "80", self.PROVIDER_SERVICE, "catchplate", "decision-gate-rs"]),
                ("basic-pki", 30, ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"]),
                ("edge", 15, ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"])):
                self.command(phase, compose + arguments, seconds)
            phase = "revision"
            code = "import http.client,json; from pathlib import Path; c=http.client.HTTPConnection('127.0.0.1',3000,timeout=4); c.request('GET','/api/operator-demo/catalog',headers={'Connection':'close','X-Catchplate-Admin-Token':Path('/run/secrets/catchplate/admin.token').read_text().strip()}); r=c.getresponse(); raw=r.read(1048577); assert r.status==200 and len(raw)<=1048576; d=json.loads(raw); assert d['schema']=='catchplate.operatorCatalog/v1' and all(d[k]==[] for k in ('credentials','applications','access_rules')); v=d['revision']; assert type(v) is int and 1<=v<=3; print(v); c.close()"
            revision = int(self.command(phase, compose + ["exec", "-T", "catchplate", "python", "-B", "-c", code], 10))
            check["command"][-1] = str(revision)
            with compose_path.open("w", encoding="utf-8") as output:
                json.dump(config, output, sort_keys=True, indent=2)
                output.write("\n")
            self.save("selected-revision.json", {"revision": revision, "composeSha256": digest(compose_path)})
            phase = "create-check"
            self.command(phase, compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build", "--pull", "never", "--no-deps", "check"], 15)
            rows = self.container_rows("created")
            require(len(rows) == 6 and {row["Config"]["Labels"]["com.docker.compose.service"] for row in rows} == runtime_services)
            network = next(row for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "network")
            observations = []
            for row in rows:
                name = row["Config"]["Labels"]["com.docker.compose.service"]
                service, host = self.services[name], row["HostConfig"]
                require(row["RestartCount"] == 0 and not host["Privileged"] and host["ReadonlyRootfs"]
                    and not host["PortBindings"] and row["Image"] == image_ids[service["image"]])
                require(host["NetworkMode"] == ("none" if name == "network" else "container:" + network["Id"]))
                actual = {(mount["Source"], mount["Destination"], not mount["RW"]) for mount in row["Mounts"] if mount["Type"] == "bind"}
                require(actual == {(mount["source"], mount["target"], mount["read_only"]) for mount in service["volumes"]})
                require(row["State"]["Status"] == ("created" if name == "check" else "running"))
                if name in {"network", self.PROVIDER_SERVICE, "edge"}:
                    started = datetime.datetime.fromisoformat(row["State"]["StartedAt"].replace("Z", "+00:00"))
                    age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
                    require(0 <= age < (45 if name == "edge" else 105))
                observations.append({"id": row["Id"], "service": name, "state": row["State"]["Status"],
                    "network": host["NetworkMode"], "bindMounts": len(actual), "image": row["Image"]})
            self.save("container-observations.json", observations)
            phase = "running-binary"
            actual = self.command(phase, compose + ["exec", "-T", "decision-gate-rs", "python", "-c",
                "import hashlib; print(hashlib.sha256(open('/usr/local/bin/catchplate-decision-gate','rb').read()).hexdigest())"], 10).decode().strip()
            require(actual == args.expected_binary_sha256)
            checker = next(row["Id"] for row in rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check")
            phase = "checker"
            self.command("checker-start", ["docker", "start", checker], 10)
            exit_code = int(self.command("checker-wait", ["docker", "wait", checker], 190))
            raw = self.command("checker-result", ["docker", "logs", checker], 10)
            terminal = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", checker], 10))
            require(exit_code == 0 and terminal["Status"] == "exited" and terminal["ExitCode"] == 0 and not terminal["OOMKilled"])
            importlib.import_module(self.CHECKER_MODULE).validate_success_result(json.loads(raw))
            success, phase = True, "complete"
        except (Exception, KeyboardInterrupt) as error:
            # Details remain in bounded phase logs; never print environment,
            # token-bearing input, provider content, or exception representations.
            success = False
            failure = failure_site(error, args.source)
        finally:
            if armed:
                cleanup, errors = self.cleanup()
            self.save("terminal.json", {"schema": self.TERMINAL_SCHEMA, "phase": phase,
                "success": success, "cleanup": cleanup, "cleanupErrors": errors,
                "elapsedSeconds": round(time.monotonic() - begun, 3),
                "syntheticOnly": True, "productionReady": False, self.REAL_PROVIDER_VERIFIED: False,
                **({"failureSite": failure} if failure is not None else {})})
            print(json.dumps({"phase": phase, "success": success, "cleanup": cleanup}), flush=True)
        return 0 if success and cleanup else 1


def main(run_type=Run, *, description=__doc__):
    parser = argparse.ArgumentParser(description=description)
    for name in ("source", "job-root", "evidence", "binary", "node", "go", "python-runtime", "python-packages", "initializer"):
        parser.add_argument("--" + name, type=absolute_path, required=True)
    parser.add_argument("--commit", required=True)
    for name in ("expected-binary-sha256", "expected-go-sha256"):
        parser.add_argument("--" + name, type=sha256, required=True)
    os.umask(0o077)
    return run_type(parser.parse_args()).execute()


if __name__ == "__main__":
    raise SystemExit(main())
