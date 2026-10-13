#!/usr/bin/env python3
"""One pre-pinned managed-X/three-SDK private fixture; never a deployment.

No download, build, provider URL override or retry. Original keeper/edge clocks
bound the checker; cleanup has its own single60s bound and retains failed state.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import prepare_operator_x_post_fixture as recipe
from scripts.run_operator_npm_example_fixture import NpmExampleRun, environment, memory_bytes
from scripts.run_operator_x_examples_fixture import absolute_path, sha256, require, failure_site, limit_command_logs, MAX_LOG_BYTES
from scripts.run_ordinary_regression import child_exit_status, stop_group

SOURCE_SCRIPT = "scripts/run_operator_x_post_fixture.py"
WORK_SECONDS, CLEANUP_SECONDS = 390, 60

# Fixed read-only observation inside inspected containers. No app import, key
# bytes, database read, lock creation or custody material enters this receipt.
PUBLIC_PROBE = r'''
import fcntl, hashlib, json, os, signal, stat, sys, time
from pathlib import Path
signal.alarm(5)
mode, initial = sys.argv[1:]
assert mode in ('app','gate') and initial in ('0','1') and os.geteuid()==os.getegid()==10001
root=Path('/data/gate-runtime') if mode=='app' else Path('/data')
def identity(path,directory=False):
    s=path.lstat()
    assert (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1)
    assert s.st_uid==s.st_gid==10001
    if directory: assert stat.S_IMODE(s.st_mode)==0o700
    return [s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid,s.st_size]
def bounded(path,limit):
    before=identity(path); assert before[2]==0o600 and 0<before[5]<=limit
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f: raw=f.read(limit+1)
    assert len(raw)==before[5] and identity(path)==before
    return raw
leaves=('.operator-publication.lock','.serverware-operator-demo.json','mitmproxy/mitmproxy-ca-cert.pem','mitmproxy/mitmproxy-ca.pem')
fd=os.open('/data/.operator-publication.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    until=time.monotonic()+2
    while True:
        try: fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB); break
        except BlockingIOError:
            assert time.monotonic()<until
            time.sleep(.025)
    rows={name:identity(Path('/data')/name) for name in leaves}
    assert rows[leaves[0]][2]==0o600 and rows[leaves[0]][5]==0
    assert [os.fstat(fd).st_dev,os.fstat(fd).st_ino]==rows[leaves[0]][:2]
    assert rows[leaves[1]][2]==rows[leaves[3]][2]==0o600 and all(rows[name][5]>0 for name in leaves[1:])
    directory=identity(root,True)[:5]; identity(root/'mitmproxy',True)
    assert set(os.listdir(root))=={'policy-bundle.json','operator-x-configuration.json','mitmproxy',*leaves[:2]}
    assert set(os.listdir(root/'mitmproxy'))=={'mitmproxy-ca-cert.pem','mitmproxy-ca.pem'}
    policy=bounded(root/'policy-bundle.json',4194304)
    configuration=bounded(root/'operator-x-configuration.json',32768)
    document=json.loads(configuration)
    assert document['schema']=='serverware.operatorXGateConfiguration/v1'
    if initial=='1': assert document['operation'] is None and document['profile_binding_digest'] is None
    if mode=='app':
        assert bounded(Path('/data/policy-bundle.json'),4194304)==policy
        for name in leaves:
            item=identity(root/name); assert item[2]==item[5]==0
    else:
        assert not Path('/x-custody').exists()
    print(json.dumps({'directory':directory,'leaves':rows,
        'policySha256':hashlib.sha256(policy).hexdigest(),
        'configurationSha256':hashlib.sha256(configuration).hexdigest()}))
finally:
    os.close(fd)
'''


class XPostRun(NpmExampleRun):
    """Existing exact-ID discovery/cleanup, with owned group cleanup on exit."""

    def command(self, name, arguments, seconds=30):
        require(re.fullmatch(r"[a-z0-9-]{1,80}", name) and 0 < seconds <= 210)
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            require(remaining > 6, "X posting phase budget expired")
            seconds = min(seconds, remaining - 6)
        print(name, flush=True)
        output = self.args.evidence / (name + ".stdout.log")
        with output.open("xb") as out, (self.args.evidence / (name + ".stderr.log")).open("xb") as err:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                cwd=self.args.source, start_new_session=True, preexec_fn=limit_command_logs)
            until = time.monotonic() + seconds
            try:
                while True:
                    status = child_exit_status(process)
                    require(time.monotonic() < until, "X posting command timed out")
                    if status is not None:
                        break
                    time.sleep(min(0.05, max(0, until - time.monotonic())))
            finally:
                stop_group(process)  # WNOWAIT keeps the leader ID reserved until descendants are killed.
        require(status == 0, "private X posting phase failed")
        with output.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        require(len(raw) <= MAX_LOG_BYTES, "X posting command output exceeded bound")
        return raw

    def inputs(self, suffix):
        self.source_unchanged(suffix)
        args = self.args
        for path, expected in ((args.binary, args.expected_binary_sha256), (args.go, args.expected_go_sha256),
                (args.node, recipe.NODE_SHA256), (args.initializer, recipe.base.INITIALIZER_SHA256),
                (recipe.LIBATOMIC, recipe.LIBATOMIC_SHA256)):
            require(path.is_file() and path.resolve() == path and not path.is_symlink()
                and path.stat().st_mode & 4 and recipe.base.digest(path) == expected, "pinned input differs")
        adjacent = args.source / recipe.NODE_MODULES
        require(adjacent.is_dir() and not adjacent.is_symlink() and adjacent.resolve() == adjacent,
            "existing posting node_modules mountpoint required")
        if args.node_modules != adjacent:
            require(not list(adjacent.iterdir()), "external Node payload requires empty mountpoint")
        observed = recipe.dependencies(args.node_modules, args.python_runtime, args.python_packages)
        require(recipe.dependencies_sha256(observed) == args.expected_dependencies_sha256, "full SDK payload differs")
        self.save("dependencies-" + suffix + ".json", observed)
        return observed

    def public_view(self, container, mode, suffix, *, initial):
        require(re.fullmatch(r"[0-9a-f]{64}", container) and mode in {"app", "gate"})
        return json.loads(self.command("curated-" + mode + "-" + suffix,
            ["docker", "exec", container, "python", "-B", "-c", PUBLIC_PROBE, mode, "1" if initial else "0"], 6))

    def inspect_runtime(self, config, image_ids, *, keeper_anchor):
        rows = self.container_rows("created")
        require(len(rows) == 6 and {row["Config"]["Labels"]["com.docker.compose.service"]
            for row in rows} == recipe.RUNTIME_SERVICES, "six exact runtime services required")
        by_name = {row["Config"]["Labels"]["com.docker.compose.service"]: row for row in rows}
        network = by_name["network"]
        for name, row in by_name.items():
            service, host, actual = config["services"][name], row["HostConfig"], row["Config"]
            require(row["RestartCount"] == 0 and not row["State"]["OOMKilled"] and not host["Privileged"]
                and host["ReadonlyRootfs"] and not host["PortBindings"] and row["Image"] == image_ids[service["image"]]
                and host["NetworkMode"] == ("none" if name == "network" else "container:" + network["Id"]))
            require(host["CapDrop"] == ["ALL"]
                and {value.removeprefix("CAP_") for value in host["CapAdd"] or []} == set(service.get("cap_add", []))
                and set(host["SecurityOpt"]) in ({"no-new-privileges:true"}, {"no-new-privileges"})
                and actual["User"] == service["user"] and (actual["Entrypoint"] or []) == service["entrypoint"]
                and (actual["Cmd"] or []) == service["command"] and actual["WorkingDir"] == service["working_dir"]
                and environment(actual["Env"]) == {**self.image_environments[service["image"]], **service.get("environment", {})})
            require(host["Memory"] == host["MemorySwap"] == memory_bytes(service["mem_limit"])
                and host["NanoCpus"] == int(service["cpus"] * 10**9) and host["PidsLimit"] == service["pids_limit"]
                and bool(host.get("Init")) == service["init"] and host["RestartPolicy"]["Name"] == "no"
                and not any(host.get(key) for key in ("Devices", "DeviceRequests", "VolumesFrom", "ExtraHosts", "PidMode")))
            require(host.get("Sysctls", {}) == service.get("sysctls", {})
                and host["LogConfig"] == {"Type": service["logging"]["driver"], "Config": service["logging"]["options"]}
                and host.get("Tmpfs", {}) == dict(value.split(":", 1) for value in service["tmpfs"])
                and not host.get("Binds") and all(mount["Type"] in {"bind", "tmpfs"} for mount in row["Mounts"]))
            mounts = {(mount["Source"], mount["Destination"], not mount["RW"])
                for mount in row["Mounts"] if mount["Type"] == "bind"}
            require(len(mounts) == len(service["volumes"]) and mounts == {
                (mount["source"], mount["target"], mount["read_only"]) for mount in service["volumes"]})
            require(row["State"]["Status"] == ("created" if name == "check" else "running"))
            if name in {"network", "provider", "serverware", "decision-gate-rs"}:
                require(row["State"].get("Health", {}).get("Status") == "healthy")
            if name in {"network", "provider", "edge"}:
                started = datetime.datetime.fromisoformat(row["State"]["StartedAt"].replace("Z", "+00:00"))
                age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
                limit = recipe.PRECHECK_SECONDS if name != "edge" else recipe.EDGE_SECONDS - recipe.CHECKER_OUTER_SECONDS
                require(0 <= age < limit, "original X fixture lifetime insufficient")
        require(time.monotonic() - keeper_anchor < recipe.PRECHECK_SECONDS)
        self.save("container-observations.json", [{"id": row["Id"], "service": name,
            "image": row["Image"], "state": row["State"]["Status"]} for name, row in sorted(by_name.items())])
        self.wait_edge_ready(by_name["edge"]["Id"])
        self.edge_started_at = by_name["edge"]["State"]["StartedAt"]
        return {name: row["Id"] for name, row in by_name.items()}

    def admit_checker_window(self, edge, *, keeper_anchor, work_anchor):
        state = json.loads(self.command("edge-launch-state", ["docker", "inspect", "--format", "{{json .State}}", edge], 3))
        require(state["Status"] == "running" and not state["OOMKilled"]
            and state["StartedAt"] == self.edge_started_at, "original edge identity changed")
        started = datetime.datetime.fromisoformat(state["StartedAt"].replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
        require(0 <= age < recipe.EDGE_SECONDS - recipe.CHECKER_OUTER_SECONDS,
            "original edge remaining lifetime insufficient")
        now = time.monotonic()
        require(now - keeper_anchor < recipe.PRECHECK_SECONDS, "original keeper preparation budget expired")
        cutoff = min(work_anchor + WORK_SECONDS, keeper_anchor + recipe.KEEPER_SECONDS - 15)
        require(cutoff - now > recipe.CHECKER_OUTER_SECONDS, "original checker work budget insufficient")
        return cutoff

    def start_app_then_gate(self, compose):
        self.command("app-start", compose + ["up", "-d", "--no-build", "--pull", "never", "--wait",
            "--wait-timeout", "30", "provider", "serverware"], 35)
        rows = self.container_rows("app-ready")
        names = {row["Config"]["Labels"]["com.docker.compose.service"]: row for row in rows}
        require(set(names) == {"network", "provider", "serverware"}, "gate must not exist before app publication")
        self.initial_view = self.public_view(names["serverware"]["Id"], "app", "before-gate", initial=True)
        self.command("gate-start", compose + ["up", "-d", "--no-build", "--pull", "never", "--no-deps",
            "--wait", "--wait-timeout", "15", "decision-gate-rs"], 20)

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
        self.save("run.claim.json", {"schema": "serverware.privateXPostRunClaim/v1",
            "sourceCommit": args.commit, "jobRoot": str(args.job_root)})
        phase, success, armed, clean = "inputs", False, False, False
        errors, failure, begun = [], None, time.monotonic()
        self.deadline = begun + WORK_SECONDS
        try:
            require(Path(__file__).resolve() == args.source / SOURCE_SCRIPT)
            before = self.inputs("before")
            config = recipe.build(args.source, args.binary, args.initializer, args.job_root, args.node,
                args.node_modules, args.python_runtime, args.python_packages, args.go,
                expected_binary_sha256=args.expected_binary_sha256, expected_go_sha256=args.expected_go_sha256,
                expected_dependencies_sha256=args.expected_dependencies_sha256)
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
            dependency_path = args.job_root / "dependencies.json"
            with dependency_path.open("x", encoding="ascii") as stream:
                json.dump(before, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
                stream.flush(); os.fsync(stream.fileno())
            dependency_path.chmod(0o444)
            require(recipe.base.digest(dependency_path) == args.expected_dependencies_sha256)
            compose_path = args.job_root / "compose.json"
            with compose_path.open("x", encoding="utf-8") as stream:
                json.dump(config, stream, sort_keys=True, indent=2); stream.write("\n")
                stream.flush(); os.fsync(stream.fileno())
            compose = ["docker", "compose", "-f", str(compose_path), "-p", self.project]
            self.save("run-inputs.json", {"sourceCommit": args.commit, "binarySha256": args.expected_binary_sha256,
                "goSha256": args.expected_go_sha256, "nodeSha256": recipe.NODE_SHA256,
                "dependenciesSha256": args.expected_dependencies_sha256, "libatomicSha256": recipe.LIBATOMIC_SHA256,
                "initializerSha256": recipe.base.INITIALIZER_SHA256, "composeSha256": recipe.base.digest(compose_path),
                "project": self.project, "images": image_ids, "initialProviderTokenSeconds": recipe.INITIAL_TOKEN_SECONDS,
                "checkerSeconds": recipe.CHECKER_SECONDS, "keeperSeconds": recipe.KEEPER_SECONDS,
                "edgeSeconds": recipe.EDGE_SECONDS, "workSeconds": WORK_SECONDS, "cleanupSeconds": CLEANUP_SECONDS,
                "dependencyPayloadRehashed": True, "syntheticOnly": True, "realXVerified": False, "productionReady": False})
            for phase, profile, limit in (("initialize", "prepare", 35), ("x-post-pki", "x-post-pki", 25)):
                self.command(phase, compose + ["--profile", profile, "run", "--rm", "--no-deps", "--pull", "never", phase], limit)
            phase, keeper_anchor = "network", time.monotonic()
            self.deadline = min(begun + WORK_SECONDS, keeper_anchor + recipe.PRECHECK_SECONDS)
            self.command(phase, compose + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "15", "network"], 20)
            phase = "app-before-gate"
            self.start_app_then_gate(compose)
            self.command("basic-pki", compose + ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"], 25)
            self.command("edge", compose + ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"], 10)
            phase = "revision"
            code = "import http.client,json; from pathlib import Path; c=http.client.HTTPConnection('127.0.0.1',3000,timeout=3); c.request('GET','/api/operator-demo/catalog',headers={'Connection':'close','X-Serverware-Admin-Token':Path('/run/secrets/serverware/admin.token').read_text().strip()}); r=c.getresponse(); raw=r.read(1048577); assert r.status==200 and len(raw)<=1048576; d=json.loads(raw); assert d['schema']=='serverware.operatorCatalog/v1' and all(d[k]==[] for k in ('credentials','applications','access_rules')); v=d['revision']; assert type(v) is int and 1<=v<=3; print(v); c.close()"
            revision = int(self.command(phase, compose + ["exec", "-T", "serverware", "python", "-B", "-c", code], 5))
            check = self.services["check"]
            check["command"][check["command"].index("--expected-initial-revision") + 1] = str(revision)
            with compose_path.open("w", encoding="utf-8") as stream:
                json.dump(config, stream, sort_keys=True, indent=2); stream.write("\n")
                stream.flush(); os.fsync(stream.fileno())
            self.save("selected-revision.json", {"revision": revision, "composeSha256": recipe.base.digest(compose_path)})
            self.command("create-check", compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build",
                "--pull", "never", "--no-deps", "check"], 10)
            phase = "runtime-inspection"
            identities = self.inspect_runtime(config, image_ids, keeper_anchor=keeper_anchor)
            app_view = self.public_view(identities["serverware"], "app", "before", initial=True)
            gate_view = self.public_view(identities["decision-gate-rs"], "gate", "before", initial=True)
            require(app_view == gate_view == self.initial_view, "original curated publication identity differs")
            actual = self.command("running-binary", ["docker", "exec", identities["decision-gate-rs"], "python", "-B", "-c",
                "import hashlib; print(hashlib.sha256(open('/usr/local/bin/serverware-decision-gate','rb').read()).hexdigest())"], 5).decode().strip()
            require(actual == args.expected_binary_sha256)
            self.command("network-proof", ["docker", "exec", identities["provider"], "python", "-B", "-c",
                "from scripts.operator_x_post_fixture_network import assert_isolated_network; assert_isolated_network()"], 5)
            # Same original keeper cutoff; no service or token timer is reset.
            self.deadline = self.admit_checker_window(identities["edge"], keeper_anchor=keeper_anchor, work_anchor=begun)
            phase = "checker"
            checker = identities["check"]
            self.command("checker-start", ["docker", "start", checker], 10)
            exit_code = int(self.command("checker-wait", ["docker", "wait", checker], 190))
            raw = self.command("checker-result", ["docker", "logs", checker], 5)
            state = json.loads(self.command("checker-state", ["docker", "inspect", "--format", "{{json .State}}", checker], 5))
            require(exit_code == 0 and state["Status"] == "exited" and state["ExitCode"] == 0 and not state["OOMKilled"])
            from scripts.check_operator_x_post import validate_success_result
            result = json.loads(raw); validate_success_result(result)
            require(result["dataPlaneBinaryDigest"] == "sha256:" + args.expected_binary_sha256
                and result["goExampleSha256"] == args.expected_go_sha256
                and result["dependenciesSha256"] == args.expected_dependencies_sha256)
            phase = "immutable-inputs"
            final_app = self.public_view(identities["serverware"], "app", "after", initial=False)
            final_gate = self.public_view(identities["decision-gate-rs"], "gate", "after", initial=False)
            require(final_app == final_gate and all(final_app[key] == app_view[key] for key in ("directory", "leaves")))
            require(self.inputs("after") == before and recipe.base.digest(dependency_path) == args.expected_dependencies_sha256)
            final_rows = self.container_rows("final")
            require({row["Config"]["Labels"]["com.docker.compose.service"]: row["Id"] for row in final_rows} == identities
                and all(row["RestartCount"] == 0 and not row["State"]["OOMKilled"] for row in final_rows))
            success, phase = True, "complete"
        except (Exception, KeyboardInterrupt) as error:
            failure = failure_site(error, args.source)
        finally:
            if armed:
                clean, errors = self.cleanup()
            self.save("terminal.json", {"schema": "serverware.privateXPostRun/v1", "phase": phase,
                "success": success, "cleanup": clean, "cleanupErrors": errors,
                "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True,
                "realXVerified": False, "productionReady": False,
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
    return XPostRun(args).execute()


if __name__ == "__main__":
    raise SystemExit(main())
