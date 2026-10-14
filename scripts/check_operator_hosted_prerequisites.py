#!/usr/bin/env python3
"""Hosted setup probe only: user-cgroup ownership and private Docker loopback.

No application, browser, provider, database or native authority is exercised.
The workflow provisions the user manager and image before this fixed probe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time

IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
WORK_SECONDS, CLEANUP_SECONDS = 60, 20
LABEL = "serverware.hosted-prerequisites"
PROPERTIES = {"RuntimeMaxUSec": "3min 5s", "TimeoutStopUSec": "5s", "KillMode": "control-group",
    "Restart": "no", "MemoryMax": "2147483648", "TasksMax": "128", "CPUQuotaPerSecUSec": "1s",
    "UMask": "0077", "NRestarts": "0"}

# Both processes have independent 15s ceilings. The descendant reports SIGTERM;
# its natural timeout is not accepted as proof of normal-exit group cleanup.
DESCENDANT = r'''
import json, os, pathlib, signal, sys, time
p = pathlib.Path(sys.argv[1])
def save(name, value):
    with (p/(name+'.tmp')).open('x') as f: json.dump(value, f)
    (p/(name+'.tmp')).rename(p/name)
def ended(sig, frame):
    save('descendant-ended.json', {'signal': sig, 'pid': os.getpid()})
    raise SystemExit(0)
signal.signal(signal.SIGTERM, ended)
save('descendant-ready.json', {'pid': os.getpid(), 'uid': os.getuid(),
    'cgroup': pathlib.Path('/proc/self/cgroup').read_text(),
    'start': pathlib.Path('/proc/self/stat').read_text().split(') ', 1)[1].split()[19]})
time.sleep(15)
raise SystemExit(74)
'''
SERVICE_CHILD = r'''
import json, os, pathlib, subprocess, sys, time
p = pathlib.Path(sys.argv[1]); deadline = time.monotonic()+15
assert p.resolve() == p and p.stat().st_uid == os.getuid() and p.stat().st_mode & 0o777 == 0o700
child = subprocess.Popen(['/usr/bin/python3', '-I', '-S', '-B', '-c', sys.argv[2], str(p)],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
while not (p/'descendant-ready.json').exists():
    assert time.monotonic() < deadline and child.poll() is None
    time.sleep(.02)
group = pathlib.Path('/proc/self/cgroup').read_text()
assert group.startswith('0::/') and group.count('\n') == 1
cg = pathlib.Path('/sys/fs/cgroup') / group.strip().split('::',1)[1].lstrip('/')
with (p/'ready.json.tmp').open('x') as f:
    json.dump({'pid':os.getpid(),'uid':os.getuid(),'cgroup':group,
        'limits':{name:(cg/name).read_text().strip() for name in ('memory.max','pids.max','cpu.max')},
        'descendant':json.loads((p/'descendant-ready.json').read_text())},f)
(p/'ready.json.tmp').rename(p/'ready.json')
while not (p/'release').exists():
    assert time.monotonic() < deadline and child.poll() is None
    time.sleep(.02)
assert (p/'release').read_bytes() == b'release\n'
'''
SERVER = r'''
import hashlib,json,os,socket,time
started=time.monotonic()
with socket.socket() as s:
    s.settimeout(15); s.bind(('127.0.0.1',40817)); s.listen(1)
    print(json.dumps({'ready':True,'namespace':os.readlink('/proc/self/ns/net')}),flush=True)
    with s.accept()[0] as c:
        c.settimeout(max(.1,15-(time.monotonic()-started)))
        data=b''
        while len(data)<64:
            part=c.recv(64-len(data)); assert part; data+=part
        assert len(data)==64 and all(x in b'0123456789abcdef' for x in data)
        answer=hashlib.sha256(b'serverware-hosted-loopback/v1:'+data).hexdigest().encode()
        c.sendall(answer)
    print(json.dumps({'ok':True,'requestSha256':hashlib.sha256(data).hexdigest(),
        'responseSha256':hashlib.sha256(answer).hexdigest()}),flush=True)
'''
CLIENT = r'''
import hashlib,json,os,socket,sys
data=sys.argv[1].encode(); assert len(data)==64
with socket.create_connection(('127.0.0.1',40817),timeout=5) as s:
    s.settimeout(5); s.sendall(data); answer=b''
    while len(answer)<64:
        part=s.recv(64-len(answer)); assert part; answer+=part
assert answer == hashlib.sha256(b'serverware-hosted-loopback/v1:'+data).hexdigest().encode()
print(json.dumps({'ok':True,'namespace':os.readlink('/proc/self/ns/net'),
    'requestSha256':hashlib.sha256(data).hexdigest(),'responseSha256':hashlib.sha256(answer).hexdigest()}))
'''


def require(value):
    if not value:
        raise ValueError("hosted prerequisite refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def stream_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))


def command_operation(args):
    prefixes = {
        ("/usr/bin/docker","image","inspect"):"docker_image_inspect",
        **{("/usr/bin/docker",name):"docker_"+name for name in ("ps","create","inspect","start","logs","wait","rm")},
        **{("/usr/bin/systemctl","--user",name):"systemctl_"+name.replace("-","_")
            for name in ("list-units","list-unit-files","show","stop")},
    }
    for prefix, operation in prefixes.items():
        if tuple(args[:len(prefix)]) == prefix:
            return operation
    raise ValueError("hosted command operation refused")


class NonzeroCommand(ValueError):
    def __init__(self, operation, exit_code, stderr):
        require(type(exit_code) is int and -64 <= exit_code <= 255
            and type(stderr) is bytes and len(stderr) <= 65536)
        self.diagnostic = {"operation":operation,"exitCode":exit_code,"stderrLength":len(stderr),
            "stderrSha256":hashlib.sha256(stderr).hexdigest(),"category":
                "local_log_compression_invalid" if b"compression cannot be enabled when max file count is 1" in stderr
                else "other_nonzero"}
        super().__init__("hosted command exited nonzero")


class Probe:
    def __init__(self, directory, namespace, environment):
        self.directory, self.namespace, self.environment = directory, namespace, environment
        self.unit = namespace + ".service"
        self.names = [namespace + "-server", namespace + "-client"]
        self.armed_names, self.identities = set(), {}
        self.unit_armed, self.unit_process, self.cgroup = False, None, None
        self.unit_observed = False
        self.deadline = time.monotonic() + WORK_SECONDS

    def command(self, args, seconds=4):
        operation = command_operation(args)
        remaining = min(seconds, self.deadline-time.monotonic()-2)
        require(remaining > 0)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=self.environment, start_new_session=True, preexec_fn=stream_limit)
            try:
                status = process.wait(timeout=remaining)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=2)
            require(out.tell() <= 65536 and err.tell() <= 65536)
            if status != 0:
                err.seek(0); raise NonzeroCommand(operation,status,err.read(65537))
            out.seek(0); return out.read(65537)

    def json_file(self, name):
        path = self.directory/name
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= 4096
                and not path.is_symlink())
            return json.loads(stream.read(4097))

    def until(self, predicate, seconds):
        deadline = min(self.deadline-2, time.monotonic()+seconds)
        while True:
            if predicate():
                return
            require(time.monotonic() < deadline)
            time.sleep(.05)

    def unit_present(self):
        present = bool(self.command(["/usr/bin/systemctl", "--user", "list-units", "--all", "--plain",
            "--no-legend", "--no-pager", self.unit]).strip())
        if present and self.unit_armed:
            self.unit_observed = True
        return present

    def docker_ids(self, name):
        rows = self.command(["/usr/bin/docker", "ps", "-aq", "--no-trunc", "--filter", "name=^/"+name+"$"]).decode().split()
        require(len(rows) <= 1 and all(re.fullmatch(r"[0-9a-f]{64}", row) for row in rows))
        return rows

    def inspect(self, identity, name):
        value = json.loads(self.command(["/usr/bin/docker", "inspect", "--format",
            '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
            '"config":{{json .Config.Labels}},"user":{{json .Config.User}},"host":{{json .HostConfig}},'
            '"state":{{json .State}},"restarts":{{json .RestartCount}},"mounts":{{json .Mounts}}}', identity]))
        require(name in self.names and value["id"] == identity and value["config"].get(LABEL) == self.namespace
            and value["name"] == "/"+name)
        return value

    def effective_container(self, row, network, image_id):
        host = row["host"]
        require(row["image"] == image_id and row["user"] == "65534:65534" and host["NetworkMode"] == network
            and host["ReadonlyRootfs"] is True and host["Privileged"] is False
            and host["Memory"] == 134217728 and host["MemorySwap"] == 134217728
            and host["NanoCpus"] == 1000000000 and host["PidsLimit"] == 32
            and host["CapDrop"] == ["ALL"] and host["SecurityOpt"] == ["no-new-privileges"]
            and host["RestartPolicy"]["Name"] == "no" and host["LogConfig"]["Type"] == "local"
            and host["LogConfig"]["Config"] == {"max-size":"32k","max-file":"1","compress":"false"}
            and host["Tmpfs"] == {"/tmp":"rw,nosuid,nodev,size=16m,mode=1777"}
            and len(row["mounts"]) <= 1 and all(mount.get("Type") == "tmpfs"
                and mount.get("Destination") == "/tmp" and mount.get("RW") is True for mount in row["mounts"])
            and not host["Binds"] and not host["PortBindings"]
            and row["restarts"] == 0 and row["state"]["OOMKilled"] is False)

    def service(self):
        require(not self.unit_present())
        rows = self.command(["/usr/bin/systemctl", "--user", "list-unit-files", "--no-legend", "--no-pager",
            self.unit, "default.target"]).decode().splitlines()
        require([row.split() for row in rows] == [["default.target", "static", "-"]])
        self.unit_armed = True  # Launch uncertainty still owns exact-unit cleanup.
        self.unit_process = subprocess.Popen(["/usr/bin/systemd-run", "--user", "--wait", "--pipe", "--collect",
            "--quiet", "--service-type=exec", "--unit="+self.unit, "--property=RuntimeMaxSec=185",
            "--property=TimeoutStopSec=5", "--property=KillMode=control-group", "--property=Restart=no",
            "--property=MemoryMax=2G", "--property=TasksMax=128", "--property=CPUQuota=100%", "--property=UMask=0077",
            "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "/usr/bin/python3", "-I", "-S", "-B",
            "-c", SERVICE_CHILD, str(self.directory), DESCENDANT], env=self.environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.until(lambda: (self.directory/"ready.json").exists(), 8)
        ready = self.json_file("ready.json"); child = ready["descendant"]
        require(ready["uid"] == child["uid"] == os.getuid() and ready["pid"] != child["pid"]
            and type(ready["pid"]) is int and type(child["pid"]) is int
            and re.fullmatch(r"0::/[A-Za-z0-9_./:@-]+\n", ready["cgroup"])
            and ready["cgroup"] == child["cgroup"])
        group = ready["cgroup"].strip().split("::",1)[1]
        require(group.endswith("/"+self.unit) and ".." not in group.split("/"))
        self.cgroup = Path("/sys/fs/cgroup"+group)
        require(self.cgroup.resolve() == self.cgroup and self.cgroup.is_dir())
        limits = ready["limits"]
        require(limits == {"memory.max":"2147483648","pids.max":"128","cpu.max":"100000 100000"}
            and {key:(self.cgroup/key).read_text().strip() for key in limits} == limits)
        require((Path("/proc")/str(child["pid"])/"cgroup").read_text() == ready["cgroup"])
        show = self.command(["/usr/bin/systemctl", "--user", "show", self.unit,
            "--property="+",".join([*PROPERTIES,"MainPID","ControlGroup","ActiveState","SubState"])]).decode()
        actual = dict(line.split("=",1) for line in show.splitlines())
        require(all(actual.get(key) == value for key,value in PROPERTIES.items())
            and actual.get("MainPID") == str(ready["pid"]) and actual.get("ControlGroup") == group
            and actual.get("ActiveState") == "active" and actual.get("SubState") == "running")
        self.unit_observed = True
        with (self.directory/"release.tmp").open("xb") as stream:
            stream.write(b"release\n")
        (self.directory/"release.tmp").rename(self.directory/"release")
        require(self.unit_process.wait(timeout=min(8,self.deadline-time.monotonic()-2)) == 0)
        self.until(lambda: not self.unit_present() and not self.cgroup.exists(), 3)
        ended = self.json_file("descendant-ended.json")
        require(ended == {"signal":signal.SIGTERM,"pid":child["pid"]})
        proc = Path("/proc")/str(child["pid"])/"stat"
        require(not proc.exists() or proc.read_text().split(") ",1)[1].split()[19] != child["start"])
        return {"unit":self.unit,"uid":ready["uid"],"mainPid":ready["pid"],"descendantPid":child["pid"],
            "cgroup":group,"configured":PROPERTIES,"effective":limits,"normalMainExit":True,
            "descendantTerminatedByGroup":True,"unitCollected":True,"cgroupRemoved":True,"runtimeTimerExpiryTested":False}

    def containers(self):
        for name in self.names:
            require(not self.docker_ids(name))
        image = json.loads(self.command(["/usr/bin/docker", "image", "inspect", "--format", "{{json .Id}}", IMAGE]))
        require(re.fullmatch(r"sha256:[0-9a-f]{64}",image))
        nonce = secrets.token_hex(32)
        for ordinal, code in enumerate((SERVER, CLIENT)):
            name = self.names[ordinal]; network = "none" if ordinal == 0 else "container:"+self.identities[self.names[0]]
            self.armed_names.add(name)
            identity = self.command(["/usr/bin/docker", "create", "--pull", "never", "--name", name,
                "--label", LABEL+"="+self.namespace, "--network", network, "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--memory", "128m", "--memory-swap", "128m", "--cpus", "1",
                "--pids-limit", "32", "--restart", "no", "--log-driver", "local", "--log-opt", "max-size=32k",
                "--log-opt", "max-file=1", "--log-opt", "compress=false",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777", "--user", "65534:65534",
                "--entrypoint", "/usr/local/bin/python", IMAGE, "-I", "-S", "-B", "-c", code, *([nonce] if ordinal else [])], 6).decode().strip()
            require(re.fullmatch(r"[0-9a-f]{64}",identity)); self.identities[name] = identity
            self.effective_container(self.inspect(identity,name),network,image)
            self.command(["/usr/bin/docker","start",identity])
            if ordinal == 0:
                def ready():
                    raw = self.command(["/usr/bin/docker","logs",identity])
                    if not raw.strip(): return False
                    value = json.loads(raw)
                    require(set(value) == {"ready","namespace"} and value["ready"] is True
                        and re.fullmatch(r"net:\[[0-9]+\]",value["namespace"]))
                    self.network_namespace = value["namespace"]; return True
                self.until(ready,5)
        for name in self.names:
            identity = self.identities[name]
            require(self.command(["/usr/bin/docker","wait",identity],8).strip() == b"0")
            row = self.inspect(identity,name)
            self.effective_container(row,"none" if name == self.names[0] else "container:"+self.identities[self.names[0]],image)
            require(row["state"]["Status"] == "exited" and row["state"]["ExitCode"] == 0)
        server = self.command(["/usr/bin/docker","logs",self.identities[self.names[0]]]).decode().splitlines()
        client = json.loads(self.command(["/usr/bin/docker","logs",self.identities[self.names[1]]]))
        request = hashlib.sha256(nonce.encode()).hexdigest()
        answer = hashlib.sha256(b"serverware-hosted-loopback/v1:"+nonce.encode()).hexdigest().encode()
        expected = {"ok":True,"requestSha256":request,"responseSha256":hashlib.sha256(answer).hexdigest()}
        require(len(server) == 2 and json.loads(server[1]) == expected
            and client == {**expected,"namespace":self.network_namespace})
        return {"image":IMAGE,"imageId":image,"containerIds":self.identities.copy(),
            "namespace":self.network_namespace,"networkModes":["none","container:"+self.identities[self.names[0]]],
            "loopbackExchange":expected,"requests":1,"retries":0,"exitedNormally":True}

    def cleanup(self):
        self.deadline = time.monotonic()+CLEANUP_SECONDS
        errors = []
        try:
            launch_completed = self.unit_process is not None and self.unit_process.poll() == 0
            # Finish the one launch client before the terminal manager query;
            # a timed-out observer must not submit a later unnoticed launch.
            if self.unit_process is not None and self.unit_process.poll() is None:
                os.killpg(self.unit_process.pid,signal.SIGKILL)
                self.unit_process.wait(timeout=2)
            if self.unit_armed and self.unit_present():
                self.command(["/usr/bin/systemctl","--user","stop",self.unit],8)
            if self.unit_armed:
                require(not self.unit_present() and (self.cgroup is None or not self.cgroup.exists()))
                # A negative inventory alone cannot close an uncertain launch
                # that the manager may still finish after its client was killed.
                require(self.unit_observed or launch_completed)
        except Exception:
            errors.append("unit_cleanup_unconfirmed")
        for name in reversed(self.names):
            if name not in self.armed_names: continue
            try:
                for identity in self.docker_ids(name):
                    self.inspect(identity,name)  # Exact name and run label, including uncertain create.
                    require(name not in self.identities or self.identities[name] == identity)
                    self.identities[name] = identity
                    self.command(["/usr/bin/docker","rm","--force",identity],4)
                require(not self.docker_ids(name))
                # A lost create response plus current absence is not a
                # cancellation receipt from the daemon; preserve uncertainty.
                require(name in self.identities)
            except Exception:
                errors.append("container_cleanup_unconfirmed")
        return {"ok":not errors,"errors":errors,"secondsLimit":CLEANUP_SECONDS,
            "unit":self.unit,"containerIds":self.identities.copy()}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    require(sys.platform == "linux" and os.getuid() == os.geteuid() != 0
        and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux")
    run, attempt = os.environ.get("GITHUB_RUN_ID",""),os.environ.get("GITHUB_RUN_ATTEMPT","")
    require(re.fullmatch(r"[1-9][0-9]{0,19}",run) and re.fullmatch(r"[1-9][0-9]{0,5}",attempt))
    output = Path(args.output)
    require(output.is_absolute() and output.resolve() == output and output.suffix == ".json"
        and not output.exists() and not output.is_symlink())
    parent = output.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700)
    runtime = Path("/run/user")/str(os.getuid()); bus = "unix:path="+str(runtime/"bus")
    require(os.environ.get("XDG_RUNTIME_DIR") == str(runtime) and os.environ.get("DBUS_SESSION_BUS_ADDRESS") == bus
        and runtime.resolve() == runtime and runtime.stat().st_uid == os.getuid()
        and stat.S_IMODE(runtime.stat().st_mode) == 0o700 and stat.S_ISSOCK((runtime/"bus").stat().st_mode)
        and os.environ.get("DOCKER_HOST") == "unix:///var/run/docker.sock")
    environment = {"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","XDG_RUNTIME_DIR":str(runtime),
        "DBUS_SESSION_BUS_ADDRESS":bus,"DOCKER_HOST":"unix:///var/run/docker.sock"}
    namespace = "serverware-hosted-"+run+"-"+attempt
    result = {"schema":"serverware.hostedPrerequisites/v1","ok":False,"runId":run,"runAttempt":attempt,
        "scope":"setup-only user-cgroup and synthetic private loopback; not guided journey acceptance",
        "appExecuted":False,"browserExecuted":False,"providerExecuted":False,"runtimeTimerExpiryTested":False,
        "guidedArtifactChecksPerformed":False,
        "workSecondsLimit":WORK_SECONDS,"cleanupSecondsLimit":CLEANUP_SECONDS,
        "scriptSha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"service":None,"containers":None}
    with output.open("xb") as receipt:
        directory = Path(tempfile.mkdtemp(prefix="hosted-probe-",dir=output.parent))
        probe = Probe(directory,namespace,environment); stage = "service"; begun = time.monotonic()
        try:
            result["service"] = probe.service(); stage = "containers"; result["containers"] = probe.containers()
            result["workPassed"] = True
        except Exception as error:
            result.update(workPassed=False,failureStage=stage,failureType=type(error).__name__)
            if isinstance(error,NonzeroCommand):
                result["commandFailure"] = error.diagnostic.copy()
            trace = error.__traceback__; line = None
            while trace is not None:
                if trace.tb_frame.f_code.co_filename == __file__ and trace.tb_frame.f_code.co_name != "require":
                    line = trace.tb_lineno
                trace = trace.tb_next
            result["failureLine"] = line
        finally:
            result["workElapsedSeconds"] = round(time.monotonic()-begun,3)
            result["cleanup"] = probe.cleanup()
        # Keep the handshake directory if process cleanup is uncertain. Never
        # remove state files underneath a possibly surviving service child.
        if result["cleanup"]["ok"]:
            try:
                allowed = {name+suffix for name in ("ready.json","descendant-ready.json","descendant-ended.json","release")
                    for suffix in ("",".tmp")}
                require(directory.resolve() == directory and directory.stat().st_uid == os.getuid()
                    and stat.S_IMODE(directory.stat().st_mode) == 0o700)
                entries = list(directory.iterdir())
                require(all(path.name in allowed and not path.is_symlink() and path.is_file() for path in entries))
                for path in entries: path.unlink()
                directory.rmdir()
                result["cleanup"]["temporaryRemoved"] = True
            except Exception:
                result["cleanup"].update(ok=False,temporaryRemoved=False)
                result["cleanup"]["errors"].append("temporary_cleanup_unconfirmed")
        else:
            result["cleanup"]["temporaryRemoved"] = False
        result["ok"] = result["workPassed"] and result["cleanup"]["ok"]
        raw = canonical(result); require(len(raw) <= 16384); receipt.write(raw); receipt.flush(); os.fsync(receipt.fileno())
    print(canonical(result).decode(),end="")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"schema":"serverware.hostedPrerequisites/v1","ok":False,
            "stage":"input-or-receipt","failureType":type(error).__name__}),flush=True)
        raise SystemExit(1)
