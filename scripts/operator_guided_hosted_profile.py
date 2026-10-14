"""Closed GitHub CI runtime provenance, never a native-authority admission."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

PROFILE = "github-hosted-v1"
SCHEMA = "serverware.guidedHostedProvision/v1"
CLIENT_IMAGE = "python@sha256:edd0b3ec946cc68bd20e39480bd03929016d0fb6254cbf870cd3bc55ea25116d"
CLIENT_ID = "sha256:61d53b56a648da09aa966c5cc46a7e751aea2b38d01f33b04456a9f289685be9"
GATE_IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
PYTHON, CURL = "/usr/local/bin/python3.12", "/usr/bin/curl"
PROVISION_MOUNT = "/hosted-provision.json"
LABEL = "serverware.guided-hosted"
PIN_FILES = ("Dockerfile", "requirements.lock", ".dockerignore",
    "scripts/operator_guided_hosted_profile.py", "scripts/provision_operator_guided_hosted.py")
HEX = re.compile(r"[0-9a-f]{64}")


def require(value, message="hosted guided profile refused"):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_pins(source):
    return {name: digest((source / name).read_bytes()) for name in PIN_FILES}


def github_identity(environment):
    require(environment.get("GITHUB_ACTIONS") == "true" and environment.get("RUNNER_OS") == "Linux")
    value = {key: environment.get(name) for key, name in (
        ("repository", "GITHUB_REPOSITORY"), ("runId", "GITHUB_RUN_ID"), ("runAttempt", "GITHUB_RUN_ATTEMPT"))}
    require(all(type(item) is str for item in value.values())
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["repository"])
        and all(re.fullmatch(r"[1-9][0-9]{0,19}", value[key]) for key in ("runId", "runAttempt")))
    return value


def namespace(github):
    return "serverware-guided-hosted-" + github["runId"] + "-" + github["runAttempt"]


def validate_curl(value):
    require(type(value) is dict and set(value) == {"path", "sha256", "bytes", "version", "protocols", "features"}
        and value["path"] == CURL and type(value["sha256"]) is str and HEX.fullmatch(value["sha256"])
        and type(value["bytes"]) is int and 0 < value["bytes"] <= 67108864
        and type(value["version"]) is str and 0 < len(value["version"]) <= 1024
        and value["version"].startswith("curl ") and value["version"].isascii()
        and "\n" not in value["version"] and "\r" not in value["version"])
    for key in ("protocols", "features"):
        require(type(value[key]) is list and 1 <= len(value[key]) <= 64
            and all(type(item) is str and re.fullmatch(r"[A-Za-z0-9_.+-]{1,40}", item) for item in value[key])
            and value[key] == sorted(set(value[key])))
    require("https" in value["protocols"] and {"SSL", "HTTPS-proxy"} <= set(value["features"]))


def validate(value, *, source=None, revision=None, github=None):
    require(type(value) is dict and set(value) == {"schema", "profile", "sourceRevision", "sourcePins", "github",
        "app", "client", "gate", "curl", "metadataContainerRemoved", "nativeAuthority", "journeyExecuted"}
        and value["schema"] == SCHEMA and value["profile"] == PROFILE
        and type(value["sourceRevision"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["sourceRevision"])
        and value["metadataContainerRemoved"] is True and value["nativeAuthority"] is False
        and value["journeyExecuted"] is False)
    gh = value["github"]
    require(type(gh) is dict and set(gh) == {"repository", "runId", "runAttempt"})
    require(github_identity({"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": gh["repository"],
        "GITHUB_RUN_ID": gh["runId"], "GITHUB_RUN_ATTEMPT": gh["runAttempt"]}) == gh)
    require(type(value["sourcePins"]) is dict and set(value["sourcePins"]) == set(PIN_FILES)
        and all(type(item) is str and HEX.fullmatch(item) for item in value["sourcePins"].values()))
    app, client, gate = value["app"], value["client"], value["gate"]
    require(type(app) is dict and set(app) == {"id", "tag", "target", "labels"}
        and type(app["id"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", app["id"])
        and app["tag"] == namespace(gh) + ":runtime" and app["target"] == "production-runtime"
        and app["labels"] == {LABEL: namespace(gh), LABEL + ".source": value["sourceRevision"]})
    require(client == {"reference": CLIENT_IMAGE, "id": CLIENT_ID, "python": PYTHON, "entrypoint": None})
    require(type(gate) is dict and set(gate) == {"reference", "id"} and gate["reference"] == GATE_IMAGE
        and type(gate["id"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", gate["id"]))
    validate_curl(value["curl"])
    require(source is None or value["sourcePins"] == source_pins(source))
    require(revision is None or value["sourceRevision"] == revision)
    require(github is None or gh == github)
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def read(path, **kwargs):
    require(isinstance(path, Path) and path.is_absolute() and not path.is_symlink() and path.resolve() == path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_mode & 0o022 == 0
        and 0 < before.st_size <= 65536)
    raw = path.read_bytes(); after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and len(raw) <= 65536)
    return validate(json.loads(raw, object_pairs_hook=_pairs), **kwargs)


def curl_file(path, expected):
    validate_curl(expected)
    info = path.lstat()
    require(str(path) == CURL and path.resolve() == path and stat.S_ISREG(info.st_mode)
        and info.st_size == expected["bytes"] and digest(path.read_bytes()) == expected["sha256"])


# Only the exact immutable client runs this, without mounts or network.
CURL_PROBE = r'''
import hashlib,json,pathlib,stat,subprocess,sys,signal
signal.alarm(10)
python=pathlib.Path('/usr/local/bin/python3.12')
assert sys.version_info[:3]==(3,12,15) and sys.executable==str(python)
assert python.resolve()==python and stat.S_ISREG(python.lstat().st_mode)
p=pathlib.Path('/usr/bin/curl'); s=p.lstat()
assert p.resolve()==p and stat.S_ISREG(s.st_mode) and 0<s.st_size<=67108864
r=subprocess.run([str(p),'--version'],check=True,timeout=3,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LANG':'C'})
assert len(r.stdout)<=16384 and not r.stderr
lines=r.stdout.decode('ascii').splitlines()
assert len(lines) in (3,4) and (len(lines)==3 or lines[1].startswith('Release-Date: '))
assert lines[-2].startswith('Protocols: ') and lines[-1].startswith('Features: ')
print(json.dumps({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':s.st_size,
    'version':lines[0],'protocols':sorted(set(lines[-2].split()[1:])),'features':sorted(set(lines[-1].split()[1:]))}))
'''
