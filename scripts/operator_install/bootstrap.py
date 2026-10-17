"""Fresh-instance provisioning only; never adopt or overwrite an existing store."""
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import uuid
from urllib.parse import urlsplit

from . import compose, lifecycle, process, state, tls
from .config import InstallError, check_path, load_config, parse_json, read_file

DIRECTORIES = ("app-data", "gate-data", "service-secrets", "provider-custody", "x-custody",
    "notification-custody", "ecr-artifacts", "edge-secrets", "edge")
TEMPLATE = Path(__file__).resolve().parents[2] / "docker/catchplate-standalone/nginx.conf.template"


def _inspect_image(reference: str) -> dict:
    value = parse_json(process.run(["docker", "image", "inspect", "--format", "{{json .}}", reference], timeout=15))
    if (type(value) is not dict or type(value.get("Id")) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["Id"])
            or value.get("Os") != "linux" or value.get("Architecture") != "amd64"):
        raise InstallError("Select an already-built Linux amd64 image; init never builds or pulls images.")
    digests = value.get("RepoDigests") or []
    if type(digests) is not list or any(type(item) is not str or not re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}", item) for item in digests):
        raise InstallError("The selected image has malformed content identities.")
    return {"id": value["Id"], "repo_digests": digests, "requested": reference,
        "labels": value.get("Config", {}).get("Labels") or {}}


def _artifact(image: dict) -> dict:
    labels = image["labels"]
    if (type(labels) is not dict or labels.get("io.catchplate.artifact.schema") != "catchplate.standaloneArtifact/v1"
            or labels.get("io.catchplate.artifact.path") != "/opt/catchplate/artifact.json"):
        raise InstallError("The paired image is not a standalone Catchplate artifact; build it explicitly first.")
    # A networkless, read-only metadata utility, not app or gate startup. There
    # are no host data mounts, provider credentials or secret command arguments.
    raw = process.run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
        "--pids-limit", "32", "--memory", "64m", "--cpus", "0.25", "--entrypoint", "python",
        image["id"], "-I", "-B", "-c",
        "import sys; sys.stdout.buffer.write(open('/opt/catchplate/artifact.json','rb').read(8193))"], timeout=20)
    if len(raw) > 8192:
        raise InstallError("The paired image artifact exceeds its metadata bound.")
    value = state.artifact(parse_json(raw))
    if labels.get("org.opencontainers.image.revision") != value["sourceRevision"]:
        raise InstallError("The paired image revision label does not match its artifact.")
    return value


def _network_preflight(config, instance_id):
    """Probe the two selected networks before committing a fresh private store."""
    created = []
    try:
        for name in ("control", "outbound"):
            command = ["docker", "network", "create", "--driver", "bridge", "--label",
                lifecycle.LABEL + "=" + instance_id]
            if name == "control":
                command.append("--internal")
            if config["network_subnets"] is not None:
                command.extend(("--subnet", config["network_subnets"][name]))
            command.append("catchplate-preflight-" + instance_id + "-" + name)
            identifiers = lifecycle._identifiers(process.run(command, timeout=15))
            if len(identifiers) != 1:
                raise InstallError("Docker did not identify its temporary network.")
            created.append(identifiers[0])
    except InstallError as error:
        refusal = InstallError("Docker cannot allocate both installation networks. Select two unused network_subnets after checking local Docker/LAN/VPN ranges; no installation state was initialized.")
        if getattr(error, "diagnostic_path", None) is not None:
            refusal.diagnostic_path = error.diagnostic_path
        raise refusal from None
    finally:
        for identifier in reversed(created):
            labels = parse_json(process.run(["docker", "network", "inspect", "--format", "{{json .Labels}}", identifier], timeout=10))
            if type(labels) is not dict or labels.get(lifecycle.LABEL) != instance_id:
                raise InstallError("Temporary network ownership changed; cleanup was refused. Inspect Docker before retrying.")
            process.run(["docker", "network", "rm", identifier], timeout=15)


def _edge_config(config) -> bytes:
    value = read_file(TEMPLATE).decode("utf-8")
    console, proxy = (urlsplit(config[key]).hostname for key in ("console_origin", "proxy_origin"))
    for key, replacement in (("CONSOLE_HOST", console), ("PROXY_HOST", proxy),
            ("CONSOLE_HOST_REGEX", console.replace(".", r"\."))):
        value = value.replace("${" + key + "}", replacement)
    if "${" in value:
        raise InstallError("The packaged edge template contains unsupported placeholders.")
    return value.encode()


def initialize(config_path: Path, password: bytes) -> dict:
    config = load_config(config_path)
    if type(password) is not bytes or not 12 <= len(password) <= 1024 or any(value in password for value in (b"\x00", b"\n", b"\r")):
        raise InstallError("Choose a console password of 12–1024 bytes without embedded line breaks.")
    root = Path(config["state_dir"])
    check_path(root, missing_leaf=True)
    if root.exists() and (not root.is_dir() or next(root.iterdir(), None) is not None):
        raise InstallError("Initialization refuses existing nonempty state; nothing was replaced.")
    process.require_host()
    lifecycle.resources(config["project_name"], None)
    certificate, key = tls.validate_tls_pair(Path(config["tls_certificate"]), Path(config["tls_private_key"]),
        urlsplit(config["console_origin"]).hostname, urlsplit(config["proxy_origin"]).hostname)
    images = {name: _inspect_image(config[name + "_image"]) for name in ("paired", "edge")}
    artifact = _artifact(images["paired"])
    for name in images:
        config[name + "_image"] = images[name]["id"]
        # Only fixed provenance information belongs in the installed manifest,
        # not arbitrary image labels supplied by another image author.
        images[name].pop("labels")
    hashed = process.run(["openssl", "passwd", "-6", "-stdin"], input=password + b"\n", timeout=10).strip()
    if not re.fullmatch(rb"\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}", hashed):
        raise InstallError("Console password hashing did not return the supported format.")
    instance_id = str(uuid.uuid4())
    rendered = state.encoded(compose.render(config, artifact, instance_id))
    edge = _edge_config(config)
    _network_preflight(config, instance_id)
    # Recheck project collision immediately before writing a private instance.
    lifecycle.resources(config["project_name"], None)
    with state.instance_lock(root, initialize=True):
        for name in DIRECTORIES:
            directory = root / name
            directory.mkdir(mode=0o700)
            os.chown(directory, 10001, 10001)
        tokens = {name: secrets.token_urlsafe(48).encode() for name in state.TOKEN_FILES}
        if len(set(tokens.values())) != len(tokens):
            raise InstallError("Distinct service credentials could not be generated; partial state was preserved.")
        files = {"compose.json": rendered, "edge/nginx.conf": edge,
            "edge-secrets/tls.crt": certificate, "edge-secrets/tls.key": key,
            "edge-secrets/htpasswd": config["admin_username"].encode() + b":" + hashed + b"\n",
            "edge-secrets/operator-admin-header.conf": b'proxy_set_header X-Catchplate-Admin-Token "' + tokens["admin.token"] + b'";\n',
            # The app's service-credential reader requires exact bytes without
            # surrounding whitespace. These are not newline-delimited files.
            **{"service-secrets/" + name: value for name, value in tokens.items()}}
        for name, data in files.items():
            state.write_file(root / name, data, owner=0 if name == "compose.json" else 10001)
        process.run(["docker", "compose", "--project-name", config["project_name"], "--file", str(root / "compose.json"),
            "config", "--quiet"], timeout=15)
        manifest = {"schema": state.SCHEMA, "config": config, "instance_id": instance_id,
            "images": images, "artifact": artifact, "files": {name: state.digest(data) for name, data in files.items()}}
        state.write_manifest(root, manifest, exclusive=True)
    return state.result(manifest, "init", "initialized", image_id=config["paired_image"])
