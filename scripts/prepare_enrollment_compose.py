#!/usr/bin/env python3
"""Offline, fixed-source enrollment Compose preparation; never release approval.

The provisioner independently supplies the runtime-root public key and expected
configuration digest. A signature does not enroll that supplied root. The actual
bootstrap verifier admits the original signed bytes before overlay selection.
No private key is read, no interpolation or Compose command runs, and no secret
or default policy is generated. The original bootstrap still must be separately
delivered to the control plane through its existing trust-directory mount.

PyYAML 6.0.3 is pinned in the existing requirements.lock. The interpreter, parser,
authority verifier and complete dependency/source closure must be independently
enrolled before executing this tool; a version string or this sidecar is not
that verification. The output remains a single Compose input to the unchanged
production launcher. Its source layout, output and sidecar need release admission.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import math
import os
from pathlib import Path
import posixpath
import re
import secrets
import stat
import sys


ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "docker-compose.production.yml"
OVERLAY = ROOT / "docker-compose.enrollment.yml"
LOCK = ROOT / "requirements.lock"
SCRIPT = ROOT / "scripts" / "prepare_enrollment_compose.py"
PARSER_VERSION = "6.0.3"
MAX_BASE_BYTES = 2 * 1024 * 1024
MAX_OVERLAY_BYTES = 64 * 1024
MAX_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_SCRIPT_BYTES = 256 * 1024
MAX_LOCK_BYTES = 2 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_SCALAR_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PROVENANCE_BYTES = 16 * 1024
TARGET = "/run/secrets/serverware-control-plane-enrollment-signing-key"
SOURCE = ("${SERVERWARE_CONTROL_PLANE_ENROLLMENT_SIGNING_KEY_FILE:"
    "?set preprovisioned root-owned mode 0400 enrollment signing key file}")
SOCKET_TARGET = "/run/serverware/registration-evidence"
SOCKET_SOURCE = ("${SERVERWARE_REGISTRATION_EVIDENCE_SOCKET_DIR:"
    "?set preprovisioned registration evidence signer socket directory}")
PROVENANCE_SCHEMA = "serverware.enrollmentComposePreparation/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_FLOAT = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")


class PreparationError(ValueError):
    pass


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns)


def _directory(path: Path) -> int:
    """Open an existing directory without following any path-component link."""
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(path: Path, maximum: int) -> bytes:
    parent = _directory(path.parent)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise PreparationError("preparation input is not a bounded regular file")
        chunks, offset = [], 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(65536, before.st_size - offset), offset)
            if not chunk:
                raise PreparationError("preparation input ended before its declared size")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(descriptor, 1, offset) or _identity(before) != _identity(os.fstat(descriptor)):
            raise PreparationError("preparation input changed during its bounded read")
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _parser():
    try:
        if metadata.version("PyYAML") != PARSER_VERSION:
            raise PreparationError("offline preparation requires locked PyYAML 6.0.3")
        import yaml
    except (ImportError, metadata.PackageNotFoundError) as exc:
        raise PreparationError("offline preparation requires the enrolled PyYAML 6.0.3 dependency") from exc
    if yaml.__version__ != PARSER_VERSION:
        raise PreparationError("PyYAML module differs from its required distribution version")
    return yaml


def _load_yaml(raw: bytes, yaml) -> dict:
    """Bound the actual parser; reject aliases, merges and lossy scalar forms."""
    class FixedLoader(yaml.SafeLoader):
        def __init__(self, text):
            super().__init__(text)
            self.node_count = self.node_depth = 0

        def compose_node(self, parent, index):
            event = self.peek_event()
            if (isinstance(event, yaml.events.AliasEvent)
                    or getattr(event, "anchor", None) is not None
                    or getattr(event, "tag", None) is not None):
                raise PreparationError("Compose aliases, anchors and explicit tags are forbidden")
            self.node_count += 1
            self.node_depth += 1
            try:
                if self.node_count > MAX_NODES or self.node_depth > MAX_DEPTH:
                    raise PreparationError("Compose YAML exceeds its node or depth bound")
                if isinstance(event, yaml.events.ScalarEvent) and len(event.value.encode("utf-8")) > MAX_SCALAR_BYTES:
                    raise PreparationError("Compose YAML scalar exceeds its byte bound")
                return super().compose_node(parent, index)
            finally:
                self.node_depth -= 1

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, yaml.nodes.MappingNode):
                raise PreparationError("Compose mapping has an unexpected shape")
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if type(key) is not str or key == "<<" or key in result:
                    raise PreparationError("Compose mapping keys must be unique exact strings without merges")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

        def construct_object(self, node, deep=False):
            if isinstance(node, yaml.nodes.ScalarNode):
                kind = node.tag.removeprefix("tag:yaml.org,2002:")
                if kind not in {"str", "null", "bool", "int", "float"}:
                    raise PreparationError("Compose YAML scalar type is not JSON-compatible")
                if kind == "bool" and node.value.lower() not in {"true", "false"}:
                    raise PreparationError("ambiguous YAML 1.1 boolean must be quoted")
                if kind == "int" and _INTEGER.fullmatch(node.value) is None:
                    raise PreparationError("nondecimal or ambiguous YAML integer must be quoted")
                if kind == "float" and _FLOAT.fullmatch(node.value) is None:
                    raise PreparationError("nonfinite or ambiguous YAML float must be quoted")
            result = super().construct_object(node, deep=deep)
            if type(result) is float and not math.isfinite(result):
                raise PreparationError("Compose numeric scalar is not finite")
            return result

    loader = None
    try:
        loader = FixedLoader(raw.decode("utf-8"))
        value = loader.get_single_data()
        if type(value) is not dict:
            raise PreparationError("Compose source must be one mapping document")
        return value
    except (UnicodeError, yaml.YAMLError, OverflowError, RecursionError) as exc:
        raise PreparationError("Compose source cannot be parsed under the fixed bounded profile") from exc
    finally:
        if loader is not None:
            loader.dispose()


def _volume_target(volume) -> str:
    if type(volume) is dict:
        target = volume.get("target")
    elif type(volume) is str:
        # Only delimiters outside uninterpolated ${...} expressions count.
        fields, start, position, depth = [], 0, 0, 0
        while position < len(volume):
            if volume.startswith("${", position):
                depth += 1
                position += 2
                continue
            if volume[position] == "}" and depth:
                depth -= 1
            elif volume[position] == ":" and not depth:
                fields.append(volume[start:position])
                start = position + 1
            position += 1
        fields.append(volume[start:])
        if depth or len(fields) not in (1, 2, 3):
            raise PreparationError("base volume cannot be assigned an unambiguous target")
        target = fields[0] if len(fields) == 1 else fields[1]
    else:
        raise PreparationError("base volume is not a supported exact declaration")
    if (type(target) is not str or not target.startswith("/") or target.startswith("//")
            or "$" in target or "\x00" in target or posixpath.normpath(target) != target):
        raise PreparationError("base volume target is not a fixed normalized absolute path")
    return target


def _server_volumes(base):
    services = base.get("services")
    server = services.get("serverware") if type(services) is dict else None
    volumes = server.get("volumes") if type(server) is dict else None
    if type(volumes) is not list:
        raise PreparationError("fixed production source has no serverware volume list")
    targets = set()
    for volume in volumes:
        target = _volume_target(volume)
        if target in targets:
            raise PreparationError("base serverware volumes have duplicate targets")
        targets.add(target)
        for fixed_target in (TARGET, SOCKET_TARGET):
            if (target == fixed_target or fixed_target.startswith(target.rstrip("/") + "/")
                    or target.startswith(fixed_target + "/")):
                raise PreparationError("base volume collides with a fixed enrollment key or signer socket target")
    return volumes


def _canonical(value, maximum: int) -> bytes:
    encoded = json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(encoded) > maximum:
        raise PreparationError("prepared output exceeds its fixed byte bound")
    return encoded


def _record(raw: bytes) -> dict:
    return {"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def prepare(*, bootstrap_file: Path, runtime_root_public_key_file: Path,
        expected_configuration_digest: str) -> tuple[bytes, bytes]:
    """Return ordinary Compose/provenance bytes, never deployment permission.

    Preserve ROOT as the Compose project directory. Any release relocation must
    independently preserve and admit the same source layout and relative paths.
    Caller-supplied root/digest provenance is a prerequisite, not established here.
    """
    if type(expected_configuration_digest) is not str or _DIGEST.fullmatch(expected_configuration_digest) is None:
        raise PreparationError("expected configuration digest is not canonical SHA-256")
    original = _read_regular(Path(bootstrap_file), MAX_BOOTSTRAP_BYTES)
    root_bytes = _read_regular(Path(runtime_root_public_key_file), MAX_PUBLIC_KEY_BYTES)
    base_bytes = _read_regular(BASE, MAX_BASE_BYTES)
    source_bytes = _read_regular(SCRIPT, MAX_SCRIPT_BYTES)
    lock_bytes = _read_regular(LOCK, MAX_LOCK_BYTES)
    # Fixed repository imports only; no application facade, SQL or ambient root.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware import control_plane_enrollment_bootstrap as bootstrap
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    root = serialization.load_pem_public_key(root_bytes)
    if not isinstance(root, Ed25519PublicKey):
        raise PreparationError("runtime root must be an independently supplied Ed25519 public key")
    work = _ValidationWork(QueryReadValidationLimits())
    admitted = bootstrap._admit_on_work(bootstrap_bytes=original,
        runtime_root_public_key=root, expected_configuration_digest=expected_configuration_digest,
        work=work)
    enabled = admitted.issuer_policy is not None
    if (enabled != (admitted.issuer_private_key_fd is not None)
            or enabled != (admitted.signer_endpoint is not None)):
        raise PreparationError("admitted enrollment policy, key slot and signer endpoint disagree")
    yaml = _parser()
    base = _load_yaml(base_bytes, yaml)
    volumes = _server_volumes(base)
    overlay_bytes = None
    if enabled:
        overlay_bytes = _read_regular(OVERLAY, MAX_OVERLAY_BYTES)
        overlay = _load_yaml(overlay_bytes, yaml)
        expected = {"services": {"serverware": {"volumes": [{"type": "bind",
            "source": SOURCE, "target": TARGET, "read_only": True,
            "bind": {"create_host_path": False}}, {"type": "bind",
            "source": SOCKET_SOURCE, "target": SOCKET_TARGET, "read_only": True,
            "bind": {"create_host_path": False}}]}}}
        # Canonical comparison also distinguishes bools from integers.
        if _canonical(overlay, MAX_OVERLAY_BYTES) != _canonical(expected, MAX_OVERLAY_BYTES):
            raise PreparationError("enrollment overlay differs from its two fixed read-only binds")
        volumes.extend(overlay["services"]["serverware"]["volumes"])
    compose_bytes = _canonical(base, MAX_OUTPUT_BYTES)
    provenance = {"schema": PROVENANCE_SCHEMA,
        "sourceRevision": bootstrap.authority.SOURCE_REVISION,
        "claim": "preparation-only-not-release-approval", "enabled": enabled,
        "configurationDigest": admitted.configuration_digest,
        "projectDirectory": str(ROOT),
        "pathSemantics": "unchanged-relative-paths-require-independently-admitted-same-layout",
        "sources": {"preparer": {"path": "scripts/prepare_enrollment_compose.py", **_record(source_bytes)},
            "base": {"path": BASE.name, **_record(base_bytes)},
            "overlay": None if overlay_bytes is None else {"path": OVERLAY.name, **_record(overlay_bytes)},
            "dependencyLock": {"path": LOCK.name, **_record(lock_bytes)}},
        "bootstrap": _record(original), "runtimeRootPublicKeyFile": _record(root_bytes),
        "parser": {"distribution": "PyYAML", "version": PARSER_VERSION},
        "output": _record(compose_bytes)}
    return compose_bytes, _canonical(provenance, MAX_PROVENANCE_BYTES)


def _publish(output: Path, compose_bytes: bytes, provenance_bytes: bytes) -> None:
    """Publish two complete new files without replacing any existing name.

    Publication is not a two-file transaction. A failure can leave a complete
    artifact without its sidecar; neither is an approval and neither is removed
    or overwritten for an automatic retry. Only owned unpublished temps are removed.
    """
    output = Path(os.path.abspath(output))
    if output.parent != ROOT or len(output.name.encode("utf-8")) > 200:
        raise PreparationError("output must be a new file directly in the fixed repository project directory")
    names = (output.name, output.name + ".provenance.json")
    parent = _directory(ROOT)
    temporary = []
    try:
        for name in names:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise PreparationError("preparation refuses to overwrite an existing output artifact")
        for content in (compose_bytes, provenance_bytes):
            name = ".enrollment-compose-" + secrets.token_hex(16)
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            temporary.append(name)
            try:
                position = 0
                while position < len(content):
                    written = os.write(descriptor, content[position:])
                    if written <= 0:
                        raise PreparationError("preparation output write made no progress")
                    position += written
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for source, destination in zip(tuple(temporary), names):
            os.link(source, destination, src_dir_fd=parent, dst_dir_fd=parent,
                follow_symlinks=False)
            os.unlink(source, dir_fd=parent)
            temporary.remove(source)
            os.fsync(parent)
    finally:
        for name in temporary:
            try:
                os.unlink(name, dir_fd=parent)
            except OSError:
                pass
        os.close(parent)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap-file", required=True, type=Path)
    parser.add_argument("--runtime-root-public-key-file", required=True, type=Path)
    parser.add_argument("--expected-configuration-digest", required=True)
    parser.add_argument("--output", required=True, type=Path,
        help="new Compose JSON directly in the repository root; sidecar adds .provenance.json")
    args = parser.parse_args(argv)
    try:
        originals = prepare(bootstrap_file=args.bootstrap_file,
            runtime_root_public_key_file=args.runtime_root_public_key_file,
            expected_configuration_digest=args.expected_configuration_digest)
        _publish(args.output, *originals)
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit("enrollment Compose preparation failed; no release approval was issued; "
            "complete artifacts may remain and are never overwritten") from None
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
