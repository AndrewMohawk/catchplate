"""Supplied edge TLS validation and explicit replacement; no app/state reset."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import ssl
import time
from urllib.parse import urlsplit
import uuid

from . import config, process, state
from .config import InstallError

CERTIFICATE_LIMIT = 1024 * 1024
PRIVATE_KEY_LIMIT = 64 * 1024
MAX_CHAIN_CERTIFICATES = 16
TLS_FILES = ("edge-secrets/tls.crt", "edge-secrets/tls.key")
PENDING_FILE = "tls-replacement.json"


def _certificate_blocks(certificate: bytes) -> list[bytes]:
    pattern = rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    blocks = re.findall(pattern, certificate, flags=re.DOTALL)
    if (not 1 <= len(blocks) <= MAX_CHAIN_CERTIFICATES
            or re.sub(pattern, b"", certificate, flags=re.DOTALL).strip()):
        raise InstallError("Use a PEM certificate chain with the server certificate first.")
    return blocks


def _dns_match(pattern: str, host: str) -> bool:
    pattern = pattern.lower()
    if pattern == host:
        return True
    # Only a complete single-label wildcard, never a partial or multi-label one.
    return (pattern.startswith("*.") and pattern.count("*") == 1
        and pattern.count(".") >= 2 and host.count(".") == pattern.count(".")
        and host.endswith(pattern[1:]))


def _leaf_details(certificate: bytes, hosts: tuple[str, str]) -> None:
    raw = process.run(["openssl", "x509", "-noout", "-startdate", "-enddate",
        "-ext", "subjectAltName"], input=certificate, timeout=10)
    try:
        if len(raw) > 16384:
            raise ValueError()
        lines = raw.decode("ascii").splitlines()
        before = [line.removeprefix("notBefore=") for line in lines if line.startswith("notBefore=")]
        after = [line.removeprefix("notAfter=") for line in lines if line.startswith("notAfter=")]
        san = [index for index, line in enumerate(lines) if line.strip() in {
            "X509v3 Subject Alternative Name:", "X509v3 Subject Alternative Name: critical"}]
        if len(before) != 1 or len(after) != 1 or len(san) != 1:
            raise ValueError()
        begins, expires = ssl.cert_time_to_seconds(before[0]), ssl.cert_time_to_seconds(after[0])
        now = time.time()
        if not 0 < begins <= now < expires:
            raise ValueError()
        names = [item.strip()[4:] for item in ",".join(lines[san[0] + 1:]).split(",")
            if item.strip().startswith("DNS:")]
        if not names or any(not any(_dns_match(name, host) for name in names) for host in hosts):
            raise ValueError()
    except (ValueError, UnicodeError, OverflowError):
        raise InstallError("The server certificate must be currently valid and cover both configured hostnames in DNS subject alternative names.") from None


def validate_tls_pair(certificate: Path, private_key: Path,
    console_host: str, proxy_host: str) -> tuple[bytes, bytes]:
    """Shared by init and replace. Key bytes enter OpenSSL only through stdin."""
    hosts = (console_host, proxy_host)
    if len(set(hosts)) != 2 or any(config.origin("https://" + host) != "https://" + host for host in hosts):
        raise InstallError("TLS validation requires the two distinct configured DNS hostnames.")
    cert = config.read_file(certificate, maximum=CERTIFICATE_LIMIT)
    key = config.read_file(private_key, maximum=PRIVATE_KEY_LIMIT, private=True)
    blocks = _certificate_blocks(cert)
    if not re.fullmatch(rb"\s*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n]+-----END \1-----\s*", key):
        raise InstallError("Use one unencrypted PEM private key with mode 0400 or 0600.")
    # Parse every supplied chain member; only the first is the served leaf.
    for block in blocks:
        process.run(["openssl", "x509", "-noout"], input=block, timeout=10)
    _leaf_details(blocks[0], hosts)
    public = process.run(["openssl", "x509", "-pubkey", "-noout"], input=blocks[0], timeout=10)
    cert_public = process.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, timeout=10)
    key_public = process.run(["openssl", "pkey", "-pubout", "-outform", "DER", "-passin", "pass:"], input=key, timeout=10)
    if not cert_public or cert_public != key_public:
        raise InstallError("The supplied private key does not match the server certificate.")
    return cert, key


def _leaf_pin(certificate: bytes) -> str:
    return state.digest(process.run(["openssl", "x509", "-outform", "DER"], input=certificate, timeout=10))


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _pending(state_dir: Path) -> bool:
    try:
        (state_dir / PENDING_FILE).lstat()
        return True
    except FileNotFoundError:
        return False


def _backup(state_dir: Path, certificate: bytes, private_key: bytes, manifest: bytes) -> Path:
    directory = state_dir / "tls-backups"
    try:
        directory.mkdir(mode=0o700)
        _sync_directory(state_dir)
    except FileExistsError:
        pass
    state._directory(directory)
    backup = directory / str(uuid.uuid4())
    backup.mkdir(mode=0o700)
    _sync_directory(directory)
    for name, data in (("tls.crt", certificate), ("tls.key", private_key), ("manifest.json", manifest)):
        state.write_file(backup / name, data)
    return backup


def _clear_pending(state_dir: Path, expected: bytes) -> None:
    marker = state_dir / PENDING_FILE
    if config.read_file(marker, private=True) != expected:
        raise InstallError("TLS recovery state changed; retain the marker and backup for inspection.")
    marker.unlink()
    try:
        _sync_directory(state_dir)
    except OSError:
        # Unlink without a confirmed directory fsync is not a committed finish.
        # Restore the operation marker before attempting ordinary rollback.
        state.write_file(marker, expected)
        raise


_PROBE = """import hashlib,json,socket,ssl,sys
hosts,pin=json.loads(sys.argv[1])
context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname=False
context.verify_mode=ssl.CERT_NONE
for host in hosts:
    with socket.create_connection(('edge',8443),timeout=3) as connection:
        with context.wrap_socket(connection,server_hostname=host) as secured:
            actual='sha256:'+hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()
            if actual!=pin: raise SystemExit(1)
print(json.dumps({'verified_hostnames':len(hosts),'certificate_sha256':pin}))
"""


def _probe_served_tls(manifest: dict, certificate: bytes) -> dict:
    # Trust is the prevalidated exact installed leaf, including self-signed
    # deployments. This is NOT an unverified HTTP/provider request. It sends no
    # application data and never reads credentials, CA private keys or databases.
    from . import lifecycle
    hosts = [urlsplit(manifest["config"][name]).hostname for name in ("console_origin", "proxy_origin")]
    expected = {"verified_hostnames": 2, "certificate_sha256": _leaf_pin(certificate)}
    reply = lifecycle._compose(manifest, "exec", "-T", "catchplate", "python", "-I", "-B", "-c",
        _PROBE, json.dumps([hosts, expected["certificate_sha256"]], separators=(",", ":")))
    if config.parse_json(reply) != expected:
        raise InstallError("The running edge did not confirm the replacement certificate for both hostnames.")
    return expected


def replace_tls(state_dir: Path, certificate: Path, private_key: Path) -> dict:
    """One locked, recoverable edge-only operation, never an atomic-pair claim."""
    from . import lifecycle
    process.require_host()
    state_dir = config.absolute_path(str(state_dir))
    with state.instance_lock(state_dir):
        if _pending(state_dir):
            raise InstallError("An incomplete TLS replacement is retained. Inspect tls-replacement.json and its private backup; restore the recorded certificate, key and manifest before starting or replacing TLS. No replay was attempted.")
        manifest = state.load_manifest(state_dir)
        origins = manifest["config"]
        cert, key = validate_tls_pair(certificate, private_key,
            urlsplit(origins["console_origin"]).hostname, urlsplit(origins["proxy_origin"]).hostname)
        new_pins = {TLS_FILES[0]: state.digest(cert), TLS_FILES[1]: state.digest(key)}
        if all(manifest["files"][name] == pin for name, pin in new_pins.items()):
            return state.result(manifest, "replace-tls", "unchanged", changed=False,
                services={"edge": "unchanged"}, backup=None)
        old_cert = config.read_file(state_dir / TLS_FILES[0], maximum=CERTIFICATE_LIMIT, private=True)
        old_key = config.read_file(state_dir / TLS_FILES[1], maximum=PRIVATE_KEY_LIMIT, private=True)
        old_manifest = config.read_file(state_dir / "manifest.json", maximum=131072, private=True)
        was_running = lifecycle.edge_running(manifest)
        backup = _backup(state_dir, old_cert, old_key, old_manifest)
        marker = state.encoded({"schema": "catchplate.standaloneTlsReplacement/v1",
            "instance_id": manifest["instance_id"], "backup": str(backup.relative_to(state_dir)),
            "previous_manifest_sha256": state.digest(old_manifest), "new_files": new_pins,
            "edge_was_running": was_running})
        state.write_file(state_dir / PENDING_FILE, marker)
        changed = copy.deepcopy(manifest)
        changed["files"].update(new_pins)
        reload_attempted = False
        verified = None
        try:
            # Each replacement is individually durable. The marker makes a
            # crash between files explicit; lifecycle start refuses that state.
            state.write_file(state_dir / TLS_FILES[0], cert, owner=10001, exclusive=False)
            state.write_file(state_dir / TLS_FILES[1], key, owner=10001, exclusive=False)
            state.write_manifest(state_dir, changed)
            state.load_manifest(state_dir)
            if was_running:
                reload_attempted = True
                if lifecycle.edge_reload(state_dir, changed).get("reloaded") is not True:
                    raise InstallError("The previously running edge was not restarted; TLS replacement was not confirmed.")
                verified = _probe_served_tls(changed, cert)
            _clear_pending(state_dir, marker)
        except Exception:
            try:
                state.write_file(state_dir / TLS_FILES[0], old_cert, owner=10001, exclusive=False)
                state.write_file(state_dir / TLS_FILES[1], old_key, owner=10001, exclusive=False)
                state.write_file(state_dir / "manifest.json", old_manifest, exclusive=False)
                state.load_manifest(state_dir)
                if reload_attempted:
                    if lifecycle.edge_reload(state_dir, manifest).get("reloaded") is not True:
                        raise InstallError("The previous edge certificate could not be confirmed.")
                    _probe_served_tls(manifest, old_cert)
                _clear_pending(state_dir, marker)
            except Exception:
                raise InstallError("TLS replacement and recovery could not be confirmed. Preserve the tls-backups entry and any tls-replacement.json marker. Other application data was not reset; inspect and restore the recorded certificate, key and manifest before starting or replacing TLS.") from None
            raise InstallError("TLS replacement failed; the previous certificate, key and manifest were restored. The private tls-backups entry was retained. No application or decision-gate restart was requested.") from None
        return state.result(changed, "replace-tls", "ready" if was_running else "stopped",
            changed=True, services={"edge": "restarted" if was_running else "stopped_unchanged"},
            backup=str(backup), tls=verified, application_data="not_modified")
