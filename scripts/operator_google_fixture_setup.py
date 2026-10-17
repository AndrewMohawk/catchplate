"""Fixed initialization and loopback-only namespace setup for the Google fixture.

Only the reviewed initializer and a NEW private runtime are accepted. The
network keeper has no host-network option and no route/hostname arguments.
No application source is imported by initialization or network configuration.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import socket
import struct
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.operator_google_fixture import (
    CLIENT_SECRET, CONTROL_HOST, GOOGLE_HOSTS, GOOGLE_IP, MARKER,
    assert_isolated_network, require,
)
from scripts.prepare_operator_catalog_fixture import INITIALIZER_SHA256


ROOT = Path("/fixture-runtime")


def _write(path, value, mode=0o400):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as target:
        target.write(value)
        target.flush()
        os.fsync(target.fileno())
        os.fchmod(target.fileno(), mode)
        os.fchown(target.fileno(), 10001, 10001)


def initialize():
    require(os.geteuid() == 0)
    initializer = Path("/initialize.py")
    require(not initializer.is_symlink() and hashlib.sha256(initializer.read_bytes()).hexdigest() == INITIALIZER_SHA256)
    # Reuse the existing fresh-root, token-file and marker producer unchanged.
    runpy.run_path(str(initializer))["initialize"](ROOT)
    for name in ("google-data", "network-data"):
        (ROOT / name).mkdir(mode=0o700)
        os.chown(ROOT / name, 10001, 10001)
    google = ROOT / "google-data"
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated Google Fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
            key_cert_sign=True, key_agreement=False, content_commitment=False,
            data_encipherment=False, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    server = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated Google Fixture")]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)
            for name in (*GOOGLE_HOSTS, CONTROL_HOST)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    _write(google / "ca.pem", ca.public_bytes(serialization.Encoding.PEM), 0o444)
    _write(google / "server.pem", server.public_bytes(serialization.Encoding.PEM), 0o444)
    _write(google / "server-key.pem", key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _write(ROOT / "service-secrets/google-client.secret", CLIENT_SECRET.encode("ascii"))
    _write(ROOT / ".private-google-fixture.json", (json.dumps(MARKER, sort_keys=True) + "\n").encode("ascii"))
    hosts = "127.0.0.1 localhost catchplate decision-gate-rs " + CONTROL_HOST + "\n"
    hosts += GOOGLE_IP + " " + " ".join(GOOGLE_HOSTS) + "\n"
    _write(ROOT / "fixture-hosts", hosts.encode("ascii"), 0o444)
    _write(ROOT / "fixture-resolv.conf", b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", 0o444)
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print("Fresh synthetic Google runtime initialized; no values emitted.")


def attach_loopback_address():
    """One fixed RTM_NEWADDR; no external interface, default route or command."""
    require(os.geteuid() == 0)
    assert_isolated_network(attached=False)
    require(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip() == "0")
    index = socket.if_nametoindex("lo")
    address = socket.inet_aton(GOOGLE_IP)
    # ifaddrmsg + IFA_ADDRESS/IFA_LOCAL. EXCL refuses a reused namespace.
    payload = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, index)
    payload += struct.pack("=HH4s", 8, 1, address) + struct.pack("=HH4s", 8, 2, address)
    packet = struct.pack("=IHHII", 16 + len(payload), 20, 1 | 4 | 0x400 | 0x200, 1, 0) + payload
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(3)
        channel.bind((0, 0))
        channel.sendto(packet, (0, 0))
        response = channel.recv(4096)
    require(len(response) >= 20)
    length, kind, _, sequence, _ = struct.unpack_from("=IHHII", response)
    require(length == len(response) and kind == 2 and sequence == 1
        and struct.unpack_from("=i", response, 16)[0] == 0)
    assert_isolated_network()


def keep_namespace(lifetime_seconds):
    require(120 <= lifetime_seconds <= 360)
    attach_loopback_address()
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(status[name].strip(), 16) == 0 for name in ("CapEff", "CapPrm", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1")
    assert_isolated_network()
    ready = Path("/fixture-network/ready")
    descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        json.dump({"schema": "catchplate.googleFixtureNetwork/v1", "network": "none",
            "interfaces": ["lo"], "address": GOOGLE_IP, "effectiveCapabilities": 0}, output)
        output.flush()
        os.fsync(output.fileno())
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    stop.wait(lifetime_seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("initialize", "network"))
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "initialize":
        initialize()
    else:
        keep_namespace(args.lifetime_seconds)


if __name__ == "__main__":
    main()
