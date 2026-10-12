"""Closed synthetic Alchemy JSON-RPC receiver; no provider or wallet actions.

Every arrival is counted before HTTP/request validation. Only the private
observation GET is off-count. Accepted request telemetry contains independently
validated, closed read-only RPC bytes, never authentication or arbitrary bodies.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import HTTPServer
import json
import os
from pathlib import Path
import re
import signal
import ssl
import time

from scripts import operator_github_fixture as base
from scripts.operator_alchemy_fixture_network import (
    FIXTURE_IP, PROVIDER_HOSTS, assert_isolated_network, prepare_network_files,
)

SCHEMA = "serverware.privateAlchemyExampleObservations/v1"
CLIENTS = ("node", "python", "go")
CASES = ("success", "rpc-error", "error429", "wrong-id", "oversize", "reflection", "invalid-json")
MAX_ATTEMPTS, MAX_BODY = 24, 65536
CHAIN, TARGET = "eth-mainnet", "/v2"
HOSTS = dict(zip(("eth-mainnet", "eth-sepolia"), PROVIDER_HOSTS))
ORIGIN = "https://" + HOSTS[CHAIN]
CHAIN_IDS = {"eth-mainnet": "0x1", "eth-sepolia": "0xaa36a7"}
BLOCK_NUMBER = "0x10"
METHODS = ("eth_chainId", "eth_blockNumber")
TOKEN = "serverware_alchemy_synthetic_only_8a4671d8096a47f488aad7ee207489ab"
AGENTS = {"node": None, "python": "web3.py/7.15.0/web3.providers.rpc.rpc.HTTPProvider", "go": "Go-http-client/1.1"}
MEDIA = {"node": "application/json", "python": "*/*", "go": "application/json", "probe": "application/json"}
ROW_KEYS = {"ordinal", "accepted", "client", "case", "method", "target", "chain", "rpcMethod", "requestId",
    "semanticHeaders", "requestBodyBase64", "requestBodySha256", "requestBodyBytes", "responseBodySha256",
    "responseBodyBytes", "status", "providerCredentialMatched", "proxyAuthorizationPresent", "allParsedHeadersValidated"}


def require(condition):
    if not condition:
        raise ValueError("private Alchemy examples fixture refused")


def _headers(fields):
    require(type(fields) is list and len(fields) <= 14)
    require(all(type(name) is str and type(value) is str and name.isascii() and value.isascii()
        and 0 < len(name) <= 64 and 0 < len(value) <= 8192
        and all(32 <= ord(char) <= 126 for char in value) for name, value in fields))
    normalized = [(name.lower(), value) for name, value in fields]
    require(len({name for name, _ in normalized}) == len(normalized))
    return dict(normalized)


def classify(method, raw_target, fields):
    require(method == "POST" and raw_target == TARGET)
    headers = _headers(fields)
    if ("user-agent" not in headers and headers.get("alchemy-ethers-sdk-method") == "send"
            and headers.get("alchemy-ethers-sdk-version") == "3.6.5"):
        return "node", "success"
    for client in ("python", "go"):
        if headers.get("user-agent") == AGENTS[client]:
            return client, "success"
    for case in CASES[1:]:
        if headers.get("user-agent") == "serverware-alchemy-probe/" + case:
            return "probe", case
    raise ValueError("private Alchemy client fingerprint refused")


def validated_headers(client, fields, case="success"):
    require(client in (*CLIENTS, "probe") and type(case) is str and case in CASES
        and (case != "success") == (client == "probe"))
    headers = _headers(fields)
    required = {"host", "authorization", "content-type", "content-length", "accept"}
    required.update({"alchemy-ethers-sdk-method", "alchemy-ethers-sdk-version"} if client == "node"
        else {"accept", "user-agent"})
    require(required <= headers.keys() <= required | {"connection"}
        and headers["host"] in PROVIDER_HOSTS
        and hmac.compare_digest(headers["authorization"], "Bearer " + TOKEN)
        and headers["content-type"] == "application/json"
        and headers["accept"] == MEDIA[client]
        and re.fullmatch(r"[1-9][0-9]{0,4}", headers["content-length"])
        and 1 <= int(headers["content-length"]) <= MAX_BODY
        and headers.get("connection", "close") in {"close", "keep-alive"})
    if client == "node":
        require(headers["alchemy-ethers-sdk-method"] == "send" and headers["alchemy-ethers-sdk-version"] == "3.6.5")
    else:
        require(headers["accept"] == MEDIA[client]
            and headers["user-agent"] == ("serverware-alchemy-probe/" + case if client == "probe" else AGENTS[client]))
    # Preserve observed framing for the checker to join independently to the
    # real gate's canonical request; do not assume framing is unsigned/absent.
    return {name: headers[name] for name in sorted(required - {"host", "authorization"})}


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def request(raw, *, client, case="success"):
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_BODY)
    def nonfinite(_value):
        raise ValueError("private Alchemy JSON refused")
    def integer(value):
        require(value == "0" or re.fullmatch(r"[1-9][0-9]*", value))
        return int(value)
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
        parse_int=integer, parse_float=nonfinite, parse_constant=nonfinite)
    require(type(value) is dict and set(value) == {"jsonrpc", "id", "method", "params"}
        and value["jsonrpc"] == "2.0" and type(value["method"]) is str and value["method"] in METHODS
        and type(value["params"]) is list and value["params"] == [])
    identifier = value["id"]
    if client == "probe":
        require(case in CASES[1:] and type(identifier) is str and identifier == "probe:" + case)
    else:
        require(client in CLIENTS and case == "success" and type(identifier) is int
            and 0 <= identifier <= (1 << 53) - 1)
        if client in {"python", "go"}:
            require(identifier == METHODS.index(value["method"]) + (1 if client == "go" else 0))
    return value


def status(case="success"):
    require(type(case) is str and case in CASES)
    return 429 if case == "error429" else 200


def body(case, request_id, method="eth_chainId", chain=CHAIN):
    require(type(case) is str and case in CASES and method in METHODS and chain in CHAIN_IDS)
    value = {"jsonrpc": "2.0", "id": request_id,
        "result": CHAIN_IDS[chain] if method == "eth_chainId" else BLOCK_NUMBER}
    if case in {"rpc-error", "error429"}:
        return base.encoded({"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32000, "message": "Synthetic fixture RPC error", "data": {"synthetic": True}}})
    if case == "wrong-id":
        value["id"] = request_id + 1 if type(request_id) is int else request_id + ":wrong"
    if case == "reflection":
        value["unselected"] = {"credential": TOKEN}
    if case == "oversize":
        value["padding"] = ""
        value["padding"] = "x" * (MAX_BODY + 1 - len(base.encoded(value)))
    if case == "invalid-json":
        return b'{"jsonrpc":'
    return base.encoded(value)


def setup(root, marker):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    require(root == Path("/upstream-data/alchemy") and not root.exists() and not root.is_symlink()
        and root.parent.is_dir() and root.parent.stat().st_uid == os.geteuid() == 10001)
    assert_isolated_network(attached=False)
    require(json.loads(marker.read_bytes()) == {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private synthetic Alchemy fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PROVIDER_HOSTS[0])]))
        .issuer_name(subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in PROVIDER_HOSTS]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    root.mkdir(mode=0o700)
    for name, data in {"ca.pem": ca.public_bytes(serialization.Encoding.PEM),
            "cert.pem": leaf.public_bytes(serialization.Encoding.PEM),
            "key.pem": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())}.items():
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    prepare_network_files()
    print('{"ok":true,"syntheticOnly":true,"providerContact":false}', flush=True)


class Fixture(HTTPServer):
    def __init__(self, address, context):
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.attempts, self.total, self.timeout = [], 0, 0.5


class Handler(base.Handler):
    def record_arrival(self):
        if getattr(self, "arrival", None) is None:
            self.server.total += 1
            self.arrival = {"ordinal": self.server.total, "accepted": False}
            if self.server.total <= MAX_ATTEMPTS:
                self.server.attempts.append(self.arrival)
        return self.arrival

    def parse_request(self):
        self.arrival = None
        row = self.record_arrival()
        parsed = super().parse_request()
        if parsed and self.command == "GET" and self.path == "/_fixture/observations":
            if row["ordinal"] <= MAX_ATTEMPTS:
                require(self.server.attempts[-1] is row)
                self.server.attempts.pop()
            self.server.total -= 1
            self.arrival = None
        return parsed

    def send_error(self, code, message=None, explain=None):
        self.record_arrival()  # Also covers request-line refusal before parsing.
        self.send(400, b'{"message":"synthetic Alchemy fixture refused"}')

    def do_GET(self):
        if self.path == "/_fixture/observations":
            self.send(200, base.encoded({"schema": SCHEMA, "syntheticOnly": True,
                "total": self.server.total, "attempts": deepcopy(self.server.attempts)}))
            return
        self.resource()

    def resource(self):
        row = self.record_arrival()
        try:
            require(self.server.total <= MAX_ATTEMPTS)
            fields = list(self.headers.raw_items())
            client, case = classify(self.command, self.path, fields)
            semantic = validated_headers(client, fields, case)
            raw = self.rfile.read(int(semantic["content-length"]))
            require(len(raw) == int(semantic["content-length"]))
            document = request(raw, client=client, case=case)
            host = _headers(fields)["host"]
            chain = next(chain for chain, expected in HOSTS.items() if host == expected)
            response = body(case, document["id"], document["method"], chain)
            row.update(client=client, case=case, accepted=True, method="POST", target=TARGET,
                chain=chain, rpcMethod=document["method"], requestId=document["id"], semanticHeaders=semantic,
                requestBodyBase64=base64.b64encode(raw).decode("ascii"), requestBodyBytes=len(raw),
                requestBodySha256="sha256:" + hashlib.sha256(raw).hexdigest(),
                responseBodySha256="sha256:" + hashlib.sha256(response).hexdigest(), responseBodyBytes=len(response),
                status=status(case), providerCredentialMatched=True, proxyAuthorizationPresent=False,
                allParsedHeadersValidated=True)
            self.send(status(case), response)
        except (ValueError, OSError, RecursionError):
            self.send(400, b'{"message":"synthetic Alchemy fixture refused"}')

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.setup:
        signal.alarm(20)
        setup(Path("/upstream-data/alchemy"), Path("/private-fixture.json"))
        return
    assert_isolated_network()
    require(60 <= args.lifetime_seconds <= 300)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/alchemy/cert.pem", "/alchemy/key.pem")
    signal.alarm(args.lifetime_seconds + 5)
    with Fixture((FIXTURE_IP, 443), context) as server:
        deadline = time.monotonic() + args.lifetime_seconds
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
