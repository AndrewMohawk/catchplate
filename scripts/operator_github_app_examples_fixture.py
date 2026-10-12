"""Finite synthetic GitHub App + issue provider, restricted to a private netns.

The oracle uses only a generated PUBLIC signing key. It does not import the
production App protocol, parse a stored credential, or fabricate lease results.
Provisioning and proxied resource requests have separate bounded observations.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import ssl
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from scripts import operator_github_examples_fixture as examples
from scripts import operator_github_fixture as base
from scripts.operator_github_fixture_network import FIXTURE_IP, assert_isolated_network

SCHEMA = "serverware.privateGithubAppExampleObservations/v1"
APP_ID, INSTALLATION_ID, ACCOUNT_ID, REPOSITORY_ID = 123, 456, 700, 900
TOKEN_SECONDS = 120
TOKENS = ("ghs_123_synthetic.initial-token_v1", "ghs_123_synthetic.renewed-token_v2")
INSTALL_PATH = f"/repos/{examples.OWNER}/{examples.REPO}/installation"
MINT_PATH = f"/app/installations/{INSTALLATION_ID}/access_tokens"
REPOSITORIES_PATH = "/installation/repositories?per_page=100&page=1"
PERMISSIONS = {"issues": "read", "metadata": "read"}
MAX_ARRIVALS = 24
require = examples.require


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    def constant(_):
        raise ValueError("synthetic JSON refused")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def verify_jwt(value, public_key, now):
    require(isinstance(value, str) and value.startswith("Bearer ") and len(value) <= 8192)
    parts = value[7:].split(".")
    require(len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts))
    decoded = [base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)) for part in parts]
    require(strict_json(decoded[0]) == {"alg": "RS256", "typ": "JWT"})
    claims = strict_json(decoded[1])
    require(type(claims) is dict and set(claims) == {"iss", "iat", "exp"}
        and claims["iss"] == str(APP_ID) and type(claims["iat"]) is int and type(claims["exp"]) is int
        and now - 90 <= claims["iat"] <= now and now < claims["exp"] <= now + 600
        and claims["exp"] - claims["iat"] == 600)
    public_key.verify(decoded[2], (parts[0] + "." + parts[1]).encode("ascii"),
        padding.PKCS1v15(), hashes.SHA256())


def provisioning_headers(fields, *, post, length):
    require(len(fields) <= 12)
    headers = {name.lower(): value for name, value in fields}
    require(len(headers) == len(fields))
    expected = {"accept", "accept-encoding", "authorization", "user-agent", "x-github-api-version", "host", "connection"}
    require(set(headers) == expected | ({"content-type", "content-length"} if post else set())
        and headers["host"] == "api.github.com" and headers["accept"] == "application/vnd.github+json"
        and headers["accept-encoding"] == "identity" and headers["connection"] == "close"
        and headers["user-agent"] == "serverware-github-app/1" and headers["x-github-api-version"] == "2022-11-28")
    if post:
        require(headers["content-type"] == "application/json" and headers["content-length"] == str(length))
    else:
        require(length == 0)
    return headers


def repository():
    return {"id": REPOSITORY_ID, "name": examples.REPO,
        "full_name": examples.OWNER + "/" + examples.REPO,
        "owner": {"id": ACCOUNT_ID, "login": examples.OWNER}}


class Oracle:
    def __init__(self, public_key):
        require(isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size == 2048)
        self.public_key = public_key
        self.auth, self.attempts, self.mints = [], [], []
        self.total = 0

    def observation(self):
        return {"schema": SCHEMA, "syntheticOnly": True, "total": self.total,
            "auth": deepcopy(self.auth), "attempts": deepcopy(self.attempts), "mints": deepcopy(self.mints)}

    def arrival(self, target):
        self.total += 1
        require(self.total <= MAX_ARRIVALS)
        auth = target in {INSTALL_PATH, MINT_PATH, REPOSITORIES_PATH}
        row = {"ordinal": self.total, "accepted": False}
        (self.auth if auth else self.attempts).append(row)
        return auth, row

    def handle(self, method, target, fields, body, now):
        auth, row = self.arrival(target)
        if auth:
            step, cycle = len(self.auth) - 1, len(self.mints)
            expected = (("GET", INSTALL_PATH), ("POST", MINT_PATH), ("GET", REPOSITORIES_PATH))[step % 3]
            require(step < 6 and (method, target) == expected)
            headers = provisioning_headers(fields, post=method == "POST", length=len(body))
            if step % 3 < 2:
                verify_jwt(headers["authorization"], self.public_key, now)
            else:
                require(hmac.compare_digest(headers["authorization"], "Bearer " + TOKENS[cycle - 1]))
            if step % 3 == 0:
                require((step == 0 and not self.attempts) or
                    (step == 3 and len(self.attempts) == 6 and now > self.mints[0]["expiresAt"]))
                value = {"id": INSTALLATION_ID, "app_id": APP_ID, "account": {
                    "id": ACCOUNT_ID, "login": examples.OWNER, "type": "Organization"},
                    "target_id": ACCOUNT_ID, "target_type": "Organization", "suspended_at": None,
                    "suspended_by": None, "permissions": PERMISSIONS}
                status = 200
            elif step % 3 == 1:
                require(strict_json(body) == {"permissions": PERMISSIONS,
                    **({"repositories": [examples.REPO]} if cycle == 0 else {"repository_ids": [REPOSITORY_ID]})})
                expires = int(now) + (TOKEN_SECONDS if cycle == 0 else 3600)
                self.mints.append({"ordinal": cycle + 1, "issuedAt": int(now), "expiresAt": expires,
                    "selection": "name" if cycle == 0 else "id", "permissions": dict(PERMISSIONS)})
                value = {"token": TOKENS[cycle], "expires_at": datetime.fromtimestamp(expires, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "permissions": PERMISSIONS, "repository_selection": "selected", "repositories": [repository()]}
                status = 201
            else:
                value, status = {"total_count": 1, "repositories": [repository()]}, 200
            row.update(accepted=True, kind=("installation", "mint", "repositories")[step % 3],
                cycle=step // 3 + 1, method=method, status=status, jwtVerified=step % 3 < 2)
            return status, base.encoded(value), ()

        index = len(self.attempts) - 1
        require(index < 12 and body == b"")
        client, page = examples.classify(method, target)
        cycle = index // 6
        require((client, page) == (examples.CLIENTS[(index % 6) // 2], index % 2 + 1)
            and len(self.auth) == (cycle + 1) * 3 and len(self.mints) == cycle + 1
            and self.mints[cycle]["issuedAt"] <= now < self.mints[cycle]["expiresAt"])
        headers = dict((name.lower(), value) for name, value in fields)
        require(len(headers) == len(fields) and hmac.compare_digest(headers.get("authorization", ""), "Bearer " + TOKENS[cycle]))
        # Reuse every stock-client header guard unchanged; only substitute the
        # already-independently-verified synthetic token for its static oracle.
        semantic = examples.validated_headers(client, [(name, "Bearer " + examples.TOKEN if name.lower() == "authorization" else value)
            for name, value in fields])
        output = examples.body(page)
        row.update(accepted=True, client=client, page=page, cycle=cycle + 1, method="GET", target=target,
            semanticHeaders=semantic, requestBodySha256="sha256:" + hashlib.sha256(b"").hexdigest(),
            responseBodySha256="sha256:" + hashlib.sha256(output).hexdigest(), responseBodyBytes=len(output), status=200,
            providerCredentialMatched=True, proxyAuthorizationPresent=False, allParsedHeadersValidated=True)
        extra = [("X-GitHub-Request-Id", f"fixture:app:{cycle + 1}:{client}:{page}")]
        if page == 1:
            extra.append(("Link", '<' + examples.ORIGIN + examples.target(client, 2) + '>; rel="next"'))
        return 200, output, extra


class Handler(base.Handler):
    def do_GET(self):
        if self.path == "/_fixture/observations":
            self.send(200, base.encoded(self.server.oracle.observation()))
        else:
            self.resource()

    def resource(self):
        before = self.server.oracle.total
        try:
            lengths = self.headers.get_all("Content-Length", [])
            require(not self.headers.get_all("Transfer-Encoding") and len(lengths) <= 1
                and (not lengths or re.fullmatch(r"[1-9][0-9]{0,3}", lengths[0])))
            length = int(lengths[0]) if lengths else 0
            require(length <= 4096)
            body = self.rfile.read(length)
            require(len(body) == length)
            status, body, extra = self.server.oracle.handle(self.command, self.path,
                list(self.headers.raw_items()), body, time.time())
            self.send(status, body, extra)
        except Exception:
            # No request/header/body/JWT/PEM values in logs or observations.
            if self.server.oracle.total == before:
                try:
                    self.server.oracle.arrival(self.path)
                except ValueError:
                    pass  # Counter remains above the cap; no unbounded rows.
            self.send(400, b'{"message":"synthetic App fixture refused"}')
    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def setup():
    root = Path("/upstream-data/github")
    base.setup(root, Path("/private-fixture.json"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    material = {"app-key.pem": key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        "app-public.pem": key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)}
    for name, data in material.items():
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    args = parser.parse_args()
    signal.alarm(20 if args.setup else 305)
    if args.setup:
        setup(); return
    assert_isolated_network()
    key = serialization.load_pem_public_key(Path("/github/app-public.pem").read_bytes())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/github/cert.pem", "/github/key.pem")
    with base.HTTPServer((FIXTURE_IP, 443), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.oracle, server.timeout = Oracle(key), 0.5
        until = time.monotonic() + 300
        while time.monotonic() < until:
            server.handle_request()


if __name__ == "__main__":
    main()
