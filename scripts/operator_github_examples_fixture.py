"""Closed synthetic receiver for the checked-in Node/Python/Go issue examples.

Uses the existing network-none namespace and offline GitHub PKI. It is a
separate acceptance profile, not a relaxation of the accepted Octokit fixture.
No caller-supplied header, URL, body, or credential is returned in observations.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import hmac
from http.server import HTTPServer
from pathlib import Path
import re
import signal
import ssl
import time

from scripts import operator_github_fixture as base
from scripts.operator_github_fixture_network import FIXTURE_IP, assert_isolated_network

SCHEMA = "catchplate.privateGithubExampleObservations/v1"
CLIENTS = ("node", "python", "go")
MAX_ATTEMPTS = 12
OWNER, REPO, ORIGIN, BASE, TOKEN = base.OWNER, base.REPO, base.ORIGIN, base.BASE, base.TOKEN
QUERIES = {
    "node": ("per_page=100", "per_page=100&page=2"),
    "python": ("direction=desc&sort=updated&state=open", "page=2&per_page=30&state=open"),
    "go": ("page=1&per_page=100&state=open", "page=2&per_page=100&state=open"),
}
MEDIA = {"node": "application/vnd.github.v3+json", "python": "*/*",
         "go": "application/vnd.github.squirrel-girl-preview"}
AGENTS = {"python": "PyGithub/Python", "go": "go-github/v74.0.0"}
NODE_AGENT = (r"octokit-rest\.js/22\.0\.1 octokit-core\.js/7\.0\.8 "
              r"(?:Node\.js/25|Node\.js/25\.5\.0 \(linux; x64\))")


def require(condition):
    if not condition:
        raise ValueError("private GitHub examples fixture refused")


def body(page):
    require(type(page) is int and page in (1, 2))
    number = 10 + page
    return base.encoded([{**base.issue(number), "state": "open",
        "url": ORIGIN + BASE + "/" + str(number)}])


def target(client, page):
    require(type(client) is str and client in CLIENTS and type(page) is int and page in (1, 2))
    return BASE + "?" + QUERIES[client][page - 1]


def classify(method, raw_target):
    for client in CLIENTS:
        for page in (1, 2):
            if method == "GET" and raw_target == target(client, page):
                return client, page
    raise ValueError("private GitHub examples target refused")


def validated_headers(client, fields):
    """Validate all parsed fields before returning ONLY public semantic fields."""
    require(client in CLIENTS and len(fields) <= 12)
    fields = [(name.lower(), value) for name, value in fields]
    require(len({name for name, _ in fields}) == len(fields))
    headers = dict(fields)
    common = {"host", "authorization", "accept", "user-agent"}
    semantic = {"accept", "user-agent"}
    required = common | ({"accept-language", "sec-fetch-mode"} if client == "node"
                         else {"x-github-api-version"})
    allowed = required | {"connection"}
    if client == "node":
        allowed.add("x-github-api-version")
    require(required <= headers.keys() <= allowed
        and headers["host"] == "api.github.com"
        and hmac.compare_digest(headers["authorization"], "Bearer " + TOKEN)
        and headers["accept"] == MEDIA[client]
        and headers.get("connection", "close") in {"close", "keep-alive"})
    if client == "node":
        require(re.fullmatch(NODE_AGENT, headers["user-agent"]) is not None
            and headers["accept-language"] == "*" and headers["sec-fetch-mode"] == "cors")
        semantic.update(("accept-language", "sec-fetch-mode"))
    else:
        require(headers["user-agent"] == AGENTS[client])
    if "x-github-api-version" in headers:
        require(headers["x-github-api-version"] == "2022-11-28")
        semantic.add("x-github-api-version")
    return {name: headers[name] for name in sorted(semantic)}


class Fixture(HTTPServer):
    def __init__(self, address, context):
        super().__init__(address, Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.attempts, self.total, self.timeout = [], 0, 0.5


class Handler(base.Handler):
    def do_GET(self):
        if self.path == "/_fixture/observations":
            self.send(200, base.encoded({"schema": SCHEMA, "syntheticOnly": True,
                "total": self.server.total, "attempts": deepcopy(self.server.attempts)}))
            return
        self.resource()

    def resource(self):
        self.server.total += 1
        row = {"ordinal": self.server.total, "accepted": False}
        if self.server.total <= MAX_ATTEMPTS:
            self.server.attempts.append(row)
        try:
            require(self.server.total <= MAX_ATTEMPTS)
            client, page = classify(self.command, self.path)
            headers = validated_headers(client, list(self.headers.raw_items()))
            # No request body or framing header is admitted by this read-only profile.
            response = body(page)
            row.update(client=client, page=page, accepted=True, method="GET",
                target=target(client, page), semanticHeaders=headers,
                requestBodySha256="sha256:" + hashlib.sha256(b"").hexdigest(),
                responseBodySha256="sha256:" + hashlib.sha256(response).hexdigest(),
                responseBodyBytes=len(response), status=200,
                providerCredentialMatched=True, proxyAuthorizationPresent=False,
                allParsedHeadersValidated=True)
            extra = [("X-GitHub-Request-Id", "fixture:" + client + ":" + str(page))]
            if page == 1:
                extra.append(("Link", '<' + ORIGIN + target(client, 2) + '>; rel="next"'))
            self.send(200, response, extra)
        except (ValueError, OSError):
            self.send(400, b'{"message":"synthetic example fixture refused"}')

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.setup:
        signal.alarm(20)
        base.setup(Path("/upstream-data/github"), Path("/private-fixture.json"))
        return
    assert_isolated_network()
    require(60 <= args.lifetime_seconds <= 300)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/github/cert.pem", "/github/key.pem")
    signal.alarm(args.lifetime_seconds + 5)
    with Fixture((FIXTURE_IP, 443), context) as server:
        deadline = time.monotonic() + args.lifetime_seconds
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
