"""Official Gmail SDK; explicit HTTPS CONNECT transport, no Google credentials."""
import argparse
import base64
from contextlib import contextmanager
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit
from uuid import UUID

import certifi
import httplib2
import requests
from googleapiclient.discovery import build
from requests.adapters import HTTPAdapter

PLACEHOLDER = "serverware-gmail-placeholder-v1"  # Public replacement marker, not a token.
ORIGIN = "https://gmail.googleapis.com"
LIST_PATH = "/gmail/v1/users/me/messages"
HEADERS = ["From", "Subject", "Date"]
PINS = {"google-api-python-client": "2.201.0", "httplib2": "0.32.0",
    "requests": "2.34.2", "urllib3": "2.8.0", "certifi": "2026.7.22"}
REQUIRED_ENV = ("SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN", "SERVERWARE_CA_FILE")
FAILURE = "Gmail read failed; check application permission, proxy trust and the operator audit log."


def settings(env):
    proxy = env.get("SERVERWARE_PROXY_URL", "")
    parts = urlsplit(proxy)
    host = parts.hostname or ""
    if (not 1 <= len(proxy) <= 2048 or not proxy.isascii()
            or any(ord(c) < 33 or ord(c) > 126 or c == "\\" for c in proxy)
            or parts.scheme != "https" or "." not in host or host == "gmail.googleapis.com"
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split("."))
            or re.fullmatch(r"[0-9.]+", host) or len(host) > 253
            or parts.username is not None or parts.password is not None
            or parts.path not in {"", "/"} or "?" in proxy or "#" in proxy
            or parts.port is not None and not 1 <= parts.port <= 65535
            or parts.netloc != host + (":" + str(parts.port) if parts.port is not None else "")):
        raise ValueError("Explicit HTTPS proxy origin required")
    app, token = env.get("SERVERWARE_APP_ID", ""), env.get("SERVERWARE_PROXY_TOKEN", "")
    identity = UUID(app)
    if (str(identity) != app or identity.version not in {1, 2, 3, 4, 5}
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
            or base64.urlsafe_b64encode(base64.urlsafe_b64decode(token + "=")).decode().rstrip("=") != token):
        raise ValueError("Explicit application Basic login required")
    for key in ("SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE"):
        if key == "SERVERWARE_CA_FILE" or key in env:
            if not env.get(key) or not Path(env[key]).is_absolute():
                raise ValueError("Absolute public CA path required")
    # This URL stays in process memory; Requests owns Basic CONNECT authentication.
    return "https://" + quote(app, safe="") + ":" + quote(token, safe="") + "@" + parts.netloc


def child_environment(env):
    settings(env)
    selected = {key: env[key] for key in REQUIRED_ENV}
    if "SERVERWARE_PROXY_CA_FILE" in env:
        selected["SERVERWARE_PROXY_CA_FILE"] = env["SERVERWARE_PROXY_CA_FILE"]
    # No ADC, netrc, environment proxy/CA override, mTLS discovery or TLS key log.
    return selected


def private_child_environment(env):
    selected = child_environment(env)
    extra = set(env) - set(selected)
    # CPython may add this during POSIX locale coercion of the clean environment.
    if extra - {"LC_CTYPE"} or "LC_CTYPE" in extra and env["LC_CTYPE"] != "C.UTF-8":
        raise ValueError("Private child environment required")
    return selected


def check_versions():
    if any(version(package) != expected for package, expected in PINS.items()):
        raise ValueError("Install pinned requirements")


def public_ca(path):
    selected = Path(path)
    if not selected.is_absolute() or not selected.is_file():
        raise ValueError("Absolute public CA file required")
    with selected.open("rb") as source:
        raw = source.read(65537)
    if not raw or len(raw) > 65536 or b"PRIVATE KEY" in raw:
        raise ValueError("Public CA refused")
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe.load_verify_locations(cadata=raw.decode("ascii"))
    return raw


def outer_context(path=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=certifi.where())
    if path is not None:
        context.load_verify_locations(cadata=public_ca(path).decode("ascii"))
    return context


class ProxyAdapter(HTTPAdapter):
    """Standard Requests extension for independently verified outer proxy TLS."""
    def __init__(self, context):
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("Verified proxy TLS required")
        self.outer_context = context
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def proxy_manager_for(self, proxy, **kwargs):
        return super().proxy_manager_for(proxy, proxy_ssl_context=self.outer_context, **kwargs)

    def send(self, request, **kwargs):
        response = super().send(request, **kwargs)
        if response.status_code != 200:
            # Requests prepares a possible redirect even with allow_redirects=False,
            # consuming its body first. Stop here, before that unbounded read.
            response.close()
            raise ValueError("Gmail response refused")
        return response


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Ambiguous response")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("Invalid JSON constant")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    if type(value) is not dict or "error" in value:
        raise ValueError("Unexpected Gmail response")
    return value


class GmailHttp:
    """Documented googleapiclient http= seam; SDK still builds and decodes calls.

    httplib2's default proxy transport cannot do this HTTPS-proxy TLS hop. This
    adapter does not rewrite SDK URLs, query ordering or API methods.
    """
    def __init__(self, session, proxy, ca_file):
        self.session, self.proxy, self.ca_file = session, proxy, ca_file
        self.attempts, self.deadline = 0, time.monotonic() + 110

    def request(self, uri, method="GET", body=None, headers=None, **kwargs):
        parts, values = urlsplit(uri), dict(headers or {})
        lowered = {key.lower(): value for key, value in values.items()}
        path_ok = parts.path == LIST_PATH or re.fullmatch(re.escape(LIST_PATH) + r"/[A-Za-z0-9_-]{1,512}", parts.path)
        if (kwargs or method != "GET" or body is not None or not uri.isascii() or len(uri) > 2048
                or parts.scheme != "https" or parts.netloc != "gmail.googleapis.com" or parts.fragment or not path_ok
                or len(lowered) != len(values)
                or set(lowered) - {"accept", "accept-encoding", "authorization", "user-agent", "x-goog-api-client", "content-length"}
                or lowered.get("authorization") != "Bearer " + PLACEHOLDER
                or lowered.get("accept-encoding") != "identity" or lowered.get("content-length", "0") != "0"
                or self.attempts >= 12 or time.monotonic() >= self.deadline):
            raise ValueError("SDK request refused")
        self.attempts += 1
        response = self.session.request(method, uri, headers=values, data=None,
            proxies={"https": self.proxy}, verify=self.ca_file, cert=None,
            allow_redirects=False, stream=True, timeout=(5, 10))
        try:
            # Errors/redirects are terminal; never pass reflected bodies to diagnostics.
            if (response.status_code != 200 or response.headers.get("Content-Encoding", "identity").lower() != "identity"
                    or not re.fullmatch(r"application/json(?:;\s*charset=utf-8)?", response.headers.get("Content-Type", ""), re.I)):
                raise ValueError("Gmail response refused")
            length = response.headers.get("Content-Length")
            if length is not None and (not re.fullmatch(r"0|[1-9][0-9]{0,9}", length) or int(length) > 1048576):
                raise ValueError("Response exceeds limit")
            raw = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                raw.extend(chunk)
                if len(raw) > 1048576 or time.monotonic() >= self.deadline:
                    raise ValueError("Response exceeds limit")
            if length is not None and int(length) != len(raw):
                raise ValueError("Response framing refused")
            strict_json(bytes(raw))  # Reject ambiguity before SDK's ordinary JSON decoder.
            return httplib2.Response({"status": "200", "content-type": "application/json"}), bytes(raw)
        finally:
            response.close()

    def close(self):
        self.session.close()


@contextmanager
def configured_http(env):
    proxy = settings(env)
    public_ca(env["SERVERWARE_CA_FILE"])
    with requests.Session() as session:
        session.trust_env = False
        session.max_redirects = 0
        session.headers.clear()
        session.headers["Connection"] = "close"
        for adapter in session.adapters.values():
            adapter.close()
        session.adapters.clear()
        session.mount(ORIGIN + "/", ProxyAdapter(outer_context(env.get("SERVERWARE_PROXY_CA_FILE"))))
        yield GmailHttp(session, proxy, env["SERVERWARE_CA_FILE"])


def page_token(value):
    if (not isinstance(value, str) or len(value.encode("utf-8")) > 4096
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c == "\\" for c in value)):
        raise ValueError("Page token refused")
    return value


def execute(request):
    # SDK converts long GETs to POST; this read-only example refuses instead.
    if request.method != "GET" or request.body is not None or len(request.uri) > 2048:
        raise ValueError("Read-only SDK request required")
    request.headers["authorization"] = "Bearer " + PLACEHOLDER
    request.headers["accept-encoding"] = "identity"
    return request.execute(num_retries=0)


def read_mail(http):
    # Bundled discovery: no discovery fetch, ADC, credentials file or refresh code.
    service = build("gmail", "v1", http=http, static_discovery=True,
        cache_discovery=False, num_retries=0, client_options={"api_endpoint": ORIGIN + "/"})
    messages = service.users().messages()
    seen, tokens, next_page, pages, count = set(), set(), "", 0, 0
    for _ in range(2):
        args = {"userId": "me", "maxResults": 5, "labelIds": ["INBOX"]}
        if next_page:
            args["pageToken"] = next_page
        value = execute(messages.list(**args))
        rows = value.get("messages", [])
        if type(rows) is not list or len(rows) > 5:
            raise ValueError("Message list refused")
        ids = []
        for row in rows:
            ident = row.get("id") if type(row) is dict else None
            if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", ident) or ident in seen:
                raise ValueError("Message identity refused")
            seen.add(ident)
            ids.append(ident)
        next_page = page_token(value.get("nextPageToken", ""))
        if next_page:
            if next_page in tokens:
                raise ValueError("Pagination cycle refused")
            tokens.add(next_page)
        for ident in ids:
            item = execute(messages.get(userId="me", id=ident, format="metadata", metadataHeaders=HEADERS))
            if item.get("id") != ident:
                raise ValueError("Returned message identity refused")
            count += 1
        pages += 1
        if not next_page:
            break
    return {"pages": pages, "messages_read": count, "more_pages": bool(next_page)}


def summary(value):
    if (type(value) is not dict or set(value) != {"pages", "messages_read", "more_pages"}
            or type(value["pages"]) is not int or not 1 <= value["pages"] <= 2
            or type(value["messages_read"]) is not int or not 0 <= value["messages_read"] <= value["pages"] * 5
            or type(value["more_pages"]) is not bool or value["more_pages"] and value["pages"] != 2):
        raise ValueError("Invalid job summary")
    return value


def launch(env):
    check_versions()
    result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
        env=child_environment(env), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=120, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Gmail child failed")
    return summary(json.loads(result.stdout))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read a bounded INBOX sample with the official Gmail SDK.")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    try:
        if args.child:
            check_versions()
            with configured_http(private_child_environment(os.environ)) as http:
                value = read_mail(http)
        else:
            value = launch(os.environ)
        print(json.dumps(summary(value), separators=(",", ":")))
        return 0
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
