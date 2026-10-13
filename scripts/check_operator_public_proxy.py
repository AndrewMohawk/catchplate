#!/usr/bin/env python3
"""One fixed public-proxy curl request; no provisioning, retry or audit authority.

The parent supplies a fresh scoped application via the private environment.
Only public commitments leave this process. A revoked CONNECT refusal does not
by itself prove zero provider arrivals: the parent must join actual audit data.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

ENVIRONMENT = "SERVERWARE_PUBLIC_PROXY_CHECK_JSON"
SCHEMA = "serverware.publicProxySmokeResult/v1"
PROXY = "https://serverware-proxy.example.com:443"
UPSTREAM = "https://demo-upstream:8443/echo"
PEER = "203.0.113.10"
BODY = b'{"public_proxy_smoke":true}'
DUMMY = "Bearer SERVERWARE_PUBLIC_PROXY_DUMMY"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
TRAILER = b"\nserverware-public-proxy:"
FIELDS = {"schema", "run_id", "application_id", "client_token", "credential_id", "rule_id",
          "policy_hash", "authorization_sha256", "ca_pem", "ca_sha256"}


class CheckError(ValueError):
    def __init__(self):
        super().__init__("Public proxy check refused")


def require(value):
    if not value:
        raise CheckError()


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def refused(_):
        raise CheckError()
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=refused, parse_float=refused)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CheckError() from None


def parse_config(raw):
    require(type(raw) is str and 1 <= len(raw) <= 32768)
    value = document(raw)
    require(type(value) is dict and set(value) == FIELDS and all(type(item) is str for item in value.values()))
    require(value["schema"] == "serverware.publicProxySmoke/v1"
        and re.fullmatch(r"public-proxy-[0-9a-f]{32}", value["run_id"])
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", value["client_token"]))
    require(all(UUID.fullmatch(value[key]) for key in ("application_id", "credential_id", "rule_id"))
        and len({value[key] for key in ("application_id", "credential_id", "rule_id")}) == 3
        and all(DIGEST.fullmatch(value[key]) for key in ("policy_hash", "authorization_sha256", "ca_sha256"))
        and value["authorization_sha256"] != sha(DUMMY.encode()))
    try:
        pem = value["ca_pem"].encode("ascii")
        require(1 <= len(pem) <= 16384 and sha(pem) == value["ca_sha256"]
            and re.fullmatch(rb"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?", pem))
        # Real certificate parsing, not a PEM-shaped string or a private key.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=value["ca_pem"])
    except (ValueError, UnicodeError, ssl.SSLError):
        raise CheckError() from None
    return value


def curl_arguments(config, ca_path, body_path):
    return ["/usr/bin/curl", "-q", "--config", "-", "--silent", "--show-error", "--proxy-basic",
        "--proxy", PROXY, "--noproxy", "", "--cacert", str(ca_path), "--proto", "=https",
        "--proto-redir", "=https", "--http1.1", "--connect-timeout", "10", "--max-time", "20",
        "--retry", "0", "--max-redirs", "0", "--max-filesize", "65536", "--raw", "--include",
        "--suppress-connect-headers", "--request", "POST", "--data-binary", "@" + str(body_path),
        "--header", "Authorization: " + DUMMY, "--header", "Content-Type: application/json",
        "--header", "Accept: application/json", "--header", "Accept-Encoding: identity",
        "--header", "User-Agent: serverware-test-run/" + config["run_id"],
        "--write-out", TRAILER.decode() + "%{http_connect}:%{http_code}:%{proxy_ssl_verify_result}:%{ssl_verify_result}:%{remote_ip}\n",
        UPSTREAM + "?" + urlencode({"expectedAuthorizationSha256": config["authorization_sha256"]})]


def run_curl(arguments, private_input):
    """Bounded pipes; kill the owned group before reaping its leader on every exit."""
    deadline = time.monotonic() + 23
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, close_fds=True, start_new_session=True)
    result = {"out": bytearray(), "err": bytearray()}
    try:
        process.stdin.write(private_input)
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, key)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                for item, _ in selector.select(remaining):
                    try:
                        chunk = os.read(item.fd, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(item.fileobj)
                        continue
                    result[item.data].extend(chunk)
                    require(len(result[item.data]) <= (98304 if item.data == "out" else 8192))
        require(time.monotonic() < deadline)
        # Observe exit without reaping: the PID/group cannot be reused before cleanup.
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            require(time.monotonic() < deadline)
            time.sleep(0.01)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    return process.returncode, bytes(result["out"]), bytes(result["err"])


def validate_result(config, mode, exit_code, output, error):
    require(mode in {"positive", "revoked"} and type(exit_code) is int
        and type(output) is bytes and len(output) <= 98304 and type(error) is bytes and len(error) <= 8192)
    private = (config["application_id"] + ":" + config["client_token"]).encode()
    require(all(secret not in output and secret not in error
        for secret in (config["client_token"].encode(), private, base64.b64encode(private), DUMMY.encode())))
    content, separator, trailer = output.rpartition(TRAILER)
    match = re.fullmatch(rb"([0-9]{3}):([0-9]{3}):([0-9]+):([0-9]+):(207\.38\.135\.7)\n", trailer)
    require(separator and match)
    connect, status, proxy_tls, inner_tls = (int(part) for part in match.groups()[:4])
    require(proxy_tls == 0 and inner_tls == 0)
    result = {"schema": SCHEMA, "ok": True, "mode": mode,
        **{key: config[key] for key in ("run_id", "application_id", "credential_id", "rule_id", "policy_hash", "ca_sha256")},
        "peer": PEER, "connect_status": connect, "http_status": status, "proxy_tls_verify_result": proxy_tls,
        "response_body_sha256": None, "response_body_bytes": None, "request_digest": None, "operation_digest": None}
    if mode == "revoked":
        require(exit_code == 56 and connect == 403 and status == 0 and not content)
        return result  # No provider-arrival or mutation-outcome assertion.
    require(exit_code == 0 and connect == 200 and status == 200 and not error)
    head, separator, body = content.partition(b"\r\n\r\n")
    require(separator and len(head) <= 16384 and 1 <= len(body) <= 65536)
    lines = head.split(b"\r\n")
    require(re.fullmatch(rb"HTTP/1\.1 200 [\x20-\x7e]{0,128}", lines[0]))
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        require(colon and re.fullmatch(rb"[A-Za-z0-9-]{1,128}", name)
            and re.fullmatch(rb"[\x20-\x7e]{0,4096}", value))
        name, value = name.decode().lower(), value.decode().strip()
        require(name not in headers)
        headers[name] = value
    require(not set(headers) & {"authorization", "proxy-authorization", "set-cookie", "cookie",
        "x-serverware-data-plane-token", "x-serverware-agent", "transfer-encoding", "trailer", "location"}
        and headers.get("content-length") == str(len(body))
        and headers.get("content-type", "").lower() in {"application/json", "application/json; charset=utf-8"}
        and headers.get("content-encoding", "identity").lower() == "identity")
    require(headers.get("x-serverware-policy-hash") == config["policy_hash"]
        and headers.get("x-serverware-response-body-sha256") == sha(body)
        and all(DIGEST.fullmatch(headers.get(key, "")) for key in ("x-serverware-request-digest", "x-serverware-operation-digest")))
    value = document(body)
    require(type(value) is dict and set(value) == {"method", "path", "authorization_present", "authorization_scheme",
        "authorization_matches_expected", "proxy_authorization_seen", "query", "credential_marker",
        "proxy_authorization", "cookie", "x_api_key", "serverware_agent"}
        and value.get("method") == "POST" and value.get("path") == "/echo"
        and value.get("authorization_present") is True and value.get("authorization_scheme") == "Bearer"
        and value.get("authorization_matches_expected") is True and value.get("proxy_authorization_seen") is False
        and type(value.get("query")) is dict and set(value["query"]) == {"_data_plane_token_seen", "_cookie_seen"}
        and all(item is False for item in value["query"].values()) and value.get("credential_marker") == "other"
        and all(key in value and value[key] is None for key in ("proxy_authorization", "cookie", "x_api_key", "serverware_agent")))
    result.update(response_body_sha256=sha(body), response_body_bytes=len(body),
        request_digest=headers["x-serverware-request-digest"], operation_digest=headers["x-serverware-operation-digest"])
    return result


def execute(config, mode):
    # Only these owned temporary public-CA/fixed-body files are created and removed.
    with tempfile.TemporaryDirectory(prefix="serverware-public-proxy-") as directory:
        paths = [Path(directory) / "ca.pem", Path(directory) / "body.json"]
        for path, content in zip(paths, (config["ca_pem"].encode("ascii"), BODY)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
        private_input = ('proxy-user = "' + config["application_id"] + ':' + config["client_token"] + '"\n').encode()
        code, output, error = run_curl(curl_arguments(config, *paths), private_input)
        return validate_result(config, mode, code, output, error)


def main():
    raw = os.environ.pop(ENVIRONMENT, None)  # Never inherited by curl, including failures.
    mode = sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in {"positive", "revoked"} else None
    try:
        require(mode is not None)
        result = execute(parse_config(raw), mode)
    except Exception:
        result = {"schema": SCHEMA, "ok": False, "mode": mode, "error": "public_proxy_check_failed",
                  "outcome": "unconfirmed", "retry_allowed": False}
    print(json.dumps(result, separators=(",", ":"), allow_nan=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
