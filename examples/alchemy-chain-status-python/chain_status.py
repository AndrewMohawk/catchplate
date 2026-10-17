"""Two read-only Alchemy calls through an explicit, verified Catchplate proxy."""
import argparse
from contextlib import contextmanager
from importlib.metadata import version
import json
import logging
import math
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlsplit
from uuid import UUID

import requests
from requests.adapters import HTTPAdapter

PLACEHOLDER = "catchplate-alchemy-placeholder-v1"  # Public, not a provider key.
CHAINS = {"eth-mainnet": 1, "eth-sepolia": 11155111}
PINS = {"web3": "7.15.0", "requests": "2.34.2", "urllib3": "2.8.0",
    "certifi": "2026.7.22", "pydantic": "2.13.4"}
REQUIRED_ENV = ("CATCHPLATE_PROXY_URL", "CATCHPLATE_APP_ID", "CATCHPLATE_PROXY_TOKEN",
    "CATCHPLATE_CA_FILE", "CATCHPLATE_ALCHEMY_CHAIN")
MAX_RESPONSE_BYTES = 65536
FAILURE = "Alchemy chain status failed; check configuration, proxy health and the operator audit log."
MAX_CONFIG_BYTES = 64 * 1024


def configuration_environment(config_file):
    """Read the private console download as connection data, not an RPC recipe."""
    path = Path(config_file).absolute()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_CONFIG_BYTES:
            raise ValueError("Invalid configuration file")
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if not 0 < len(raw) <= MAX_CONFIG_BYTES:
        raise ValueError("Invalid configuration file")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate configuration field")
            result[key] = value
        return result

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Invalid configuration number")
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_float=number, parse_constant=number)
    if type(value) is not dict:
        raise ValueError("Invalid configuration object")
    for field in ("application_id", "access_rule_id"):
        if type(value.get(field)) is not str or str(UUID(value[field])) != value[field]:
            raise ValueError("Invalid configuration identity")
    expiry, chain = value.get("token_expires_at_epoch_ms"), value.get("chain")
    if (value.get("proxy_authentication") != "basic_and_bearer_v1"
            or value.get("proxy_username") != value["application_id"]
            or type(expiry) is not int or not time.time_ns() // 1_000_000 < expiry <= 2**53 - 1
            or value.get("operation_bundle") != "alchemy_chain_status_read_v1"
            or type(chain) is not str or chain not in CHAINS
            or value.get("upstream_url") != "https://" + chain + ".g.alchemy.com/v2"
            or value.get("methods") != ["POST"]
            or value.get("rpc_methods") != ["eth_chainId", "eth_blockNumber"]
            or value.get("credential_input") != "replace_exact"
            or value.get("response_mode") != "alchemy_rpc_read_json_v1"):
        raise ValueError("Invalid Alchemy configuration scope")
    selected = {"CATCHPLATE_ALCHEMY_CHAIN": chain}
    for field, key in (("application_id", "CATCHPLATE_APP_ID"), ("proxy_url", "CATCHPLATE_PROXY_URL"),
            ("proxy_password", "CATCHPLATE_PROXY_TOKEN")):
        if type(value.get(field)) is not str:
            raise ValueError("Invalid connection value")
        selected[key] = value[field]
    for field, key in (("ca_file", "CATCHPLATE_CA_FILE"), ("proxy_ca_file", "CATCHPLATE_PROXY_CA_FILE")):
        item = value.get(field)
        if field == "proxy_ca_file" and item is None:
            continue
        if type(item) is not str or not item or len(item) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in item):
            raise ValueError("Invalid CA path")
        selected[key] = str((path.parent / item).resolve())
    # request_body, request_headers, client_recipe and ambient settings are inert.
    return child_environment(selected)


def settings(env):
    chain = env.get("CATCHPLATE_ALCHEMY_CHAIN", "")
    if chain not in CHAINS:
        raise ValueError("An explicit supported chain is required")
    proxy = env.get("CATCHPLATE_PROXY_URL", "")
    parts = urlsplit(proxy)
    if (not 1 <= len(proxy) <= 2048 or not proxy.isascii()
            or any(ord(c) < 33 or ord(c) > 126 or c == "\\" for c in proxy)
            or parts.scheme != "https" or not parts.hostname
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", parts.hostname)
            or parts.username is not None or parts.password is not None
            or parts.path not in {"", "/"} or "?" in proxy or "#" in proxy
            or parts.port is not None and not 1 <= parts.port <= 65535
            or parts.netloc != parts.hostname + (":" + str(parts.port) if parts.port is not None else "")):
        raise ValueError("An explicit credential-free HTTPS proxy origin is required")
    application, token = env.get("CATCHPLATE_APP_ID", ""), env.get("CATCHPLATE_PROXY_TOKEN", "")
    if (str(UUID(application)) != application or not 1 <= len(token) <= 8192
            or not all(33 <= ord(c) <= 126 for c in token)):
        raise ValueError("An explicit Catchplate Basic proxy login is required")
    for key in ("CATCHPLATE_CA_FILE", "CATCHPLATE_PROXY_CA_FILE"):
        if key == "CATCHPLATE_CA_FILE" or key in env:
            value = env.get(key, "")
            if not value or not Path(value).is_absolute():
                raise ValueError("CA inputs must be explicit absolute files")
    # Requests owns Basic CONNECT auth. Never print this in-memory proxy URL.
    authenticated_proxy = "https://" + quote(application, safe="") + ":" + quote(token, safe="") + "@" + parts.netloc
    return chain, "https://" + chain + ".g.alchemy.com/v2", authenticated_proxy


def child_environment(env):
    settings(env)
    selected = {name: env[name] for name in REQUIRED_ENV}
    if "CATCHPLATE_PROXY_CA_FILE" in env:
        selected["CATCHPLATE_PROXY_CA_FILE"] = env["CATCHPLATE_PROXY_CA_FILE"]
    return selected


def check_versions():
    if any(version(package) != expected for package, expected in PINS.items()):
        raise ValueError("Install the pinned requirements")


def public_ca(path):
    selected = Path(path)
    if not selected.is_absolute() or not selected.is_file():
        raise ValueError("An absolute public CA file is required")
    with selected.open("rb") as stream:
        raw = stream.read(65537)
    if not raw or len(raw) > 65536 or b"PRIVATE KEY" in raw:
        raise ValueError("Invalid public CA material")
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe.load_verify_locations(cadata=raw.decode("ascii"))
    return raw


def proxy_context(extra=None):
    import certifi
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=certifi.where())
    if extra is not None:
        context.load_verify_locations(cadata=public_ca(extra).decode("ascii"))
    return context


@contextmanager
def request_ca_bundle(path):
    import certifi
    extra = public_ca(path)
    with tempfile.TemporaryDirectory(prefix="catchplate-alchemy-ca-") as directory:
        combined = Path(directory) / "ca.pem"
        with combined.open("xb") as stream:
            os.chmod(combined, 0o600)
            stream.write(Path(certifi.where()).read_bytes() + b"\n" + extra + b"\n")
        yield str(combined)


class BoundedAdapter(HTTPAdapter):
    """Requests extension: separate proxy TLS, no retries, bounded response.

    No SDK method, serialized body or prepared request header is rewritten.
    The pinned Requests response is buffered once, before web3.py decodes it.
    """
    def __init__(self, outer_context, endpoint, proxy, bundle):
        if outer_context.verify_mode != ssl.CERT_REQUIRED or not outer_context.check_hostname:
            raise ValueError("Verified proxy TLS is required")
        self.outer_context = outer_context
        self.endpoint, self.proxy, self.bundle = endpoint, proxy, bundle
        self.attempts = 0
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def proxy_manager_for(self, proxy, **kwargs):
        return super().proxy_manager_for(proxy, proxy_ssl_context=self.outer_context, **kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        if (self.attempts >= 2 or request.method != "POST" or request.url != self.endpoint
                or type(request.body) is not bytes or not 1 <= len(request.body) <= 65536
                or request.headers.get("Authorization") != "Bearer " + PLACEHOLDER
                or "Proxy-Authorization" in request.headers or verify != self.bundle
                or cert is not None or proxies != {"https": self.proxy}):
            raise ValueError("Unexpected SDK transport request")
        self.attempts += 1
        response = super().send(request, stream=True, timeout=(5, 10), verify=verify,
            cert=None, proxies=proxies)
        try:
            if (300 <= response.status_code < 400
                    or response.headers.get("Content-Encoding", "identity").lower() != "identity"
                    or not re.fullmatch(r"application/json(?:;\s*charset=utf-8)?",
                        response.headers.get("Content-Type", ""), re.IGNORECASE)):
                raise ValueError("Unexpected provider response")
            length = response.headers.get("Content-Length")
            if length is not None and (not re.fullmatch(r"0|[1-9][0-9]{0,9}", length)
                    or int(length) > MAX_RESPONSE_BYTES):
                raise ValueError("Provider response exceeds limit")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Provider response exceeds limit")
            if length is not None and int(length) != len(body):
                raise ValueError("Provider response framing mismatch")
            response._content = bytes(body)
            response._content_consumed = True
            return response
        finally:
            response.close()


@contextmanager
def configured_client(env):
    from web3 import HTTPProvider, Web3
    _, endpoint, proxy = settings(env)
    outer = proxy_context(env.get("CATCHPLATE_PROXY_CA_FILE"))
    with request_ca_bundle(env["CATCHPLATE_CA_FILE"]) as bundle, requests.Session() as session:
        session.trust_env = False  # No netrc, ambient proxy, bypass or CA discovery.
        session.max_redirects = 0
        session.proxies = {"https": proxy}
        session.verify = bundle
        session.headers["Authorization"] = "Bearer " + PLACEHOLDER
        previous = session.adapters["https://"]
        session.mount("https://", BoundedAdapter(outer, endpoint, proxy, bundle))
        previous.close()
        provider = HTTPProvider(endpoint_uri=endpoint, session=session,
            request_kwargs={"timeout": (5, 10), "allow_redirects": False},
            exception_retry_configuration=None, cache_allowed_requests=False)
        # Ordinary SDK properties below: no provider/method replacement, no
        # is_connected() probe (which would request web3_clientVersion).
        yield Web3(provider)


def summary(value, chain):
    if (type(value) is not dict or set(value) != {"chain", "chain_id", "block_number"}
            or value["chain"] != chain or chain not in CHAINS
            or type(value["chain_id"]) is not int or value["chain_id"] != CHAINS[chain]
            or type(value["block_number"]) is not int or not 0 <= value["block_number"] < 2**64):
        raise ValueError("Unexpected chain status")
    return value


def read_chain_status(env):
    chain, _, _ = settings(env)
    with configured_client(env) as client:
        chain_id = client.eth.chain_id
        if type(chain_id) is not int or chain_id != CHAINS[chain]:
            raise ValueError("Unexpected chain identity")
        block_number = client.eth.block_number
    return summary({"chain": chain, "chain_id": chain_id, "block_number": block_number}, chain)


def launch(env):
    check_versions()
    child = child_environment(env)
    result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
        env=child, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Child failed")
    return summary(json.loads(result.stdout), child["CATCHPLATE_ALCHEMY_CHAIN"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read permitted Alchemy chain status using web3.py.")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", metavar="PATH", help="Private client JSON downloaded from Catchplate")
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    try:
        if args.child and args.config is not None:
            raise ValueError("Downloaded configuration is parent-only")
        if args.child:
            check_versions()
            value = read_chain_status(child_environment(os.environ))
        else:
            value = launch(os.environ if args.config is None else configuration_environment(args.config))
        print(json.dumps(value, ensure_ascii=True))
        return 0
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
