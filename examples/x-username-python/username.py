"""One read-only username lookup using the official XDK and Requests transport."""
import argparse
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
import tempfile
from urllib.parse import quote, urlsplit
from uuid import UUID

from requests.adapters import HTTPAdapter

PLACEHOLDER = "serverware-x-placeholder-v1"  # Public; never an X credential.
BASE_URL = "https://api.x.com"
PINS = {"xdk": "0.10.6", "requests": "2.34.2", "urllib3": "2.8.0",
    "certifi": "2026.7.22", "pydantic": "2.13.4", "requests-oauthlib": "2.0.0"}
FAILURE = "X lookup failed; check configuration, proxy health and the operator audit log."
REQUIRED_ENV = ("SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN",
    "SERVERWARE_CA_FILE", "SERVERWARE_X_USERNAME")


def settings(env):
    """Validate explicit configuration; do not discover a provider credential."""
    username = env.get("SERVERWARE_X_USERNAME", "")
    if not re.fullmatch(r"[a-z0-9_]{1,15}", username):
        raise ValueError("An exact lowercase username is required")
    endpoint = env.get("SERVERWARE_PROXY_URL", "")
    parts = urlsplit(endpoint)
    if (not endpoint.isascii() or any(ord(c) < 33 or c == "\\" for c in endpoint)
            or parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path not in {"", "/"}
            or "?" in endpoint or "#" in endpoint
            or parts.port is not None and not 1 <= parts.port <= 65535):
        raise ValueError("A credential-free HTTPS proxy origin is required")
    app_id, token = env.get("SERVERWARE_APP_ID", ""), env.get("SERVERWARE_PROXY_TOKEN", "")
    if (str(UUID(app_id)) != app_id or not 1 <= len(token) <= 8192
            or not all(33 <= ord(c) <= 126 for c in token)):
        raise ValueError("A Serverware application login is required")
    for key in ("SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE"):
        if key == "SERVERWARE_CA_FILE" or key in env:
            value = env.get(key, "")
            if not value or not Path(value).is_absolute():
                raise ValueError("CA inputs must be explicit absolute files")
    # Requests owns Basic CONNECT authentication. Never log this in-memory URL.
    proxy = "https://" + quote(app_id, safe="") + ":" + quote(token, safe="") + "@" + parts.netloc
    return username, proxy


def child_environment(env):
    settings(env)
    result = {key: env[key] for key in REQUIRED_ENV}
    if "SERVERWARE_PROXY_CA_FILE" in env:
        result["SERVERWARE_PROXY_CA_FILE"] = env["SERVERWARE_PROXY_CA_FILE"]
    return result


def check_versions():
    if any(version(package) != expected for package, expected in PINS.items()):
        raise ValueError("Install the pinned requirements")


def public_ca(path):
    selected = Path(path)
    if not selected.is_absolute() or not selected.is_file():
        raise ValueError("An absolute CA file is required")
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
    with tempfile.TemporaryDirectory(prefix="serverware-x-ca-") as directory:
        combined = Path(directory) / "ca.pem"
        with combined.open("xb") as stream:
            os.chmod(combined, 0o600)
            stream.write(Path(certifi.where()).read_bytes() + b"\n" + extra + b"\n")
        yield str(combined)


class BoundedAdapter(HTTPAdapter):
    """Documented Requests adapter extension; SDK serialization is unchanged."""

    def __init__(self, outer_context):
        if outer_context.verify_mode != ssl.CERT_REQUIRED or not outer_context.check_hostname:
            raise ValueError("Verified proxy TLS is required")
        self.outer_context = outer_context
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def proxy_manager_for(self, proxy, **kwargs):
        return super().proxy_manager_for(proxy, proxy_ssl_context=self.outer_context, **kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        return super().send(request, stream=stream, timeout=(5, 10), verify=verify,
            cert=cert, proxies=proxies)


@contextmanager
def configured_client(env):
    from xdk import Client
    _, proxy = settings(env)
    outer = proxy_context(env.get("SERVERWARE_PROXY_CA_FILE"))
    with request_ca_bundle(env["SERVERWARE_CA_FILE"]) as bundle:
        client = Client(base_url=BASE_URL, bearer_token=PLACEHOLDER)
        try:
            client.session.trust_env = False  # No netrc, environment proxy or CA fallback.
            client.session.max_redirects = 0
            client.session.proxies = {"https": proxy}
            client.session.verify = bundle
            previous = client.session.adapters["https://"]
            client.session.mount("https://", BoundedAdapter(outer))
            previous.close()
            yield client
        finally:
            client.session.close()


def summary(value, username):
    if (type(value) is not dict or set(value) != {"id", "username", "name"}
            or type(value["id"]) is not str or not re.fullmatch(r"[0-9]{1,30}", value["id"])
            or type(value["username"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9_]{1,15}", value["username"])
            or value["username"].lower() != username
            or type(value["name"]) is not str or len(value["name"]) > 200):
        raise ValueError("Unexpected user summary")
    return value


def read_username(env):
    username, _ = settings(env)
    with configured_client(env) as client:
        result = client.users.get_by_username(username=username)
        if result.errors or result.data is None:
            raise ValueError("No complete user result")
        return summary({"id": result.data.id, "username": result.data.username,
            "name": result.data.name}, username)


def launch(env):
    check_versions()
    child = child_environment(env)
    # No provider credentials, HOME, proxy overrides, Python paths or TLS logging.
    result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
        env=child, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Child failed")
    return summary(json.loads(result.stdout), child["SERVERWARE_X_USERNAME"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Look up one permitted X username (read only).")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    try:
        if args.child:
            check_versions()
            value = read_username(child_environment(os.environ))
        else:
            value = launch(os.environ)
        print(json.dumps(value, ensure_ascii=True))
        return 0
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
