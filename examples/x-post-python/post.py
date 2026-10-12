"""One explicit text-only XDK post; integration is not yet available/verified."""
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

PLACEHOLDER = "serverware-x-post-placeholder-v1"  # Public, never a provider token.
BASE_URL = "https://api.x.com"
PINS = {"xdk": "0.10.6", "requests": "2.34.2", "urllib3": "2.8.0",
    "certifi": "2026.7.22", "pydantic": "2.13.4", "requests-oauthlib": "2.0.0"}
FAILURE = "X post preparation failed; no post was attempted by this invocation."
UNKNOWN = "X post outcome unknown. Do not replay; check the operator audit and X before any new action."
REQUIRED_ENV = ("SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN",
    "SERVERWARE_CA_FILE", "SERVERWARE_X_POST_TEXT", "SERVERWARE_X_POST_CONFIRM")


class OutcomeUnknown(Exception):
    def __init__(self):
        super().__init__(UNKNOWN)


def text_input(value):
    if type(value) is not str or "\0" in value or not 1 <= len(value.encode("utf-8")) <= 16384:
        raise ValueError("Invalid text")
    # Requests' pinned JSON serialization escapes Unicode. Check the actual
    # prepared bytes again at the adapter, without altering SDK serialization.
    if len(json.dumps({"text": value}, allow_nan=False).encode("utf-8")) > 32768:
        raise ValueError("Text-only JSON exceeds the wire bound")
    return value


def settings(env):
    if env.get("SERVERWARE_X_POST_CONFIRM") != "post-once":
        raise ValueError("Explicit single-post confirmation is required")
    text = text_input(env.get("SERVERWARE_X_POST_TEXT"))
    endpoint = env.get("SERVERWARE_PROXY_URL", "")
    parts = urlsplit(endpoint)
    if (not endpoint.isascii() or any(ord(c) < 33 or c == "\\" for c in endpoint)
            or parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path not in {"", "/"}
            or "?" in endpoint or "#" in endpoint
            or parts.port is not None and not 1 <= parts.port <= 65535):
        raise ValueError("An explicit credential-free HTTPS proxy is required")
    app_id, token = env.get("SERVERWARE_APP_ID", ""), env.get("SERVERWARE_PROXY_TOKEN", "")
    if (str(UUID(app_id)) != app_id or not 1 <= len(token) <= 8192
            or not all(33 <= ord(c) <= 126 for c in token)):
        raise ValueError("A Serverware application login is required")
    for key in ("SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE"):
        if key == "SERVERWARE_CA_FILE" or key in env:
            value = env.get(key, "")
            if not value or not Path(value).is_absolute():
                raise ValueError("Explicit absolute CA files are required")
    proxy = "https://" + quote(app_id, safe="") + ":" + quote(token, safe="") + "@" + parts.netloc
    return text, proxy


def child_environment(env):
    settings(env)
    child = {key: env[key] for key in REQUIRED_ENV}
    if "SERVERWARE_PROXY_CA_FILE" in env:
        child["SERVERWARE_PROXY_CA_FILE"] = env["SERVERWARE_PROXY_CA_FILE"]
    return child


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
    with tempfile.TemporaryDirectory(prefix="serverware-x-post-ca-") as directory:
        combined = Path(directory) / "ca.pem"
        with combined.open("xb") as stream:
            os.chmod(combined, 0o600)
            stream.write(Path(certifi.where()).read_bytes() + b"\n" + extra + b"\n")
        yield str(combined)


class SinglePostAdapter(HTTPAdapter):
    """Inspect, never rewrite, one SDK request; transport retries are disabled."""
    def __init__(self, outer_context, text):
        if outer_context.verify_mode != ssl.CERT_REQUIRED or not outer_context.check_hostname:
            raise ValueError("Verified proxy TLS is required")
        self.outer_context, self.text = outer_context, text
        self.attempted, self.status = False, None
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def proxy_manager_for(self, proxy, **kwargs):
        return super().proxy_manager_for(proxy, proxy_ssl_context=self.outer_context, **kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        if self.attempted:
            raise OutcomeUnknown()
        if (request.method != "POST" or request.url != BASE_URL + "/2/tweets"
                or type(request.body) is not bytes or not 0 < len(request.body) <= 32768
                or json.loads(request.body) != {"text": self.text}
                or request.headers.get("Authorization") != "Bearer " + PLACEHOLDER
                or request.headers.get("Content-Type") != "application/json"
                or "Proxy-Authorization" in request.headers or verify is False):
            raise ValueError("Unexpected prepared request")
        self.attempted = True
        response = None
        try:
            response = super().send(request, stream=True, timeout=(5, 10), verify=verify,
                cert=cert, proxies=proxies)
            self.status = response.status_code
            if self.status != 201:
                raise OutcomeUnknown()  # Includes withheld 409 and all redirects.
            chunks, length = [], 0
            for chunk in response.iter_content(chunk_size=8192):
                length += len(chunk)
                if length > 65536:
                    raise OutcomeUnknown()
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
            return response
        except Exception:
            raise OutcomeUnknown() from None
        finally:
            if response is not None:
                response.close()


@contextmanager
def configured_client(env):
    from xdk import Client
    text, proxy = settings(env)
    outer = proxy_context(env.get("SERVERWARE_PROXY_CA_FILE"))
    with request_ca_bundle(env["SERVERWARE_CA_FILE"]) as bundle:
        client = Client(base_url=BASE_URL, access_token=PLACEHOLDER)
        try:
            client.session.trust_env = False
            client.session.max_redirects = 0
            client.session.proxies = {"https": proxy}
            client.session.verify = bundle
            previous = client.session.adapters["https://"]
            client.session.mount("https://", SinglePostAdapter(outer, text))
            previous.close()
            yield client
        finally:
            client.session.close()


def summary(value):
    if (type(value) is not dict or set(value) != {"status", "id"}
            or type(value["status"]) is not int or value["status"] != 201
            or type(value["id"]) is not str or not re.fullmatch(r"[0-9]{1,20}", value["id"])):
        raise OutcomeUnknown()
    return value


def create_post(env):
    from xdk.posts.models import CreateRequest
    text, _ = settings(env)
    invoked = False
    try:
        with configured_client(env) as client:
            body = CreateRequest(text=text)
            invoked = True
            result = client.posts.create(body=body)
            if result.errors or result.data is None:
                raise OutcomeUnknown()
            return summary({"status": client.session.get_adapter(BASE_URL).status, "id": result.data.id})
    except BaseException:
        if invoked:
            raise OutcomeUnknown() from None
        raise


def launch(env):
    check_versions()
    child = child_environment(env)
    try:
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
            env=child, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False)
    except OSError:
        raise ValueError("Child could not start") from None
    except BaseException:
        raise OutcomeUnknown() from None
    if result.returncode == 1:
        raise ValueError("Child preparation failed")
    if result.returncode != 0 or result.stderr or len(result.stdout) > 4096:
        raise OutcomeUnknown()
    try:
        return summary(json.loads(result.stdout))
    except Exception:
        raise OutcomeUnknown() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create one confirmed text-only post; integration is not yet available.")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    completed = False
    try:
        if args.child:
            check_versions()
            value = create_post(child_environment(os.environ))
        else:
            value = launch(os.environ)
        completed = True
        print(json.dumps(value))
        return 0
    except OutcomeUnknown:
        print(UNKNOWN, file=sys.stderr)
        return 2
    except (Exception, KeyboardInterrupt):
        print(UNKNOWN if completed else FAILURE, file=sys.stderr)
        return 2 if completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
