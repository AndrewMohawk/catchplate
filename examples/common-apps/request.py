"""One explicit, bounded API request through Serverware; no provider credentials."""
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
import sys
import time
from urllib.parse import quote, urlencode, urlsplit
from uuid import UUID

MAX_CONFIG_BYTES = 65536
MAX_BODY_BYTES = 65536
MAX_RESPONSE_BYTES = 1048576
PINS = {"requests": "2.34.2", "urllib3": "2.8.0", "certifi": "2026.7.22",
    "charset-normalizer": "3.5.2", "idna": "3.20"}
# These are public replacement markers, never upstream credentials.
PROVIDERS = {
    "openai": ("api.openai.com", "Authorization", "Bearer "),
    "anthropic": ("api.anthropic.com", "x-api-key", ""),
    "gemini": ("generativelanguage.googleapis.com", "x-goog-api-key", ""),
    "openrouter": ("openrouter.ai", "Authorization", "Bearer "),
    "slack": ("slack.com", "Authorization", "Bearer "),
    "discord": ("discord.com", "Authorization", "Bot "),
    "notion": ("api.notion.com", "Authorization", "Bearer "),
    "stripe": ("api.stripe.com", "Authorization", "Bearer "),
    "resend": ("api.resend.com", "Authorization", "Bearer "),
    "gitlab": ("gitlab.com", "PRIVATE-TOKEN", ""),
    "cloudflare": ("api.cloudflare.com", "Authorization", "Bearer "),
    "sentry": ("sentry.io", "Authorization", "Bearer "),
}
FAILURE = "Request failed; inspect Serverware's audit log. If a write was sent, its outcome may be unknown: do not blindly retry."
LOCAL_ERRORS = {
    "config_missing": "Private config not found. Use --config with the downloaded JSON file.",
    "config_invalid": "Private config is invalid or incompatible. Use the complete common-app download, not its nested recipe.",
    "token_expired": "Client token expired. Ask the operator for a current private client configuration.",
    "dependencies": "Pinned dependencies are missing or differ. Install requirements.txt in the selected virtual environment before supplying credentials.",
    "ca_invalid": "Interception CA is missing or invalid. Place the verified public CA at the config's ca_file path; relative paths start beside the JSON.",
    "proxy_ca_invalid": "Outer proxy CA is missing or invalid. Check the optional proxy_ca_file; never disable TLS verification.",
    "query_invalid": "Query arguments do not match this permission. Use only its allowed keys without overriding configured selectors.",
    "check_flags": "--check-config cannot be combined with a body, write confirmation or --print-example-body.",
}


class LocalConfigurationError(ValueError):
    """Only fixed, token-safe local diagnostics may reach the CLI."""
    def __init__(self, code):
        self.code = code if code in LOCAL_ERRORS else "config_invalid"
        super().__init__(LOCAL_ERRORS[self.code])


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Non-finite JSON number")
        return result

    def constant(_):
        raise ValueError("Non-finite JSON constant")

    return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)


def read_file(path, limit):
    """Bounded, non-blocking regular-file read; never interpret config as code."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("A bounded regular file is required")
        raw = source.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("File size refused")
    return raw


def https_url(value, *, origin=False):
    if (type(value) is not str or not 1 <= len(value) <= 2048 or not value.isascii()
            or any(ord(char) < 33 or ord(char) > 126 or char == "\\" for char in value)):
        raise ValueError("An HTTPS URL is required")
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.fragment or parts.query
            or "?" in value or "#" in value
            or origin and parts.path not in {"", "/"}
            or parts.port is not None and not 1 <= parts.port <= 65535):
        raise ValueError("Credential-free HTTPS URL required")
    return parts


def load_configuration(path):
    """Consume the workspace download directly, normalizing relative CA paths."""
    path = Path(path).absolute()
    config = strict_json(read_file(path, MAX_CONFIG_BYTES).decode("utf-8"))
    if type(config) is not dict:
        raise ValueError("A client configuration object is required")
    for field in ("application_id", "access_rule_id"):
        if type(config.get(field)) is not str or str(UUID(config[field])) != config[field]:
            raise ValueError("Invalid application or permission identity")
    expiry = config.get("token_expires_at_epoch_ms")
    if type(expiry) is int and 0 < expiry <= time.time_ns() // 1000000:
        raise LocalConfigurationError("token_expired")
    if (config.get("proxy_authentication") != "basic_and_bearer_v1"
            or config.get("proxy_username") != config["application_id"]
            or type(expiry) is not int or not time.time_ns() // 1000000 < expiry <= 2**53 - 1
            or config.get("app_preset") not in PROVIDERS
            or type(config.get("app_operation")) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", config["app_operation"]) is None
            or type(config.get("scope")) is not dict
            or config.get("methods") not in (["GET"], ["POST"])
            or config.get("credential_input") != "replace_exact"
            or config.get("response_mode") != "unfiltered_json_or_empty_v2"):
        raise ValueError("Invalid common-app configuration")
    host, auth_header, prefix = PROVIDERS[config["app_preset"]]
    target = https_url(config.get("upstream_url"))
    if target.hostname != host or target.port is not None:
        raise ValueError("Upstream differs from the selected provider")
    proxy = https_url(config.get("proxy_url"), origin=True)
    token = config.get("proxy_password")
    if type(token) is not str or not 1 <= len(token) <= 8192 or not all(33 <= ord(c) <= 126 for c in token):
        raise ValueError("Application proxy password required")
    headers = config.get("request_headers")
    allowed_headers = {auth_header.lower(), "accept", "content-type", "notion-version", "anthropic-version"}
    if (type(headers) is not dict or len(headers) > 8
            or any(type(key) is not str or key.lower() not in allowed_headers
                or type(value) is not str or not 1 <= len(value) <= 256
                or any(ord(char) < 32 or ord(char) > 126 for char in value)
                for key, value in headers.items())
            or len({key.lower() for key in headers}) != len(headers)):
        raise ValueError("Unexpected request headers")
    lowered = {key.lower(): value for key, value in headers.items()}
    if lowered.get(auth_header.lower()) != prefix + "serverware-" + config["app_preset"] + "-placeholder-v1":
        raise ValueError("Only the public provider placeholder belongs in client configuration")
    recipe = config.get("client_recipe", {})
    if type(recipe) is not dict or recipe.get("automatic_retries", 0) != 0:
        raise ValueError("Automatic retries are not supported")
    for field in ("ca_file", "proxy_ca_file"):
        value = config.get(field, recipe.get(field))
        if field == "proxy_ca_file" and value is None:
            config[field] = None
            continue
        if type(value) is not str or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid public CA path")
        config[field] = str((path.parent / value).resolve())
    # Requests owns the Basic CONNECT header. Never print this URL or exceptions.
    config["_proxy_url"] = "https://" + quote(config["proxy_username"], safe="") + ":" + quote(token, safe="") + "@" + proxy.netloc
    query = config.setdefault("request_query", {})
    if (type(query) is not dict or any(type(key) is not str or type(value) is not str
            for key, value in query.items())):
        raise ValueError("Invalid configured query")
    return config


def check_versions():
    if any(version(package) != expected for package, expected in PINS.items()):
        raise ValueError("Install the pinned requirements")


def public_ca(path):
    raw = read_file(path, 65536)
    if b"PRIVATE KEY" in raw:
        raise ValueError("CA file must contain only public certificates")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=raw.decode("ascii"))
    return raw


def check_local_configuration(config, query=()):
    """Check local inputs only: no session, DNS, proxy or provider request."""
    try:
        request_url(config, query)
    except Exception:
        raise LocalConfigurationError("query_invalid") from None
    try:
        check_versions()
    except Exception:
        raise LocalConfigurationError("dependencies") from None
    for field, code in (("ca_file", "ca_invalid"), ("proxy_ca_file", "proxy_ca_invalid")):
        if field == "proxy_ca_file" and config[field] is None:
            continue
        try:
            public_ca(config[field])
        except Exception:
            raise LocalConfigurationError(code) from None


def read_bounded(response):
    limit = MAX_RESPONSE_BYTES if 200 <= response.status_code < 300 else MAX_BODY_BYTES
    chunks, size = [], 0
    for chunk in response.iter_content(chunk_size=8192):
        size += len(chunk)
        if size > limit:
            raise ValueError("Response exceeded the configured bound")
        chunks.append(chunk)
    return b"".join(chunks)


@contextmanager
def client_session(config):
    """Ordinary Requests HTTPS CONNECT with separate inner and outer TLS trust."""
    import certifi
    import requests
    from requests.adapters import HTTPAdapter

    outer = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    outer.minimum_version = ssl.TLSVersion.TLSv1_2
    outer.load_verify_locations(cafile=certifi.where())
    if config["proxy_ca_file"] is not None:
        outer.load_verify_locations(cadata=public_ca(config["proxy_ca_file"]).decode("ascii"))
    public_ca(config["ca_file"])

    class SingleRequestAdapter(HTTPAdapter):
        def __init__(self):
            self.attempted = False
            super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

        def proxy_manager_for(self, proxy, **kwargs):
            return super().proxy_manager_for(proxy, proxy_ssl_context=outer, **kwargs)

        def send(self, request, **kwargs):
            if self.attempted:
                raise ValueError("This example never automatically sends a second request")
            self.attempted = True
            response = super().send(request, **kwargs)
            try:
                # Bound even redirect bodies before Requests prepares a redirect.
                response._content = read_bounded(response)
                response._content_consumed = True
                return response
            finally:
                response.close()

    with requests.Session() as session:
        session.trust_env = False  # No ambient proxy, .netrc, or CA overrides.
        session.headers.clear()
        session.verify = config["ca_file"]
        session.proxies = {"https": config["_proxy_url"]}
        session.mount("https://", SingleRequestAdapter())
        yield session


def request_url(config, additions=()):
    query = dict(config["request_query"])
    allowed = config.get("query_keys", list(query))
    if type(allowed) is not list or any(type(key) is not str for key in allowed):
        raise ValueError("Invalid query key list")
    for entry in additions:
        key, separator, value = entry.partition("=")
        if not separator or key not in allowed or key in query:
            raise ValueError("Unknown or repeated query key")
        query[key] = value
    if any(key not in allowed or len(key) > 128 or len(value) > 2048 for key, value in query.items()):
        raise ValueError("Query differs from this operation")
    suffix = urlencode(sorted(query.items()), quote_via=quote, safe="")
    return config["upstream_url"] + ("?" + suffix if suffix else "")


class RequestExecutionError(ValueError):
    """Token-safe failure; request_started means invoked, not proven delivered."""
    def __init__(self, *, request_started=False, outcome_unknown=False):
        super().__init__(FAILURE)
        self.request_started = request_started
        self.outcome_unknown = outcome_unknown


def execute_body(config, body=None, execute_write=False, query=()):
    """Send bytes unchanged, without reading a body file, printing, or retrying.

    Callers supply a validated configuration and explicit write intent. This is
    not human approval: the proxy's permission and review policy still apply.
    JSON/empty/428 results retain the same {status, response} shape as the CLI.
    All helper failures are sanitized; never expose the private config itself.
    """
    request_started, method = False, None
    try:
        if config.get("methods") not in (["GET"], ["POST"]) or type(execute_write) is not bool:
            raise ValueError("An explicit supported method and boolean intent are required")
        method = config["methods"][0]
        if method == "POST":
            if execute_write is not True or type(body) is not bytes or not 0 < len(body) <= MAX_BODY_BYTES:
                raise ValueError("A write requires explicit intent and a bounded byte body")
            if type(strict_json(body.decode("utf-8"))) is not dict:
                raise ValueError("The request body must be a JSON object")
        elif body is not None or execute_write:
            raise ValueError("This permission is read-only")
        headers = {"Accept": "application/json", "Accept-Encoding": "identity",
            "User-Agent": "serverware-common-apps-example/1.0", **config["request_headers"]}
        if body is not None:
            headers["Content-Type"] = "application/json"
        url = request_url(config, query)
        with client_session(config) as session:
            request_started = True
            response = session.request(method, url, headers=headers, data=body,
                timeout=(5, 30), allow_redirects=False, stream=True)
            raw = response.content
            if response.status_code == 204 and not raw:
                return {"status": 204, "response": None}
            if "application/json" not in response.headers.get("Content-Type", "").lower():
                raise ValueError("Expected a bounded JSON response")
            return {"status": response.status_code, "response": strict_json(raw.decode("utf-8"))}
    except Exception:
        # Raise outside the handler so no private transport exception survives
        # as __context__ or __cause__ on the public failure object.
        pass
    raise RequestExecutionError(request_started=request_started,
        outcome_unknown=request_started and method == "POST")


def execute(config, body_path=None, execute_write=False, query=()):
    """CLI/file compatibility wrapper; never read a body without write intent."""
    try:
        body = None
        if config["methods"] == ["POST"]:
            if execute_write is not True or body_path is None:
                raise ValueError("A write requires --body PATH and --execute-write")
            body = read_file(body_path, MAX_BODY_BYTES)
        elif body_path is not None or execute_write:
            raise ValueError("This permission is read-only")
    except Exception:
        pass
    else:
        return execute_body(config, body, execute_write, query)
    raise RequestExecutionError()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Send one scoped request using the private Serverware client download.")
    parser.add_argument("--config", required=True, metavar="PATH")
    parser.add_argument("--body", metavar="PATH", help="Explicit reviewed JSON body; required for POST")
    parser.add_argument("--execute-write", action="store_true", help="Confirm this invocation may perform one write or paid AI call")
    parser.add_argument("--query", action="append", default=[], metavar="KEY=VALUE", help="An allowed read query; cannot override fixed scope")
    parser.add_argument("--print-example-body", action="store_true", help="Print the scoped example body and exit without a request")
    parser.add_argument("--check-config", action="store_true", help="Validate config, expiry, dependencies, CA files and query locally; send nothing")
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    execution_entered = False
    try:
        try:
            config = load_configuration(args.config)
        except LocalConfigurationError:
            raise
        except FileNotFoundError:
            raise LocalConfigurationError("config_missing") from None
        except Exception:
            raise LocalConfigurationError("config_invalid") from None
        if args.check_config:
            if args.body is not None or args.execute_write or args.print_example_body:
                raise LocalConfigurationError("check_flags")
            check_local_configuration(config, args.query)
            print(json.dumps({"status": "configuration_ready", "provider_calls": 0,
                "network_checked": False, "method": config["methods"][0],
                "write_confirmation_required": config["methods"] == ["POST"]}))
            return 0
        if args.print_example_body:
            if args.body is not None or args.execute_write or args.query or type(config.get("request_body")) is not dict:
                raise ValueError("This operation has no example body, or incompatible flags")
            print(json.dumps(config["request_body"], ensure_ascii=True, indent=2))
            return 0
        if config["methods"] == ["POST"] and (args.body is None or not args.execute_write):
            print("This is a write or paid API call. Review a JSON body, then explicitly pass --body PATH --execute-write. Nothing was sent.", file=sys.stderr)
            return 2
        check_local_configuration(config, args.query)
        execution_entered = True
        result = execute(config, args.body, args.execute_write, args.query)
        print(json.dumps(result, ensure_ascii=True))
        provider_error = type(result["response"]) is dict and (
            config["app_preset"] == "slack" and result["response"].get("ok") is False
            or config["app_preset"] == "cloudflare" and result["response"].get("success") is False)
        if result["status"] == 428:
            print("Approval required. Open the review URL in the JSON response. After approval, explicitly rerun the identical command and unchanged body. Nothing is retried automatically.", file=sys.stderr)
        elif not 200 <= result["status"] < 300 or provider_error:
            print("The request did not return success. Inspect the response and audit log before retrying; a write outcome may be unknown.", file=sys.stderr)
        return 0 if 200 <= result["status"] < 300 and not provider_error else 2
    except LocalConfigurationError as error:
        print("Nothing was sent. " + LOCAL_ERRORS[error.code], file=sys.stderr)
        return 1
    except RequestExecutionError as error:
        print(FAILURE if error.request_started else
            "Nothing was sent. Check the local body, query and verified CA files before trying again.", file=sys.stderr)
        return 1
    except Exception:
        # Exceptions from proxy transports may contain the private proxy URL.
        print(FAILURE if execution_entered else
            "Nothing was sent. Check the local body file and command arguments. Do not include provider credentials.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
