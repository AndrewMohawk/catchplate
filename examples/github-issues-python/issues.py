"""Read one repository through Serverware using unmodified PyGithub transport."""
import argparse
from contextlib import contextmanager
from importlib.metadata import version
from itertools import islice
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

PLACEHOLDER = "serverware-github-placeholder-v1"  # Public, not a GitHub credential.
PINS = {"PyGithub": "2.10.0", "requests": "2.34.2", "urllib3": "2.8.0", "certifi": "2026.7.22"}
FAILURE = "GitHub example failed; check configuration, proxy health and the operator audit log."
PROXY_CA_FAILURE = "This PyGithub example cannot use a separate proxy CA; use a publicly trusted proxy endpoint or the Node/Go example."
MAX_CONFIG_BYTES = 64 * 1024


class UnsupportedProxyCA(ValueError):
    pass


def configuration_environment(config_file, env):
    """Read the console's private JSON as data, never as a command or recipe."""
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

    def invalid_constant(_value):
        raise ValueError("Invalid configuration number")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
        parse_float=number, parse_constant=invalid_constant)
    if type(value) is not dict:
        raise ValueError("Invalid configuration object")
    for field in ("application_id", "access_rule_id"):
        if type(value.get(field)) is not str or str(UUID(value[field])) != value[field]:
            raise ValueError("Invalid configuration identity")
    expiry = value.get("token_expires_at_epoch_ms")
    scope = value.get("repository")
    if (value.get("proxy_authentication") != "basic_and_bearer_v1"
            or value.get("proxy_username") != value["application_id"]
            or type(expiry) is not int or not time.time_ns() // 1_000_000 < expiry <= 2**53 - 1
            or value.get("operation_bundle") not in {"github_issues_read_v1", "github_issues_write_v1"}
            or type(scope) is not dict or set(scope) != {"owner", "name"}):
        raise ValueError("Invalid GitHub configuration scope")
    if any(type(value.get(field)) is not str for field in ("proxy_url", "proxy_password")) \
            or any(type(scope[field]) is not str for field in ("owner", "name")):
        raise ValueError("Invalid GitHub connection values")
    methods = value.get("methods")
    expected_methods = {"GET"} if value["operation_bundle"] == "github_issues_read_v1" else {"GET", "POST"}
    if (type(methods) is not list or any(type(method) is not str for method in methods)
            or len(methods) != len(expected_methods) or set(methods) != expected_methods):
        raise ValueError("GitHub methods differ from permission bundle")

    def ca_path(item):
        if type(item) is not str or not item or len(item) > 4096 or "\x00" in item:
            raise ValueError("Invalid CA path")
        return str((path.parent / item).resolve())

    selected = dict(env)
    selected.pop("SERVERWARE_PROXY_CA_FILE", None)
    selected.update(SERVERWARE_APP_ID=value["application_id"],
        SERVERWARE_PROXY_URL=value.get("proxy_url"), SERVERWARE_PROXY_TOKEN=value.get("proxy_password"),
        SERVERWARE_GITHUB_OWNER=scope["owner"], SERVERWARE_GITHUB_REPO=scope["name"],
        SERVERWARE_CA_FILE=ca_path(value.get("ca_file")))
    if value.get("upstream_url") != "https://api.github.com/repos/" + repository(selected) + "/issues":
        raise ValueError("GitHub upstream differs from repository")
    recipe = value.get("client_recipe", {})
    if type(recipe) is not dict:
        raise ValueError("Invalid client recipe")
    if recipe.get("proxy_ca_file") is not None:
        selected["SERVERWARE_PROXY_CA_FILE"] = ca_path(recipe["proxy_ca_file"])
    child_environment(selected, selected["SERVERWARE_CA_FILE"])
    return selected


def repository(env):
    owner = env.get("SERVERWARE_GITHUB_OWNER", "")
    name = env.get("SERVERWARE_GITHUB_REPO", "")
    if (not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) or name in {".", ".."}):
        raise ValueError("Explicit repository required")
    return owner + "/" + name


def child_environment(env, ca_file):
    """Return a NEW minimal environment; never mutate or copy ambient settings."""
    repository(env)
    if "SERVERWARE_PROXY_CA_FILE" in env:
        raise UnsupportedProxyCA(PROXY_CA_FAILURE)
    endpoint = env.get("SERVERWARE_PROXY_URL", "")
    parts = urlsplit(endpoint)
    if (not endpoint.isascii() or any(ord(c) < 33 or c in "\\" for c in endpoint)
            or parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path not in {"", "/"}
            or "?" in endpoint or "#" in endpoint
            or parts.port is not None and not 1 <= parts.port <= 65535):
        raise ValueError("A credential-free HTTPS proxy origin is required")
    app_id = env.get("SERVERWARE_APP_ID", "")
    token = env.get("SERVERWARE_PROXY_TOKEN", "")
    if str(UUID(app_id)) != app_id or not 1 <= len(token) <= 8192 or not all(33 <= ord(c) <= 126 for c in token):
        raise ValueError("Application login required")
    # Requests' documented Basic proxy authentication interface. Never log this URL.
    proxy = "https://" + quote(app_id, safe="") + ":" + quote(token, safe="") + "@" + parts.netloc
    return {"HTTPS_PROXY": proxy, "NO_PROXY": "",
        "SERVERWARE_GITHUB_OWNER": env["SERVERWARE_GITHUB_OWNER"],
        "SERVERWARE_GITHUB_REPO": env["SERVERWARE_GITHUB_REPO"],
        "SERVERWARE_CA_FILE": str(ca_file)}


@contextmanager
def client_ca_bundle(ca_file):
    """Client-only public trust material. Do not modify certifi or system trust."""
    import certifi
    path = Path(ca_file)
    if not path.is_absolute() or not path.is_file():
        raise ValueError("Absolute CA file required")
    with path.open("rb") as stream:
        extra = stream.read(65537)
    if not extra or len(extra) > 65536 or b"PRIVATE KEY" in extra:
        raise ValueError("Invalid CA material")
    context = ssl.create_default_context(cafile=certifi.where())
    context.load_verify_locations(cadata=extra.decode("ascii"))
    roots = Path(certifi.where()).read_bytes()
    with tempfile.TemporaryDirectory(prefix="serverware-github-ca-") as directory:
        combined = Path(directory) / "ca.pem"
        with combined.open("xb") as stream:
            os.chmod(combined, 0o600)
            stream.write(roots + b"\n" + extra + b"\n")
        yield str(combined)


def check_versions():
    if any(version(package) != expected for package, expected in PINS.items()):
        raise ValueError("Install the pinned requirements")


def read_issues(env, limit):
    """Normal SDK pagination; no repository metadata call or URL/header rewriting."""
    from github import Auth, Github
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Limit must be between 1 and 100")
    name = repository(env)
    with Github(auth=Auth.Token(PLACEHOLDER), lazy=True, per_page=30,
                verify=env["SERVERWARE_CA_FILE"], retry=None, timeout=10,
                api_version="2022-11-28") as client:
        repo = client.get_repo(name)
        rows = []
        for issue in islice(repo.get_issues(state="open", sort="updated", direction="desc"), limit):
            # These public properties are populated by normal issue-list responses.
            # raw_data would force lazy completion even when these fields are present.
            number, title, state = issue.number, issue.title, issue.state
            if (type(number) is not int or number <= 0
                    or not isinstance(title, str) or state not in {"open", "closed"}):
                raise ValueError("Unexpected issue summary")
            rows.append({"number": number, "title": title[:512], "state": state})
        return rows


def launch(env, limit):
    check_versions()
    # Validate all configuration before creating the child or its trust bundle.
    child_environment(env, env.get("SERVERWARE_CA_FILE", ""))
    with client_ca_bundle(env.get("SERVERWARE_CA_FILE", "")) as ca_file:
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--child", "--limit", str(limit)], env=child_environment(env, ca_file),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False)
    if result.returncode != 0 or len(result.stdout) > 1048576:
        raise ValueError("Child failed")
    rows = json.loads(result.stdout)
    if (not isinstance(rows, list) or len(rows) > limit or any(
            not isinstance(row, dict) or set(row) != {"number", "title", "state"}
            or type(row["number"]) is not int or row["number"] <= 0
            or not isinstance(row["title"], str) or len(row["title"]) > 512
            or row["state"] not in {"open", "closed"} for row in rows)):
        raise ValueError("Invalid child result")
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description="List up to 100 open issues (read only).")
    parser.add_argument("--limit", type=int, choices=range(1, 101), default=100, metavar="1..100")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", metavar="PATH", help="Private client JSON downloaded from Serverware")
    args = parser.parse_args(argv)
    # Requests exceptions/debug logging may contain proxy credentials. Never emit them.
    logging.disable(logging.CRITICAL)
    try:
        if args.child and args.config is not None:
            raise ValueError("Downloaded configuration is parent-only")
        if args.child:
            check_versions()
            proxy = urlsplit(os.environ.get("HTTPS_PROXY", ""))
            if proxy.scheme != "https" or not proxy.username or not proxy.password or os.environ.get("NO_PROXY") != "":
                raise ValueError("Private child configuration required")
            rows = read_issues(os.environ, args.limit)
        else:
            env = os.environ if args.config is None else configuration_environment(args.config, os.environ)
            rows = launch(env, args.limit)
        print(json.dumps(rows, ensure_ascii=True))
        return 0
    except UnsupportedProxyCA:
        print(PROXY_CA_FAILURE, file=sys.stderr)
        return 1
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
