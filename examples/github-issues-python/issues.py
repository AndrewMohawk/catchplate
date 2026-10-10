"""Read one repository through Serverware using unmodified PyGithub transport."""
import argparse
from contextlib import contextmanager
from importlib.metadata import version
from itertools import islice
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

PLACEHOLDER = "serverware-github-placeholder-v1"  # Public, not a GitHub credential.
PINS = {"PyGithub": "2.10.0", "requests": "2.34.2", "urllib3": "2.8.0", "certifi": "2026.7.22"}
FAILURE = "GitHub example failed; check configuration, proxy health and the operator audit log."


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
        raise ValueError("Independent proxy CA is unsupported by stock PyGithub")
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
    args = parser.parse_args(argv)
    # Requests exceptions/debug logging may contain proxy credentials. Never emit them.
    logging.disable(logging.CRITICAL)
    try:
        if args.child:
            check_versions()
            proxy = urlsplit(os.environ.get("HTTPS_PROXY", ""))
            if proxy.scheme != "https" or not proxy.username or not proxy.password or os.environ.get("NO_PROXY") != "":
                raise ValueError("Private child configuration required")
            rows = read_issues(os.environ, args.limit)
        else:
            rows = launch(os.environ, args.limit)
        print(json.dumps(rows, ensure_ascii=True))
        return 0
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
