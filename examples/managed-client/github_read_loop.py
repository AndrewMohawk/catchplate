"""Long-running, read-only stock Requests example with managed pool handoff.

Only one exact repository's issues-list GET is submitted. No provider write,
transport retry, redirect, monkeypatch or private Serverware import is used.
"""
import argparse
from contextlib import contextmanager
import json
import logging
from pathlib import Path
import re
import signal
import ssl
import sys
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit

from managed_client import ManagedClient, RenewalUnavailable

PLACEHOLDER = "serverware-github-placeholder-v1"
MAX_BODY_BYTES = 65536
READ_SECONDS = 10


def repository(owner, name):
    if (not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) or name in {".", ".."}):
        raise ValueError("An exact repository is required")
    return owner + "/" + name


@contextmanager
def ca_bundle(path):
    """Public client-only trust bundle; outer proxy and inner TLS both verify."""
    import certifi

    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Absolute CA path required")
    with path.open("rb") as stream:
        extra = stream.read(65537)
    if not extra or len(extra) > 65536 or b"PRIVATE KEY" in extra:
        raise ValueError("Invalid CA material")
    context = ssl.create_default_context(cafile=certifi.where())
    context.load_verify_locations(cadata=extra.decode("ascii"))
    with open(certifi.where(), "rb") as stream:
        roots = stream.read(2 * 1024 * 1024 + 1)
    if len(roots) > 2 * 1024 * 1024:
        raise ValueError("CA bundle too large")
    with tempfile.TemporaryDirectory(prefix="serverware-managed-client-ca-") as temporary:
        output = Path(temporary) / "ca.pem"
        with output.open("xb") as stream:
            output.chmod(0o600)
            stream.write(roots + b"\n" + extra + b"\n")
        yield str(output)


def new_session(manager, lease, ca_file):
    import requests
    from requests.adapters import HTTPAdapter

    parsed = urlsplit(manager.proxy_origin)
    # Standard Requests Basic proxy login. This private URL is memory-only.
    proxy = "https://" + quote(manager.application_id, safe="") + ":" + quote(lease.token, safe="") + "@" + parsed.netloc
    session = requests.Session()
    session.trust_env = False  # No ambient proxy, CA, netrc or browser credentials.
    session.proxies = {"https": proxy}
    session.verify = ca_file
    session.headers.update({"Authorization": "token " + PLACEHOLDER,
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    session.mount("https://", HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1))
    return session


class SessionPool:
    """Application-owned SDK pool; generation change closes it immediately."""
    def __init__(self, factory):
        self.factory, self.session, self.generation = factory, None, None

    def for_lease(self, lease):
        if self.session is None or self.generation != lease.generation:
            self.close()
            self.session = self.factory(lease)
            self.generation = lease.generation
        return self.session

    def close(self):
        if self.session is not None:
            self.session.close()
        self.session, self.generation = None, None


@contextmanager
def read_deadline(seconds):
    """Linux main-thread total deadline, including trickling response headers."""
    if seconds <= 0 or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RenewalUnavailable("Provider read cannot fit the current token lifetime")
    def expired(*_):
        raise TimeoutError("Bounded provider read expired")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def read_once(session, repo, lease):
    remaining = (lease.expires_at_epoch_ms - time.time_ns() // 1_000_000) / 1000
    with read_deadline(min(READ_SECONDS, remaining)):
        # One GET per loop. A subsequent iteration is not a retry of a write.
        with session.get("https://api.github.com/repos/" + repo + "/issues",
                params={"state": "open", "sort": "updated", "direction": "desc", "per_page": 1},
                allow_redirects=False, stream=True, timeout=(5, 5)) as response:
            if response.status_code != 200:
                raise ValueError("Provider read refused")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=1024):
                body.extend(chunk)
                if len(body) > MAX_BODY_BYTES:
                    raise ValueError("Provider response exceeds its bound")
            value = json.loads(body)
            if (type(value) is not list or len(value) > 1 or any(type(item) is not dict
                    or type(item.get("number")) is not int or item["number"] < 1 for item in value)):
                raise ValueError("Provider response shape refused")
            return {"issues_observed": len(value), "token_generation": lease.generation}


def run(manager, repo, ca_file, *, interval=30, iterations=None, stop=None):
    if type(interval) is not int or not 1 <= interval <= 60:
        raise ValueError("The worker must poll its manager at least every 60 seconds")
    if iterations is not None and (type(iterations) is not int or iterations < 1):
        raise ValueError("Iterations must be positive")
    stop = stop or threading.Event()
    pool = SessionPool(lambda lease: new_session(manager, lease, ca_file))
    completed = 0
    try:
        while not stop.is_set() and (iterations is None or completed < iterations):
            try:
                lease = manager.lease()
                session = pool.for_lease(lease)
                result = read_once(session, repo, lease)
                session.cookies.clear()
                print(json.dumps(result), flush=True)
            except Exception:
                pool.close()
                # No HTTP exception, URL, headers, body, token or key is logged.
                print("Read unavailable; no provider write or transport retry was sent.", file=sys.stderr, flush=True)
            completed += 1
            if iterations is None or completed < iterations:
                stop.wait(interval)
    finally:
        pool.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Repeated bounded GitHub issues reads with managed token renewal")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--iterations", type=int)
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        repo = repository(args.owner, args.repo)
        with ca_bundle(args.ca_file) as bundle, ManagedClient(args.state_dir) as manager:
            run(manager, repo, bundle, interval=args.interval, iterations=args.iterations, stop=stop)
        return 0
    except Exception:
        print("Managed GitHub reader unavailable; check enrollment, private state and CA configuration.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
