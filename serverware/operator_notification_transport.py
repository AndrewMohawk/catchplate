"""Bounded, one-attempt notification transport; no approval or retry authority.

URLs are secrets. Nothing public returns them, resolver errors, response bodies
or exception details. The worker owns safe event projection and retry policy;
this module owns destination admission, TLS and acknowledgement semantics.
"""
from __future__ import annotations

import http.client
import io
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from serverware import http_client

MAX_URL_BYTES = 4096
MAX_PAYLOAD_BYTES = 16384
MAX_RESPONSE_BYTES = 8192
MAX_RESPONSE_WIRE_BYTES = 32768
TOTAL_TIMEOUT = 10.0
DNS_TIMEOUT = 3.0
CONNECT_TIMEOUT = 3.0
RETRYABLE_CODES = frozenset({"dns_unavailable", "dns_timeout", "connect_unavailable",
    "connect_timeout", "tls_unavailable", "tls_timeout"})
_FAILURE_CODES = RETRYABLE_CODES | {"destination_invalid", "egress_denied", "payload_invalid",
    "transport_unavailable", "deadline_exceeded", "dispatch_cancelled", "http_rejected", "acknowledgement_invalid"}
DELIVERY_CODES = frozenset(_FAILURE_CODES | {"acknowledged", "delivery_unknown"})
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
_SLACK_PATH = re.compile(r"/services/[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_-]{1,256}\Z")
_SLACK_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in
    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_METADATA_ADDRESSES = frozenset({ipaddress.ip_address("168.63.129.16"),
    ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254")})
_METADATA_HOSTS = frozenset({"metadata.google.internal", "instance-data.ec2.internal"})
_PAYLOAD_KEYS = frozenset({"schema", "channel", "source", "summary", "review_path", "details",
    "projection", "approval_ref", "expires_at", "delivery_id", "slot", "revision", "review_url", "test"})
_DNS_SLOTS = threading.BoundedSemaphore(2)
# Fixed code, never a URL or shell interpolation. The child output is bounded
# before serialization; communicate() therefore cannot buffer arbitrary output.
_DNS_CODE = """import json,socket,sys
try:
 data=json.loads(sys.stdin.buffer.read(1024))
 rows=socket.getaddrinfo(data[0],data[1],type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)
 if not 1 <= len(rows) <= 64: raise ValueError()
 result=[]
 for family,kind,proto,canon,address in rows:
  if family not in (socket.AF_INET,socket.AF_INET6): raise ValueError()
  pair=[family,address[0]]
  if pair not in result: result.append(pair)
 output=json.dumps(result,separators=(',',':')).encode('ascii')
 if len(output)>8192: raise ValueError()
 sys.stdout.buffer.write(output)
except BaseException:
 sys.exit(1)
"""


class DestinationError(ValueError):
    def __init__(self) -> None:
        super().__init__("notification destination invalid")


class EgressPolicyError(ValueError):
    def __init__(self) -> None:
        super().__init__("notification egress policy invalid")


@dataclass(frozen=True)
class DeliveryResult:
    state: str
    code: str
    http_status: int | None = None

    def __post_init__(self) -> None:
        if type(self.state) is not str or type(self.code) is not str:
            raise ValueError("notification delivery result invalid")
        valid = ((self.state == "acknowledged" and self.code == "acknowledged")
            or (self.state == "outcome_unknown" and self.code == "delivery_unknown")
            or (self.state == "failed" and self.code in _FAILURE_CODES))
        if not valid or (self.http_status is not None and
                (type(self.http_status) is not int or not 200 <= self.http_status <= 599)):
            raise ValueError("notification delivery result invalid")

    @property
    def retryable(self) -> bool:
        return self.state == "failed" and self.code in RETRYABLE_CODES and self.http_status is None


def _host_valid(host: object) -> bool:
    return (type(host) is str and len(host) <= 253 and _HOST.fullmatch(host) is not None
        and not all(part.isdigit() for part in host.split(".")) and host not in _METADATA_HOSTS)


@dataclass(frozen=True)
class EgressBinding:
    host: str
    port: int
    cidrs: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            if (not _host_valid(self.host) or type(self.port) is not int or not 1 <= self.port <= 65535
                    or type(self.cidrs) is not tuple or not 1 <= len(self.cidrs) <= 4):
                raise EgressPolicyError()
            if len(set(self.cidrs)) != len(self.cidrs):
                raise EgressPolicyError()
            for value in self.cidrs:
                if type(value) is not str:
                    raise EgressPolicyError()
                network = ipaddress.ip_network(value, strict=True)
                if str(network) != value or not any(network.version == base.version
                        and network.subnet_of(base) for base in _PRIVATE_NETWORKS):
                    raise EgressPolicyError()
        except (TypeError, ValueError):
            raise EgressPolicyError() from None


@dataclass(frozen=True)
class EgressPolicy:
    bindings: tuple[EgressBinding, ...] = ()

    def __post_init__(self) -> None:
        if (type(self.bindings) is not tuple or len(self.bindings) > 8
                or any(type(b) is not EgressBinding for b in self.bindings)
                or len({(b.host, b.port) for b in self.bindings}) != len(self.bindings)):
            raise EgressPolicyError()


def parse_egress_policy(raw: str) -> EgressPolicy:
    """Parse separately admitted deployment policy; never consult environment."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EgressPolicyError()
            result[key] = value
        return result
    try:
        if type(raw) is not str or len(raw.encode("utf-8")) > 4096:
            raise EgressPolicyError()
        obj = json.loads(raw, object_pairs_hook=unique)
        if type(obj) is not dict or set(obj) != {"bindings"} or type(obj["bindings"]) is not list:
            raise EgressPolicyError()
        bindings = []
        for item in obj["bindings"]:
            if type(item) is not dict or set(item) != {"host", "port", "cidrs"} or type(item["cidrs"]) is not list:
                raise EgressPolicyError()
            bindings.append(EgressBinding(item["host"], item["port"], tuple(item["cidrs"])))
        return EgressPolicy(tuple(bindings))
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise EgressPolicyError() from None


@dataclass(frozen=True, repr=False)
class _Destination:
    host: str
    port: int
    target: str = field(repr=False)
    bindings: tuple[EgressBinding, ...]


def _destination(adapter: str, url: str, policy: EgressPolicy) -> _Destination:
    try:
        if (type(policy) is not EgressPolicy or adapter not in {"slack", "webhook"}
                or type(url) is not str or not 1 <= len(url.encode("ascii")) <= MAX_URL_BYTES
                or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url):
            raise DestinationError()
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port or 443
        if (parsed.scheme != "https" or not _host_valid(host) or parsed.username is not None
                or parsed.password is not None or parsed.fragment or "#" in url
                or parsed.netloc != host + (":" + str(port) if ":" in parsed.netloc else "")
                or not 1 <= port <= 65535):
            raise DestinationError()
        bindings = tuple(b for b in policy.bindings if (b.host, b.port) == (host, port))
        if port != 443 and not bindings:
            raise DestinationError()
        path = parsed.path or "/"
        if adapter == "slack" and (host not in _SLACK_HOSTS or port != 443 or bindings or parsed.query
                or "?" in url or _SLACK_PATH.fullmatch(path) is None):
            raise DestinationError()
        # Invalid percent escapes and encoded control bytes have no legitimate
        # role in a webhook secret and create intermediary parser differences.
        if re.search(r"%(?![0-9A-Fa-f]{2})|%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|7[fF])", path + parsed.query):
            raise DestinationError()
        return _Destination(host, port, path + ("?" + parsed.query if parsed.query else ""), bindings)
    except (ValueError, TypeError, UnicodeError):
        raise DestinationError() from None


def validate_destination(adapter: str, url: str, egress_policy: EgressPolicy) -> None:
    """Static validation only: saving configuration neither resolves nor sends."""
    _destination(adapter, url, egress_policy)


class _Failure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("notification transport failed")


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise _Failure("deadline_exceeded")
    return value


def _resolve(host: str, port: int, deadline: float) -> tuple[tuple[int, str], ...]:
    if not _DNS_SLOTS.acquire(blocking=False):
        raise _Failure("dns_unavailable")
    try:
        with subprocess.Popen([sys.executable, "-I", "-c", _DNS_CODE], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
                env={"LANG": "C", "LC_ALL": "C"}) as child:
            try:
                output, _ = child.communicate(json.dumps([host, port]).encode("ascii"),
                    timeout=min(DNS_TIMEOUT, _remaining(deadline)))
            except (subprocess.TimeoutExpired, _Failure):
                child.kill()
                child.communicate()
                raise _Failure("dns_timeout") from None
            except BaseException:
                child.kill()
                child.communicate()
                raise
            if child.returncode != 0 or len(output) > 8192:
                raise _Failure("dns_unavailable")
        data = json.loads(output)
        if type(data) is not list or not 1 <= len(data) <= 64:
            raise _Failure("dns_unavailable")
        result = []
        for pair in data:
            if (type(pair) is not list or len(pair) != 2 or type(pair[0]) is not int
                    or pair[0] not in {socket.AF_INET, socket.AF_INET6} or type(pair[1]) is not str):
                raise _Failure("dns_unavailable")
            address = ipaddress.ip_address(pair[1])
            if "%" in pair[1] or (address.version == 4) != (pair[0] == socket.AF_INET):
                raise _Failure("dns_unavailable")
            result.append((pair[0], str(address)))
        _remaining(deadline)
        return tuple(result)
    except (OSError, ValueError, TypeError):
        raise _Failure("dns_unavailable") from None
    finally:
        _DNS_SLOTS.release()


def _admit_addresses(destination: _Destination, addresses: tuple[tuple[int, str], ...]) -> None:
    if not addresses:
        raise _Failure("egress_denied")
    for _family, raw in addresses:
        address = ipaddress.ip_address(raw)
        if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
                or address.is_reserved or getattr(address, "is_site_local", False)
                or address in _METADATA_ADDRESSES
                or getattr(address, "ipv4_mapped", None) is not None
                or getattr(address, "sixtofour", None) is not None
                or getattr(address, "teredo", None) is not None):
            raise _Failure("egress_denied")
        # All DNS answers must be admitted. A private receiver's explicit
        # binding is a pin on its permitted networks, not an extra public grant.
        if destination.bindings:
            allowed = any(address.version == net.version and address in net
                for binding in destination.bindings for net in map(ipaddress.ip_network, binding.cidrs))
        else:
            allowed = address.is_global
        if not allowed:
            raise _Failure("egress_denied")


def _payload(adapter: str, payload: dict) -> bytes:
    try:
        if (type(payload) is not dict or not set(payload) <= _PAYLOAD_KEYS
                or payload.get("schema") != "serverware.operatorNotification/v1"):
            raise ValueError()
        raw = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise ValueError()
        if adapter == "slack":
            summary, link = payload.get("summary"), payload.get("review_url")
            if (type(summary) is not str or not 1 <= len(summary) <= 1000
                    or type(link) is not str or not 1 <= len(link) <= 1024
                    or any(ord(c) < 32 or ord(c) == 127 for c in link)):
                raise ValueError()
            parsed = urlsplit(link)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError()
            text = summary + "\nReview in Serverware: " + link
            escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if len(escaped) > 3000:
                raise ValueError()
            raw = json.dumps({"text": escaped, "mrkdwn": False, "unfurl_links": False,
                "unfurl_media": False, "blocks": [{"type": "section", "text": {
                    "type": "plain_text", "text": escaped, "emoji": False}}]},
                ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
            if len(raw) > MAX_PAYLOAD_BYTES:
                raise ValueError()
        return raw
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _Failure("payload_invalid") from None


def _tls_context() -> ssl.SSLContext:
    # create_default_context() honors SSLKEYLOGFILE. Secret-bearing notification
    # TLS must never enable that ambient session-key export side channel.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    return context


class _ResponseReader(io.RawIOBase):
    """Bound headers as well as body, including slow-drip header deadlines."""
    def __init__(self, stream: ssl.SSLSocket, deadline: float) -> None:
        super().__init__()
        self.stream, self.deadline, self.remaining = stream, deadline, MAX_RESPONSE_WIRE_BYTES

    def readable(self) -> bool:
        return True

    def settimeout(self, timeout: float) -> None:
        self.stream.settimeout(min(timeout, _remaining(self.deadline)))

    def readinto(self, buffer) -> int:
        if self.remaining <= 0:
            raise _Failure("delivery_unknown")
        self.stream.settimeout(_remaining(self.deadline))
        count = self.stream.recv_into(buffer, min(len(buffer), self.remaining))
        self.remaining -= count
        return count


class _ResponseSocket:
    def __init__(self, stream: ssl.SSLSocket, deadline: float) -> None:
        self.stream, self.deadline = stream, deadline

    def makefile(self, mode: str):
        if mode != "rb":
            raise _Failure("delivery_unknown")
        return io.BufferedReader(_ResponseReader(self.stream, self.deadline), buffer_size=8192)


def deliver(adapter: str, url: str, payload: dict, egress_policy: EgressPolicy, *,
        before_dispatch: Callable[[], bool] | None = None) -> DeliveryResult:
    """Attempt exactly one JSON POST; caller persists the result before retrying.

    Pre-dispatch transport failures alone are retryable. Once writing can have
    begun, absent/invalid framing or transport failure is outcome-unknown. A
    complete negative HTTP/adapter acknowledgement is terminal, never retried.
    The optional bounded owner check runs after TLS and immediately before the
    first write. Only literal True permits dispatch; it grants no source action
    authority and cannot extend this transport's original deadline.
    """
    dispatched = False
    stage = "transport"
    status = None
    raw_socket = tls = response = None
    deadline = time.monotonic() + TOTAL_TIMEOUT
    try:
        destination = _destination(adapter, url, egress_policy)
        body = _payload(adapter, payload)
        addresses = _resolve(destination.host, destination.port, deadline)
        _admit_addresses(destination, addresses)
        family, address = addresses[0]
        stage = "connect"
        raw_socket = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw_socket.settimeout(min(CONNECT_TIMEOUT, _remaining(deadline)))
        raw_socket.connect((address, destination.port))
        stage = "tls"
        context = _tls_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise _Failure("tls_unavailable")
        raw_socket.settimeout(_remaining(deadline))
        tls = context.wrap_socket(raw_socket, server_hostname=destination.host)
        if tls.selected_alpn_protocol() not in {None, "http/1.1"}:
            raise _Failure("tls_unavailable")
        host = destination.host + (":" + str(destination.port) if destination.port != 443 else "")
        request = ("POST " + destination.target + " HTTP/1.1\r\nHost: " + host
            + "\r\nContent-Type: application/json\r\nAccept: */*\r\nAccept-Encoding: identity"
            + "\r\nConnection: close\r\nContent-Length: " + str(len(body)) + "\r\n\r\n").encode("ascii") + body
        if before_dispatch is not None:
            stage = "transport"
            try:
                current = before_dispatch()
            except Exception:
                raise _Failure("transport_unavailable") from None
            if current is not True:
                raise _Failure("dispatch_cancelled")
        tls.settimeout(_remaining(deadline))
        dispatched = True
        tls.sendall(request)
        response = http.client.HTTPResponse(_ResponseSocket(tls, deadline), method="POST")
        response.begin()
        status = response.status if 200 <= response.status <= 599 else None
        if status is None:
            raise _Failure("delivery_unknown")
        if status == 204 and (response.headers.get("Transfer-Encoding") is not None
                or http_client._content_length(response.headers, max_bytes=MAX_RESPONSE_BYTES) not in {None, 0}):
            raise _Failure("delivery_unknown")
        captured = http_client._captured_http_response(response, status=status, request_method="POST",
            max_bytes=MAX_RESPONSE_BYTES, deadline_at=deadline, expected_statuses=None,
            expected_content_types=None)
        if not 200 <= status <= 299:
            return DeliveryResult("failed", "http_rejected", status)
        if adapter == "slack":
            try:
                http_client._response_media_type(response.headers, expected=("text/plain",))
                valid = status == 200 and captured.body == b"ok"
            except http_client.HttpClientError:
                valid = False
            if not valid:
                return DeliveryResult("failed", "acknowledgement_invalid", status)
        return DeliveryResult("acknowledged", "acknowledged", status)
    except DestinationError:
        return DeliveryResult("failed", "destination_invalid")
    except _Failure as exc:
        return DeliveryResult("outcome_unknown", "delivery_unknown", status) if dispatched else DeliveryResult("failed", exc.code)
    except (TimeoutError, subprocess.TimeoutExpired):
        return DeliveryResult("outcome_unknown", "delivery_unknown", status) if dispatched else DeliveryResult("failed", stage + "_timeout" if stage in {"connect", "tls"} else "deadline_exceeded")
    except Exception:
        return DeliveryResult("outcome_unknown", "delivery_unknown", status) if dispatched else DeliveryResult("failed", stage + "_unavailable" if stage in {"connect", "tls"} else "transport_unavailable")
    finally:
        for resource in (response, tls, raw_socket):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
