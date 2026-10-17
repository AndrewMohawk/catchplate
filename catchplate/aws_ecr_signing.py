"""Pure SigV4 signing for five ECR API operations only.

This is not authorization. Callers must validate the JSON operation, account,
repository and upload state; bind current policy/application/credential
generation; and enforce their original operation deadline and secret lifetime.
The trusted caller supplies clock observations, never client signing headers.
The 60-second signing bound is an additional limit, not a new caller deadline.

Only the complete application-header set is checked here, with optional exact
Content-Length. Transport framing/Host additions and the actual socket dispatch
remain the caller's responsibility. There is no I/O, ambient credential chain,
storage, renewal, replay or logging. Python cannot promise secret zeroization;
credentials, canonical requests and output headers must not be serialized or
logged. Their representations are redacted, not an access-control boundary.

Algorithm: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re


MAX_BODY_BYTES = 32 * 1024 * 1024
MAX_SESSION_TOKEN_BYTES = 8192
MAX_SIGNATURE_AGE_SECONDS = 60
SESSION_EXPIRY_MARGIN_SECONDS = 5
ACTIONS = frozenset({
    "BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart",
    "CompleteLayerUpload", "PutImage",
})
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[1-9][0-9]?\Z")
_ACCESS = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}\Z")
_SECRET = re.compile(r"[A-Za-z0-9/+=]{40}\Z")
_EXPIRY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_UNIX_SECONDS = 253402300799
_MAX_MONOTONIC_NS = (1 << 63) - 1
_SEAL = object()


class SigningError(ValueError):
    def __init__(self) -> None:
        super().__init__("AWS ECR signing unavailable")


def _expiry_seconds(value: str) -> int:
    try:
        if type(value) is not str or len(value) != 20 or _EXPIRY.fullmatch(value) is None:
            raise SigningError()
        parsed = datetime(int(value[0:4]), int(value[5:7]), int(value[8:10]),
                          int(value[11:13]), int(value[14:16]), int(value[17:19]),
                          tzinfo=timezone.utc)
        delta = parsed - _EPOCH
        seconds = delta.days * 86400 + delta.seconds
        if not 0 <= seconds <= _MAX_UNIX_SECONDS:
            raise SigningError()
        return seconds
    except Exception:
        raise SigningError() from None


def _credentials_expiry(value: "Credentials") -> int | None:
    if (type(value) is not Credentials or type(value.kind) is not str
            or value.kind not in {"long_term", "session"}
            or type(value.access_key_id) is not str or len(value.access_key_id) != 20
            or _ACCESS.fullmatch(value.access_key_id) is None
            or type(value.secret_access_key) is not str or len(value.secret_access_key) != 40
            or _SECRET.fullmatch(value.secret_access_key) is None):
        raise SigningError()
    if value.kind == "long_term":
        if (not value.access_key_id.startswith("AKIA")
                or value.session_token is not None or value.expires_at is not None):
            raise SigningError()
        return None
    if (not value.access_key_id.startswith("ASIA") or type(value.session_token) is not str
            or not 1 <= len(value.session_token) <= MAX_SESSION_TOKEN_BYTES
            or any(not "!" <= character <= "~" for character in value.session_token)):
        raise SigningError()
    return _expiry_seconds(value.expires_at)


@dataclass(frozen=True, slots=True, repr=False, eq=False, kw_only=True)
class Credentials:
    kind: str
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    expires_at: str | None = None

    def __post_init__(self) -> None:
        _credentials_expiry(self)

    def __repr__(self) -> str:
        return "Credentials(<redacted>)"


@dataclass(frozen=True, slots=True)
class ClockObservation:
    """Trusted UTC epoch seconds and monotonic nanoseconds, not client input."""
    unix_seconds: int
    monotonic_ns: int

    def __post_init__(self) -> None:
        _check_clock(self)


def _check_clock(clock: ClockObservation) -> None:
    if (type(clock) is not ClockObservation or type(clock.unix_seconds) is not int
            or not 0 <= clock.unix_seconds <= _MAX_UNIX_SECONDS
            or type(clock.monotonic_ns) is not int
            or not 0 <= clock.monotonic_ns <= _MAX_MONOTONIC_NS):
        raise SigningError()


@dataclass(frozen=True, slots=True, repr=False, eq=False, init=False)
class SignedRequest:
    """Read-only application request binding; headers/canonical bytes contain secrets."""
    method: str
    scheme: str
    authority: str
    path: str
    query: str
    headers: tuple[tuple[str, str], ...]
    canonical_request: bytes
    string_to_sign: str
    body_sha256: str
    body_length: int
    _clock: ClockObservation
    _expires_at: int | None
    _seal: object

    def __init__(self, *args, **kwargs) -> None:
        raise SigningError()

    def __repr__(self) -> str:
        return "SignedRequest(<redacted>)"


def _require_fresh(signed: SignedRequest, clock: ClockObservation) -> None:
    _check_clock(clock)
    wall_elapsed = clock.unix_seconds - signed._clock.unix_seconds
    monotonic_elapsed = clock.monotonic_ns - signed._clock.monotonic_ns
    if (not 0 <= wall_elapsed < MAX_SIGNATURE_AGE_SECONDS
            or not 0 <= monotonic_elapsed < MAX_SIGNATURE_AGE_SECONDS * 1_000_000_000
            or (signed._expires_at is not None
                and signed._expires_at - clock.unix_seconds <= SESSION_EXPIRY_MARGIN_SECONDS)):
        raise SigningError()


def sign(credentials: Credentials, *, region: str, action: str, body: bytes,
         clock: ClockObservation, include_accept: bool = False) -> SignedRequest:
    """Sign exact already-authorized bytes; construct every signing header ourselves."""
    try:
        expiry = _credentials_expiry(credentials)
        _check_clock(clock)
        if (type(include_accept) is not bool
                or type(region) is not str or not 1 <= len(region) <= 63
                or _REGION.fullmatch(region) is None or region.startswith("cn-")
                or type(action) is not str or len(action) > 64 or action not in ACTIONS
                or type(body) is not bytes or len(body) > MAX_BODY_BYTES
                or (expiry is not None
                    and expiry - clock.unix_seconds <= SESSION_EXPIRY_MARGIN_SECONDS)):
            raise SigningError()
        # Region shape is not endpoint discovery, account ownership or a grant.
        authority = "api.ecr." + region + ".amazonaws.com"
        utc = _EPOCH + timedelta(seconds=clock.unix_seconds)
        date = f"{utc.year:04d}{utc.month:02d}{utc.day:02d}"
        timestamp = date + f"T{utc.hour:02d}{utc.minute:02d}{utc.second:02d}Z"
        headers = {
            "content-type": "application/x-amz-json-1.1",
            "host": authority,
            "x-amz-date": timestamp,
            "x-amz-target": "AmazonEC2ContainerRegistry_V20150921." + action,
        }
        if include_accept:
            # The ordinary reqwest transport supplies this default. Binding it
            # explicitly prevents an unobserved header insertion after the
            # final built-request comparison; it is also covered by SigV4.
            headers["accept"] = "*/*"
        if credentials.session_token is not None:
            headers["x-amz-security-token"] = credentials.session_token
        ordered = sorted(headers.items())
        canonical_headers = "".join(name + ":" + value + "\n" for name, value in ordered)
        signed_headers = ";".join(name for name, _ in ordered)
        body_sha256 = hashlib.sha256(body).hexdigest()
        canonical = ("POST\n/\n\n" + canonical_headers + "\n"
                     + signed_headers + "\n" + body_sha256).encode("ascii")
        scope = date + "/" + region + "/ecr/aws4_request"
        string_to_sign = ("AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n"
                          + hashlib.sha256(canonical).hexdigest())
        key = ("AWS4" + credentials.secret_access_key).encode("ascii")
        for component in (date, region, "ecr", "aws4_request"):
            key = hmac.new(key, component.encode("ascii"), hashlib.sha256).digest()
        signature = hmac.new(key, string_to_sign.encode("ascii"), hashlib.sha256).hexdigest()
        headers["authorization"] = ("AWS4-HMAC-SHA256 Credential=" + credentials.access_key_id
                                    + "/" + scope + ", SignedHeaders=" + signed_headers
                                    + ", Signature=" + signature)
        result = object.__new__(SignedRequest)
        values = {
            "method": "POST", "scheme": "https", "authority": authority, "path": "/", "query": "",
            "headers": tuple(sorted(headers.items())), "canonical_request": canonical,
            "string_to_sign": string_to_sign, "body_sha256": body_sha256,
            "body_length": len(body), "_clock": clock, "_expires_at": expiry, "_seal": _SEAL,
        }
        for name, value in values.items():
            object.__setattr__(result, name, value)
        return result
    except Exception:
        raise SigningError() from None


def assert_dispatch(signed: SignedRequest, *, method: str, scheme: str, authority: str,
                    path: str, query: str, headers: tuple[tuple[str, str], ...], body: bytes,
                    clock: ClockObservation) -> None:
    """Recheck the same binding and lifetime, without re-signing or granting a send."""
    try:
        if type(signed) is not SignedRequest or signed._seal is not _SEAL:
            raise SigningError()
        _require_fresh(signed, clock)
        for actual, expected in ((method, signed.method), (scheme, signed.scheme),
                                 (authority, signed.authority), (path, signed.path), (query, signed.query)):
            if type(actual) is not str or actual != expected:
                raise SigningError()
        if (type(body) is not bytes or len(body) > MAX_BODY_BYTES
                or len(body) != signed.body_length
                or not hmac.compare_digest(hashlib.sha256(body).hexdigest(), signed.body_sha256)
                or type(headers) is not tuple
                or not len(signed.headers) <= len(headers) <= len(signed.headers) + 1):
            raise SigningError()
        expected = dict(signed.headers)
        seen = set()
        for pair in headers:
            if type(pair) is not tuple or len(pair) != 2:
                raise SigningError()
            name, value = pair
            if (type(name) is not str or len(name) > 64 or name in seen
                    or type(value) is not str or len(value) > MAX_SESSION_TOKEN_BYTES):
                raise SigningError()
            seen.add(name)
            target = str(signed.body_length) if name == "content-length" else expected.get(name)
            if target is None or not hmac.compare_digest(value.encode("ascii"), target.encode("ascii")):
                raise SigningError()
        if seen - {"content-length"} != set(expected):
            raise SigningError()
        # A caller must obtain a fresh observation immediately before its send;
        # this pure function cannot observe elapsed time during hashing itself.
    except Exception:
        raise SigningError() from None


def require_fresh(signed: SignedRequest, *, clock: ClockObservation) -> None:
    """Check a second trusted observation after binding checks, without rehashing.

    This only checks retained signing/session lifetime at the supplied instant.
    It neither repeats body/header checks nor proves an atomic socket send,
    current authority/generation or the caller's original operation deadline.
    """
    try:
        if type(signed) is not SignedRequest or signed._seal is not _SEAL:
            raise SigningError()
        _require_fresh(signed, clock)
    except Exception:
        raise SigningError() from None
