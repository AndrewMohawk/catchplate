"""Read-only, cold-pinned Unix observation of an independently owned pilot.

This module imports no application/configuration/database owner and grants no
ceremony authority. A syntactically valid notice is not a live-source proof;
dispatch must reread the relay and recheck the original deadline after all
other potentially blocking guards. The integration admits configuration once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import socket
import stat
import struct
import time

NATIVE_ORIGIN = "https://serverware.example.com"
AVAILABLE_PHASES = ("confirmation_available", "prepare_available", "security_key_available")
_PHASES = frozenset((*AVAILABLE_PHASES, "waiting", "cancelled", "response_captured",
    "action_in_progress", "preparing", "preparing_confirmation", "expired"))
_SUMMARIES = {"prepare_available": "Prepare the native pilot",
    "security_key_available": "Use your security key for the native pilot",
    "confirmation_available": "Confirm the native pilot action"}
_RELAY_UID = 1000
_RELAY_GID = 10001
_MAX_BYTES = 8192
_TIMEOUT = 2.0
_MAX_NS = 2**63 - 1
_REQUEST = b"GET /v1/observation HTTP/1.0\r\n\r\n"
_ERROR = "native notification source unavailable"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NS = re.compile(r"[1-9][0-9]{0,19}\Z")
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)\Z")
_STATUS_KEYS = frozenset(("schema", "attemptSha256", "readinessSha256", "phase",
    "actionAvailable", "attemptNumber", "sourceSha256", "setupExpiresAtUnixNanos",
    "sourceExpiresAtUnixNanos", "reviewPath", "eventType", "eventId",
    "automaticRetryAllowed", "enrollmentVerified"))


class SourceError(ValueError):
    """A deliberately fixed message, without paths or untrusted response text."""

    def __init__(self, *_args):
        super().__init__(_ERROR)


@dataclass(frozen=True)
class PilotSourceConfig:
    socket_path: str
    relay_uid: int
    selection_sha256: str
    attempt_sha256: str
    native_origin: str
    # Every directory component and the socket are retained, never re-adopted.
    identities: tuple = field(repr=False)


@dataclass(frozen=True)
class PilotObservation:
    selection_sha256: str
    state: str
    observation_json: str | None


@dataclass(frozen=True)
class NativePilotNotice:
    selection_sha256: str
    observation_json: str


def _require(condition):
    if not condition:
        raise SourceError()


def _digest(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw):
    try:
        _require(type(raw) is str and 0 < len(raw.encode("utf-8")) <= _MAX_BYTES)
        return json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(SourceError()))
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise SourceError() from None


def _nanoseconds(value):
    _require(type(value) is str and _NS.fullmatch(value) is not None)
    result = int(value)
    _require(result <= _MAX_NS)
    return result


def _now(value):
    result = time.time_ns() if value is None else value
    _require(type(result) is int and 0 <= result <= _MAX_NS)
    return result


def _status(value):
    _require(type(value) is dict and value.keys() == _STATUS_KEYS)
    _require(value["schema"] == "serverware.pilotActionStatus/v1")
    _require(_digest(value["attemptSha256"]) and _digest(value["readinessSha256"]))
    phase = value["phase"]
    _require(type(phase) is str and phase in _PHASES)
    available = phase in AVAILABLE_PHASES
    _require(value["actionAvailable"] is available and value["automaticRetryAllowed"] is False
        and value["enrollmentVerified"] is False)
    attempt = value["attemptNumber"]
    _require(type(attempt) is int and 0 <= attempt <= 32)
    setup = _nanoseconds(value["setupExpiresAtUnixNanos"])
    _require(value["reviewPath"] == "/pilot-prelaunch/action-status/"
        + value["attemptSha256"][7:] + "/" + value["readinessSha256"][7:])
    if available:
        source_expiry = _nanoseconds(value["sourceExpiresAtUnixNanos"])
        _require(source_expiry <= setup and _digest(value["sourceSha256"]))
        _require(value["eventType"] == "native_pilot." + phase)
        if phase == "prepare_available":
            _require(attempt == 0 and value["sourceSha256"] == value["readinessSha256"]
                and value["sourceExpiresAtUnixNanos"] == value["setupExpiresAtUnixNanos"])
        else:
            _require(1 <= attempt <= 32)
        binding = {key: value[key] for key in ("attemptSha256", "readinessSha256", "attemptNumber",
            "eventType", "sourceSha256", "sourceExpiresAtUnixNanos")}
        expected = "sha256:" + hashlib.sha256(_canonical(binding).encode("ascii")).hexdigest()
        _require(value["eventId"] == expected)
    else:
        _require(value["eventType"] is None and value["eventId"] is None and value["sourceSha256"] is None)
        expiry = value["sourceExpiresAtUnixNanos"]
        if phase == "expired":
            _require(attempt >= 1 and _nanoseconds(expiry) <= setup)
        else:
            _require(expiry is None)
    # All fields have primitive closed types; detach from caller-owned objects.
    return dict(value)


def validate_record(record):
    """Validate a historical actionable record, without asserting currentness."""
    try:
        _require(type(record) is dict and record.keys() == {"schema", "selection_sha256", "observation"})
        _require(record["schema"] == "serverware.nativePilotNotificationObservation/v1"
            and _digest(record["selection_sha256"]))
        status = _status(record["observation"])
        _require(status["actionAvailable"] is True)
        return {"schema": record["schema"], "selection_sha256": record["selection_sha256"], "observation": status}
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise SourceError() from None


def notice_record(notice):
    _require(type(notice) is NativePilotNotice)
    record = validate_record({"schema": "serverware.nativePilotNotificationObservation/v1",
        "selection_sha256": notice.selection_sha256, "observation": _json(notice.observation_json)})
    _require(notice.observation_json == _canonical(record["observation"]))
    return record


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_ctime_ns)


def _directory_identity(info):
    # Unrelated entries may change an ancestor's link count/ctime. Its inode,
    # owner and access mode must remain identical, not its directory contents.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def _open_parent(path):
    """Walk real directory entries, never symlinks, and retain one directory FD."""
    _require(type(path) is str and path.startswith("/") and "\0" not in path
        and len(os.fsencode(path)) <= 107 and path.endswith("/observation.sock"))
    parts = path.split("/")[1:]
    _require(all(part and part not in {".", ".."} for part in parts))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    identities = [_directory_identity(os.fstat(descriptor))]
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            identities.append(_directory_identity(os.fstat(descriptor)))
        parent = os.fstat(descriptor)
        _require(parent.st_uid == _RELAY_UID and parent.st_gid == _RELAY_GID
            and stat.S_IMODE(parent.st_mode) == 0o750)
        endpoint = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        _require(stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == _RELAY_UID
            and endpoint.st_gid == _RELAY_GID and stat.S_IMODE(endpoint.st_mode) == 0o660
            and endpoint.st_nlink == 1)
        identities.append(_identity(endpoint))
        return descriptor, tuple(identities)
    except BaseException:
        os.close(descriptor)
        raise


def admit_config(raw):
    """Cold admission only: pin paths/ownership now; do not poll or cache globally."""
    if raw is None or raw == "":
        return None
    try:
        _require(type(raw) is str and len(raw.encode("utf-8")) <= 4096)
        value = _json(raw)
        _require(type(value) is dict and value.keys() == {"schema", "socketPath", "relayUid",
            "selectionSha256", "attemptSha256", "nativeOrigin"})
        _require(value["schema"] == "serverware.operatorPilotNotificationSource/v1"
            and type(value["relayUid"]) is int and value["relayUid"] == 1000
            and _digest(value["selectionSha256"]) and _digest(value["attemptSha256"])
            and value["nativeOrigin"] == NATIVE_ORIGIN)
        descriptor, identities = _open_parent(value["socketPath"])
        os.close(descriptor)
        return PilotSourceConfig(value["socketPath"], 1000, value["selectionSha256"],
            value["attemptSha256"], NATIVE_ORIGIN, identities)
    except (OSError, ValueError, TypeError, UnicodeError, KeyError, RecursionError, OverflowError):
        raise SourceError() from None


def _config(config):
    _require(type(config) is PilotSourceConfig and config.relay_uid == 1000
        and config.native_origin == NATIVE_ORIGIN and _digest(config.selection_sha256)
        and _digest(config.attempt_sha256) and type(config.identities) is tuple and bool(config.identities))


def _remaining(sock, deadline):
    remaining = deadline - time.monotonic()
    _require(remaining > 0)
    sock.settimeout(remaining)


def _peer_uid(sock):
    # A host peer can have PID 0 in the client's PID namespace. UID is the pin.
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _wire_body(wire):
    _require(type(wire) is bytes and 0 < len(wire) <= _MAX_BYTES)
    head, separator, body = wire.partition(b"\r\n\r\n")
    _require(separator == b"\r\n\r\n")
    lines = head.split(b"\r\n")
    _require(len(lines) == 5 and lines[0] == b"HTTP/1.0 200 OK")
    headers = {}
    for line in lines[1:]:
        key, delimiter, value = line.partition(b": ")
        _require(delimiter == b": " and key not in headers)
        headers[key] = value
    _require(headers.keys() == {b"Content-Type", b"Content-Length", b"Cache-Control", b"Connection"}
        and headers[b"Content-Type"] == b"application/json" and headers[b"Cache-Control"] == b"no-store"
        and headers[b"Connection"] == b"close" and headers[b"Content-Length"] == str(len(body)).encode("ascii"))
    return body.decode("utf-8", errors="strict")


def _observation(config, wrapper):
    _config(config)
    _require(type(wrapper) is dict and wrapper.keys() == {"schema", "selectionSha256", "state", "observation"})
    _require(wrapper["schema"] == "serverware.pilotObservationRelay/v1"
        and wrapper["selectionSha256"] == config.selection_sha256
        and type(wrapper["state"]) is str and wrapper["state"] in {"waiting", "observed", "unavailable"})
    raw = None
    if wrapper["state"] == "observed":
        status = _status(wrapper["observation"])
        _require(status["attemptSha256"] == config.attempt_sha256)
        raw = _canonical(status)
    else:
        _require(wrapper["observation"] is None)
    return PilotObservation(config.selection_sha256, wrapper["state"], raw)


def read_observation(config):
    """One fixed AF_UNIX request, no retry, at most 8192 total bytes / 2 seconds."""
    descriptor = None
    try:
        _config(config)
        deadline = time.monotonic() + _TIMEOUT
        descriptor, identities = _open_parent(config.socket_path)
        _require(identities == config.identities)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            _remaining(client, deadline)
            # Anchor connection to the verified open parent, not a re-resolved
            # user path. The final socket entry is checked again after the read.
            client.connect(f"/proc/self/fd/{descriptor}/observation.sock")
            _require(_peer_uid(client) == _RELAY_UID)
            _remaining(client, deadline)
            client.sendall(_REQUEST)
            wire = bytearray()
            while True:
                _remaining(client, deadline)
                chunk = client.recv(min(4096, _MAX_BYTES + 1 - len(wire)))
                if not chunk:
                    break
                wire.extend(chunk)
                _require(len(wire) <= _MAX_BYTES)
            _require(_peer_uid(client) == _RELAY_UID)
        checked, final_identities = _open_parent(config.socket_path)
        os.close(checked)
        _require(final_identities == config.identities and time.monotonic() < deadline)
        result = _observation(config, _json(_wire_body(bytes(wire))))
        _require(time.monotonic() < deadline)
        return result
    except (OSError, ValueError, TypeError, UnicodeError, KeyError, RecursionError, OverflowError):
        raise SourceError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _observed_status(config, observation):
    _config(config)
    _require(type(observation) is PilotObservation and observation.selection_sha256 == config.selection_sha256)
    wrapper = {"schema": "serverware.pilotObservationRelay/v1", "selectionSha256": observation.selection_sha256,
        "state": observation.state, "observation": None if observation.observation_json is None else _json(observation.observation_json)}
    checked = _observation(config, wrapper)
    _require(checked == observation)
    return None if checked.observation_json is None else _json(checked.observation_json)


def observation_notice(config, observation, *, now_unix_nanos=None):
    status = _observed_status(config, observation)
    now = _now(now_unix_nanos)
    if status is None or not status["actionAvailable"] or now >= int(status["sourceExpiresAtUnixNanos"]):
        return None
    return NativePilotNotice(config.selection_sha256, _canonical(status))


def _payload_record(payload):
    _require(type(payload) is dict and payload.keys() == {"schema", "channel", "source", "summary", "review_path", "details"})
    _require(payload["schema"] == "serverware.operatorNotification/v1" and payload["channel"] == "action_required")
    source = payload["source"]
    _require(type(source) is dict and source.keys() == {"event_id", "event_hash", "event_type", "created_at"}
        and _digest(source["event_id"]) and _digest(source["event_hash"])
        and source["event_type"] == "native_pilot.phase_observed"
        and type(source["created_at"]) is str and _STAMP.fullmatch(source["created_at"]) is not None)
    _require(type(payload["details"]) is dict and payload["details"].keys() == {"native_pilot"})
    record = validate_record(payload["details"]["native_pilot"])
    status = record["observation"]
    _require(payload["review_path"] == status["reviewPath"] and payload["summary"] == _SUMMARIES[status["phase"]])
    binding = {"selection_sha256": record["selection_sha256"], "native_event_id": status["eventId"]}
    _require(source["event_id"] == "sha256:" + hashlib.sha256(_canonical(binding).encode("ascii")).hexdigest())
    return record


def _bound_record(config, payload):
    _config(config)
    record = _payload_record(payload)
    _require(record["selection_sha256"] == config.selection_sha256
        and record["observation"]["attemptSha256"] == config.attempt_sha256)
    return record


def payload_is_unexpired(payload, *, now_unix_nanos=None):
    try:
        record = _payload_record(payload)
        return _now(now_unix_nanos) < int(record["observation"]["sourceExpiresAtUnixNanos"])
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return False


def payload_is_current(config, payload):
    """Live exact-source comparison; all refusals/unavailability return false."""
    try:
        expected = _bound_record(config, payload)
        if not payload_is_unexpired(payload):
            return False
        notice = observation_notice(config, read_observation(config))
        return (notice is not None and notice_record(notice) == expected
            and payload_is_unexpired(payload))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return False


def review_url(config, payload):
    record = _bound_record(config, payload)
    return config.native_origin + record["observation"]["reviewPath"]


def observation_summary(config, observation, *, now_unix_nanos=None):
    """Presentation of one retained observation only; never performs any I/O."""
    result = {"state": "not_configured" if config is None else "not_observed", "observer_available": False,
        "action_available": False, "phase": None, "source_expires_at_unix_nanos": None, "review_url": None}
    if config is None:
        _require(observation is None)
        return result
    _config(config)
    if observation is None:
        return result
    status = _observed_status(config, observation)
    now = _now(now_unix_nanos)
    result.update(state=observation.state, observer_available=observation.state != "unavailable")
    if status is not None:
        expiry = status["sourceExpiresAtUnixNanos"]
        expired = now >= int(status["setupExpiresAtUnixNanos"]) or (expiry is not None and now >= int(expiry))
        result.update(state="observed",
            action_available=status["actionAvailable"] and not expired, phase=status["phase"],
            source_expires_at_unix_nanos=expiry, review_url=config.native_origin + status["reviewPath"])
    return result
